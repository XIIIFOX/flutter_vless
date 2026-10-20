package native_dns_preservation_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dns "github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

// This source is compiled locally, but its Core Build/runtime tests run only
// in CI. Native admission itself is also tested by the inert preparer fixture.
func testIPv6DNSServers(t *testing.T, native bool) {
	for _, tc := range preparationCorpus(t, "dns-ipv6-servers.json", 4) {
		t.Run(tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			compiled := buildRootDNSAddresses(t, source)
			if len(compiled.NameServer) != 1 {
				t.Fatal("one caller DNS server required")
			}
			address := compiled.NameServer[0].Address.Address
			want := netip.MustParseAddr("2001:db8::53")
			if strings.HasPrefix(tc.Name, "mapped_") {
				want = netip.MustParseAddr("192.0.2.53")
			}
			if strings.Contains(tc.Name, "tcp_url") {
				u, err := url.Parse(address.GetDomain())
				if err != nil || u.Scheme != "tcp" || u.Port() != "18053" {
					t.Fatal("compiled DNS TCP URL changed", err)
				}
				parsed, err := netip.ParseAddr(u.Hostname())
				if err != nil || parsed.Unmap() != want {
					t.Fatal("compiled DNS TCP address family changed", err)
				}
			} else if !bytes.Equal(address.GetIp(), want.AsSlice()) {
				t.Fatal("compiled DNS literal lost its exact four/sixteen address bytes")
			}
			if !native {
				return
			}
			effective := prepareEndpointAddress(t, source)
			for _, key := range []string{"dns", "remarks", "custom"} {
				if !reflect.DeepEqual(effective[key], tc.Config[key]) {
					t.Fatal("DNS family admission rewrote caller data", key)
				}
			}
			prepared, err := json.Marshal(effective)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(compiled, buildRootDNSAddresses(t, prepared)) {
				t.Fatal("prepared DNS protobuf changed")
			}
		})
	}
}

func ipv6DNSHeader() []byte {
	address := netip.MustParseAddr("2001:db8::53").As16()
	return binary.BigEndian.AppendUint16(append([]byte{0, 0, 0, 4}, address[:]...), 18053)
}

// The carrier is IPv4-only. Its SOCKS destination is nevertheless the exact
// caller IPv6 DNS address. No physical IPv6 listener or resolver is involved.
func ipv6DNSCarrier(t *testing.T, observed *fixture, associations, callbacks *atomic.Int64, transport, nonce string) int {
	t.Helper()
	answer := func(packet []byte) ([]byte, error) {
		var request dns.Msg
		if len(packet) > 4096 || request.Unpack(packet) != nil || request.Response || len(request.Question) != 1 {
			return nil, errors.New("invalid IPv6 DNS carrier query")
		}
		q := request.Question[0]
		if q.Name != dns.Fqdn(nonce) || q.Qclass != dns.ClassINET || (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
			return nil, errors.New("IPv6 DNS carrier lost nonce/question or forwarded a refused type")
		}
		response := new(dns.Msg)
		response.SetReply(&request)
		header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 1}
		if q.Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.0.2.61")}}
		} else {
			response.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8:85::61")}}
		}
		observed.record(dns.TypeToString[q.Qtype])
		return response.Pack()
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 4096+22)
		for {
			n, peer, err := udp.ReadFromUDPAddrPort(packet)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					observed.fail(err)
				}
				return
			}
			header := ipv6DNSHeader()
			if transport != "udp" || associations.Load() == 0 || !peer.Addr().Is4() || n <= len(header) || !bytes.Equal(packet[:len(header)], header) {
				observed.fail(errors.New("DNS UDP destination was not exact IPv6 ATYP4 through its live IPv4 association"))
				continue
			}
			response, err := answer(packet[len(header):n])
			if err != nil {
				observed.fail(err)
				continue
			}
			_, err = udp.WriteToUDPAddrPort(append(header, response...), peer)
			observed.fail(err)
		}
	}()
	t.Cleanup(func() {
		_ = udp.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("IPv6 DNS UDP carrier did not drain")
		}
	})
	networkListener(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), func(connection net.Conn) {
		callbacks.Add(1)
		defer callbacks.Add(-1)
		var greeting [3]byte
		if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			observed.fail(errors.New("invalid DNS SOCKS greeting"))
			return
		}
		if _, err := connection.Write([]byte{5, 0}); err != nil {
			observed.fail(err)
			return
		}
		var request [4]byte
		if _, err := io.ReadFull(connection, request[:]); err != nil {
			observed.fail(err)
			return
		}
		if request == [4]byte{5, 3, 0, 1} && transport == "udp" {
			var target [6]byte
			if _, err := io.ReadFull(connection, target[:]); err != nil || target != [6]byte{} {
				observed.fail(errors.New("invalid DNS UDP association target"))
				return
			}
			associations.Add(1)
			defer associations.Add(-1)
			response := binary.BigEndian.AppendUint16([]byte{5, 0, 0, 1, 127, 0, 0, 1}, uint16(port))
			if _, err := connection.Write(response); err != nil {
				observed.fail(err)
				return
			}
			var extra [1]byte
			n, readErr := connection.Read(extra[:])
			if !fakeDNSControlReadClosed(n, readErr, runtime.GOOS) {
				observed.fail(fmt.Errorf("DNS UDP association did not explicitly close: n=%d err=%v", n, readErr))
			}
			return
		}
		if transport != "tcp" || request != [4]byte{5, 1, 0, 4} {
			observed.fail(errors.New("DNS TCP destination did not use exact IPv6 ATYP4"))
			return
		}
		var target [18]byte
		if _, err := io.ReadFull(connection, target[:]); err != nil || !bytes.Equal(target[:], ipv6DNSHeader()[4:]) {
			observed.fail(errors.New("DNS TCP target address/port changed"))
			return
		}
		if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
			observed.fail(err)
			return
		}
		for {
			var size [2]byte
			n, err := io.ReadFull(connection, size[:])
			if err != nil {
				if !fakeDNSControlReadClosed(n, err, runtime.GOOS) {
					observed.fail(err)
				}
				return
			}
			length := int(binary.BigEndian.Uint16(size[:]))
			if length == 0 || length > 4096 {
				observed.fail(errors.New("invalid DNS TCP frame size"))
				return
			}
			packet := make([]byte, length)
			if _, err := io.ReadFull(connection, packet); err != nil {
				observed.fail(err)
				return
			}
			response, err := answer(packet)
			if err != nil {
				observed.fail(err)
				return
			}
			if _, err := connection.Write(binary.BigEndian.AppendUint16(nil, uint16(len(response)))); err != nil {
				observed.fail(err)
				return
			}
			if _, err := connection.Write(response); err != nil {
				observed.fail(err)
				return
			}
		}
	})
	return port
}

func testNativeIPv6DNS(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("actual IPv6 DNS Core execution is CI-only")
	}
	for _, transport := range []string{"udp", "tcp"} {
		for _, strategy := range []string{"UseIP", "UseIPv4"} {
			t.Run(transport+"/"+strategy, func(t *testing.T) {
				var lookups, associations, callbacks atomic.Int64
				previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
				trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
					lookups.Add(1)
					return nil, errors.New("forbidden IPv6 DNS OS lookup")
				}}
				net.DefaultResolver, xnet.DefaultResolver = trap, trap
				t.Cleanup(func() {
					net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
					if lookups.Load() != 0 {
						t.Error("IPv6 DNS attempted OS lookup")
					}
				})
				observed := new(fixture)
				completed := false
				t.Cleanup(func() {
					if !completed {
						return
					}
					queries, failures := observed.snapshot()
					sort.Strings(queries)
					want := []string{"A", "A"}
					if strategy == "UseIP" {
						want = append(want, "AAAA", "AAAA")
					}
					if !reflect.DeepEqual(queries, want) || len(failures) != 0 || associations.Load() != 0 || callbacks.Load() != 0 || lookups.Load() != 0 {
						t.Errorf("IPv6 DNS carrier/counts/drain mismatch: queries=%v errors=%v associations=%d callbacks=%d lookups=%d", queries, failures, associations.Load(), callbacks.Load(), lookups.Load())
						return
					}
					if !t.Failed() {
						t.Logf("DNS_IPV6_UPSTREAM_RUNTIME_PASS transport=%s strategy=%s", transport, strategy)
					}
				})
				var nonce [16]byte
				if _, err := rand.Read(nonce[:]); err != nil {
					t.Fatal(err)
				}
				name := "dns-v6-" + hex.EncodeToString(nonce[:]) + ".invalid"
				carrier := ipv6DNSCarrier(t, observed, &associations, &callbacks, transport, name)
				cases := preparationCorpus(t, "dns-ipv6-servers.json", 4)
				index := 0
				if transport == "tcp" {
					index = 1
				}
				source := cases[index].Config
				source["inbounds"] = []any{}
				source["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["address"] = "127.0.0.1"
				source["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["port"] = carrier
				policy := source["dns"].(map[string]any)
				policy["queryStrategy"] = strategy
				server := policy["servers"].([]any)[0].(map[string]any)
				server["queryStrategy"], server["domains"] = strategy, []string{"full:" + name}
				prepared, port := prepare(t, source)
				decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
				if err != nil {
					t.Fatal(err)
				}
				built, err := decoded.Build()
				if err != nil {
					t.Fatal(err)
				}
				engine, err := core.New(built)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := engine.Close(); err != nil {
						t.Error(err)
					}
					// Observe peer EOF/reset before the generic listener's cleanup
					// closes remaining owned sockets. A forced close is not proof
					// that Core drained its carrier association or DNS callback.
					deadline := time.Now().Add(3 * time.Second)
					for (associations.Load() != 0 || callbacks.Load() != 0) && time.Now().Before(deadline) {
						time.Sleep(10 * time.Millisecond)
					}
					if associations.Load() != 0 || callbacks.Load() != 0 {
						t.Error("Core Stop retained its IPv6 DNS carrier association/callback")
					}
				})
				if err := engine.Start(); err != nil {
					t.Fatal(err)
				}
				for _, udp := range []bool{false, true} {
					for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX} {
						response := query(t, port, udp, name, kind)
						wantCode := dns.RcodeSuccess
						if kind == dns.TypeMX {
							wantCode = dns.RcodeRefused
						}
						if response.Rcode != wantCode {
							t.Fatal("managed IPv6 DNS reply code changed", response)
						}
						if kind == dns.TypeMX || kind == dns.TypeAAAA && strategy == "UseIPv4" {
							if len(response.Answer) != 0 {
								t.Fatal("caller UseIPv4 NODATA / address-only MX refusal changed", response)
							}
							continue
						}
						if len(response.Answer) != 1 {
							t.Fatal("IPv6 DNS carrier answer missing", response)
						}
						if kind == dns.TypeA {
							answer, ok := response.Answer[0].(*dns.A)
							if !ok || !answer.A.Equal(net.ParseIP("192.0.2.61")) {
								t.Fatal("IPv6 upstream A bytes changed", response)
							}
						} else {
							answer, ok := response.Answer[0].(*dns.AAAA)
							if !ok || !answer.AAAA.Equal(net.ParseIP("2001:db8:85::61")) {
								t.Fatal("IPv6 upstream AAAA bytes changed", response)
							}
						}
					}
				}
				completed = true
			})
		}
	}
}
