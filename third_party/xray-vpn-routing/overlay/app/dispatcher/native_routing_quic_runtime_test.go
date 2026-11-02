//go:build flutter_vless_core31_followups

package dispatcher_test

// This is a bounded QUIC-Initial sniffing/routing fixture, not a QUIC server or
// an HTTP/3 handshake test. The TLS ClientHello comes from crypto/tls; QUIC v1
// Initial encryption is independently generated from RFC 9001. Real numeric
// SOCKS UDP enters the native routing owner and reaches either a direct UDP
// origin or a second, ordinary SOCKS Core and an independent UDP origin.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	quicsniff "github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"golang.org/x/crypto/hkdf"
)

const quicRouteHost = "quic-route.invalid"

func TestNativeVPNRoutingRuntimeQUICInitial(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("QUIC routing runtime is remote-CI-only")
	}
	var dnsCalls atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("numeric QUIC fixture forbids system DNS")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if dnsCalls.Load() != 0 {
			t.Error("QUIC routeOnly attempted system DNS")
		}
	})

	hello := quicClientHello(t, quicRouteHost)
	name, nameLength, _ := quicNameOffsets(t, hello)
	wrong := quicClientHello(t, "wrong-route.invalid")
	empty := quicEmptyName(t, hello)
	var cid [8]byte
	if _, err := rand.Read(cid[:]); err != nil {
		t.Fatal(err)
	}
	packet := func(number uint32, spans ...quicCryptoSpan) []byte {
		return quicInitial(t, cid[:], number, spans)
	}
	whole := packet(0, quicCryptoSpan{0, hello})
	cut := name + 5
	prefix := packet(1, quicCryptoSpan{0, hello[:cut]})
	suffix := packet(2, quicCryptoSpan{cut, hello[cut:]})
	// A hole inside SNI must not be interpreted as an empty/partial hostname.
	gap := packet(3, quicCryptoSpan{0, hello[:name+3]}, quicCryptoSpan{name + 5, hello[name+5:]})
	repair := packet(4, quicCryptoSpan{name + 3, hello[name+3 : name+5]})
	// The two missing name-length bytes become zero in the sniffer's newly
	// extended buffer. The Core31 nonempty-hostname fix must reject this.
	lengthGap := packet(5, quicCryptoSpan{0, hello[:nameLength]}, quicCryptoSpan{nameLength + 2, hello[nameLength+2:]})
	corrupt := bytes.Clone(whole)
	corrupt[len(corrupt)-1] ^= 1 // fail AEAD, not merely a parser shape check
	cases := []struct {
		name      string
		datagrams [][]byte
		domain    string
		needMore  bool
	}{
		{"whole", [][]byte{whole}, quicRouteHost, false},
		{"frames-out-of-order", [][]byte{packet(6, quicCryptoSpan{cut, hello[cut:]}, quicCryptoSpan{0, hello[:cut]})}, quicRouteHost, false},
		{"coalesced-initials", [][]byte{append(bytes.Clone(prefix), suffix...)}, quicRouteHost, false},
		{"separate-datagrams", [][]byte{prefix, suffix}, quicRouteHost, false},
		{"gap-repaired", [][]byte{append(bytes.Clone(gap), repair...)}, quicRouteHost, false},
		{"gap-in-sni", [][]byte{gap}, "", true},
		{"gap-in-name-length", [][]byte{lengthGap}, "", true},
		{"empty-sni", [][]byte{packet(7, quicCryptoSpan{0, empty})}, "", true},
		{"wrong-sni", [][]byte{packet(8, quicCryptoSpan{0, wrong})}, "wrong-route.invalid", false},
		{"truncated-packet", [][]byte{whole[:len(whole)-1]}, "", false},
		{"bad-authentication", [][]byte{corrupt}, "", false},
	}
	for _, c := range cases {
		t.Run("decoder/"+c.name, func(t *testing.T) {
			data := bytes.Join(c.datagrams, nil)
			h, err := quicsniff.SniffQUIC(bytes.Clone(data)) // production decoder mutates its scratch input
			if c.domain != "" {
				if err != nil || h == nil || h.Domain() != c.domain || h.Protocol() != "quic" {
					t.Fatalf("real QUIC decoder mismatch: header=%v error=%v", h, err)
				}
			} else if err == nil || h != nil || c.needMore && !errors.Is(err, protocol.ErrProtoNeedMoreData) {
				t.Fatalf("incomplete/invalid Initial was accepted: header=%v error=%v", h, err)
			}
		})
	}
	for _, defaultTag := range []string{"direct", "proxy"} {
		for _, enabled := range []bool{true, false} {
			t.Run(fmt.Sprintf("route/default-%s/sniff-%t", defaultTag, enabled), func(t *testing.T) {
				f := newQUICRoutingFixture(t, defaultTag, enabled)
				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						expected := defaultTag
						if enabled && c.domain == quicRouteHost {
							expected = "proxy"
							if defaultTag == "proxy" {
								expected = "direct"
							}
						}
						f.exchange(t, c.datagrams, expected)
					})
				}
			})
		}
	}
	t.Log("CORE31_QUIC_INITIAL_PASS decoder=11 directions=2 sniff-controls=2 exact-datagrams=true")
}

// Capture a genuine TLS1.3 ClientHello without opening any network socket.
type quicHelloCapture struct{ bytes.Buffer }

func (*quicHelloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (*quicHelloCapture) Close() error                     { return nil }
func (*quicHelloCapture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*quicHelloCapture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*quicHelloCapture) SetDeadline(time.Time) error      { return nil }
func (*quicHelloCapture) SetReadDeadline(time.Time) error  { return nil }
func (*quicHelloCapture) SetWriteDeadline(time.Time) error { return nil }

func quicClientHello(t *testing.T, host string) []byte {
	t.Helper()
	capture := new(quicHelloCapture)
	client := tls.Client(capture, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.HandshakeContext(ctx); err == nil {
		t.Fatal("capture unexpectedly completed a TLS handshake")
	}
	data := capture.Bytes()
	if len(data) < 9 || data[0] != 22 || data[5] != 1 {
		t.Fatal("crypto/tls did not emit ClientHello")
	}
	size := int(binary.BigEndian.Uint16(data[3:5]))
	if size+5 > len(data) || size < 64 {
		t.Fatal("captured ClientHello is incomplete")
	}
	return bytes.Clone(data[5 : 5+size])
}

// Return the SNI bytes, hostname-length field and enclosing extension-length
// field. The offsets are discovered from TLS lengths, never fixed byte guesses.
func quicNameOffsets(t *testing.T, hello []byte) (int, int, int) {
	t.Helper()
	p := 39 + int(hello[38])
	p += 2 + int(binary.BigEndian.Uint16(hello[p:p+2]))
	p += 1 + int(hello[p])
	end := p + 2 + int(binary.BigEndian.Uint16(hello[p:p+2]))
	for p += 2; p+4 <= end; {
		n := int(binary.BigEndian.Uint16(hello[p+2 : p+4]))
		if binary.BigEndian.Uint16(hello[p:p+2]) == 0 {
			if n < 5 || hello[p+6] != 0 {
				t.Fatal("unexpected generated SNI structure")
			}
			return p + 9, p + 7, p + 2
		}
		p += 4 + n
	}
	t.Fatal("generated ClientHello has no SNI extension")
	return 0, 0, 0
}

func quicEmptyName(t *testing.T, original []byte) []byte {
	t.Helper()
	name, length, extLength := quicNameOffsets(t, original)
	n := int(binary.BigEndian.Uint16(original[length : length+2]))
	result := append(bytes.Clone(original[:name]), original[name+n:]...)
	binary.BigEndian.PutUint16(result[length:length+2], 0)
	binary.BigEndian.PutUint16(result[extLength:extLength+2], 5)
	binary.BigEndian.PutUint16(result[extLength+2:extLength+4], 3)
	p := 39 + int(result[38])
	p += 2 + int(binary.BigEndian.Uint16(result[p:p+2]))
	p += 1 + int(result[p])
	binary.BigEndian.PutUint16(result[p:p+2], uint16(int(binary.BigEndian.Uint16(result[p:p+2]))-n))
	handshakeLength := len(result) - 4
	result[1], result[2], result[3] = byte(handshakeLength>>16), byte(handshakeLength>>8), byte(handshakeLength)
	return result
}

type quicCryptoSpan struct {
	offset int
	data   []byte
}

func quicVarint(value int) []byte {
	if value < 64 {
		return []byte{byte(value)}
	}
	if value >= 16384 || value < 0 {
		panic("fixture varint exceeds its explicit 14-bit bound")
	}
	return binary.BigEndian.AppendUint16(nil, uint16(value)|0x4000)
}

func quicExpand(t *testing.T, secret []byte, label string, n int) []byte {
	t.Helper()
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out); err != nil {
		t.Fatal(err)
	}
	return out
}

func quicInitial(t *testing.T, cid []byte, number uint32, spans []quicCryptoSpan) []byte {
	t.Helper()
	// RFC9001 section5.2, v1 Initial salt; no Core cryptographic helpers used.
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initial := hkdf.Extract(sha256.New, cid, salt)
	secret := quicExpand(t, initial, "client in", 32)
	key, iv, hp := quicExpand(t, secret, "quic key", 16), quicExpand(t, secret, "quic iv", 12), quicExpand(t, secret, "quic hp", 16)
	plain := []byte{}
	for _, span := range spans {
		plain = append(plain, 6)
		plain = append(plain, quicVarint(span.offset)...)
		plain = append(plain, quicVarint(len(span.data))...)
		plain = append(plain, span.data...)
	}
	// Pad in authenticated plaintext. Each Initial is at least 1200 bytes;
	// zero-tail/coalesced datagrams exercise the production cached reader.
	header := []byte{0xc3, 0, 0, 0, 1, byte(len(cid))}
	header = append(header, cid...)
	header = append(header, 0, 0) // source CID length and token length
	minimumPlain := 1200 - (len(header) + 2 + 4 + 16)
	if len(plain) < minimumPlain {
		plain = append(plain, make([]byte, minimumPlain-len(plain))...)
	}
	header = append(header, quicVarint(4+len(plain)+16)...)
	pnOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, number)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Clone(iv)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(number >> (8 * i))
	}
	packet := append(bytes.Clone(header), aead.Seal(nil, nonce, plain, header)...)
	maskBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	maskBlock.Encrypt(mask[:], packet[pnOffset+4:pnOffset+20])
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet
}

type quicUDPOrigin struct {
	socket   *net.UDPConn
	marker   string
	mu       sync.Mutex
	seen     map[string]int
	expected map[string]int
	errors   []error
	done     chan struct{}
}

func newQUICUDPOrigin(t *testing.T, marker string) *quicUDPOrigin {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	o := &quicUDPOrigin{socket: socket, marker: marker, seen: map[string]int{}, expected: map[string]int{}, done: make(chan struct{})}
	go func() {
		defer close(o.done)
		data := make([]byte, 32768)
		for {
			n, peer, err := socket.ReadFromUDP(data)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					o.mu.Lock()
					o.errors = append(o.errors, err)
					o.mu.Unlock()
				}
				return
			}
			digest := sha256.Sum256(data[:n])
			key := hex.EncodeToString(digest[:])
			o.mu.Lock()
			o.seen[key]++
			o.mu.Unlock()
			if _, err := socket.WriteToUDP([]byte(marker+"|"+key), peer); err != nil {
				o.mu.Lock()
				o.errors = append(o.errors, err)
				o.mu.Unlock()
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = socket.Close()
		select {
		case <-o.done:
		case <-time.After(2 * time.Second):
			t.Error("QUIC UDP origin did not drain")
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if len(o.errors) != 0 || len(o.seen) != len(o.expected) {
			t.Errorf("QUIC %s origin failure/count mismatch: errors=%v got=%v want=%v", marker, o.errors, o.seen, o.expected)
		}
		for key, count := range o.expected {
			if o.seen[key] != count {
				t.Errorf("QUIC %s wrong-destination/duplicate/changed-payload receipt", marker)
			}
		}
	})
	return o
}

type quicRoutingFixture struct {
	privatePort int
	targetPort  int
	origins     map[string]*quicUDPOrigin
}

func quicConfig(t *testing.T, value map[string]any) *core.Config {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	document, err := confserial.DecodeJSONConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := document.Build()
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func quicCloseCore(t *testing.T, instance *core.Instance) {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- instance.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Error("QUIC Core Close", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("QUIC Core did not close within deadline")
	}
}

func newQUICRoutingFixture(t *testing.T, defaultTag string, enabled bool) *quicRoutingFixture {
	t.Helper()
	f := &quicRoutingFixture{origins: map[string]*quicUDPOrigin{
		"direct": newQUICUDPOrigin(t, "direct"), "proxy": newQUICUDPOrigin(t, "proxy"),
	}}
	f.targetPort = f.origins["direct"].socket.LocalAddr().(*net.UDPAddr).Port
	reserve := func() net.Listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	proxyReservation, inputReservation := reserve(), reserve()
	proxyPort := proxyReservation.Addr().(*net.TCPAddr).Port
	f.privatePort = inputReservation.Addr().(*net.TCPAddr).Port
	proxyConfiguration := quicConfig(t, map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": proxyPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"redirect": f.origins["proxy"].socket.LocalAddr().String()}}},
	})
	proxyCore, err := core.New(proxyConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { quicCloseCore(t, proxyCore) })
	_ = proxyReservation.Close()
	if err := proxyCore.Start(); err != nil {
		t.Fatal(err)
	}
	ruleTag := "proxy"
	if defaultTag == "proxy" {
		ruleTag = "direct"
	}
	configuration := quicConfig(t, map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{"tag": "managed-quic", "listen": "127.0.0.1", "port": f.privatePort, "protocol": "socks",
			"settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": nativeRuntimeUser, "pass": nativeRuntimePassword}}, "udp": true},
			"sniffing": map[string]any{"enabled": enabled, "destOverride": []string{"quic"}, "routeOnly": true}}},
		"outbounds": []any{map[string]any{"tag": "ordinary-default-must-not-win", "protocol": "blackhole"},
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}, map[string]any{"action": "block"}}}},
			map[string]any{"tag": "proxy", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": proxyPort}}}}},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"caller-quic"}, "network": "udp", "domain": []string{"full:" + quicRouteHost}, "outboundTag": ruleTag}}},
	})
	owner, err := routing.NewNativeRoutingOwner(routing.NativeRoutingPolicy{Key: configuration.Inbound[0], ManagedTag: "managed-quic", AuthUser: nativeRuntimeUser,
		AliasEnabled: true, InboundAlias: "caller-quic", DefaultOutboundTag: defaultTag})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := dispatcher.ContextWithNativeVPNRouting(context.Background(), owner, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	instance, err := core.NewWithContext(ctx, configuration)
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(); quicCloseCore(t, instance) })
	if err := owner.Seal(instance); err != nil {
		t.Fatal(err)
	}
	_ = inputReservation.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *quicRoutingFixture) exchange(t *testing.T, datagrams [][]byte, expected string) {
	t.Helper()
	// Existing authenticated numeric SOCKS encoder is also used by the original
	// UDP native-owner acceptance; there is no mock dispatcher/context grant.
	helper := &nativeRuntimeFixture{privatePort: f.privatePort}
	u := helper.udp(t)
	defer u.close()
	_ = u.socket.SetDeadline(time.Now().Add(3 * time.Second))
	wanted := map[string]int{}
	for _, packet := range datagrams {
		digest := sha256.Sum256(packet)
		key := hex.EncodeToString(digest[:])
		wanted[expected+"|"+key]++
		f.origins[expected].expected[key]++
		encoded := append(append([]byte{0, 0, 0}, nativeRuntimeAddress("127.0.0.1", f.targetPort)...), packet...)
		if _, err := u.socket.WriteToUDP(encoded, u.relay); err != nil {
			t.Fatal(err)
		}
	}
	for range datagrams {
		response := make([]byte, 1024)
		n, peer, err := u.socket.ReadFromUDP(response)
		if err != nil || peer == nil || !peer.IP.Equal(u.relay.IP) || peer.Port != u.relay.Port || n < 10 || !bytes.Equal(response[:4], []byte{0, 0, 0, 1}) {
			t.Fatal("QUIC SOCKS UDP response failed", err)
		}
		// The original numeric destination must survive routeOnly even on the
		// second Core/SOCKS path; a sniffed hostname cannot stand in for it.
		if !net.IP(response[4:8]).Equal(net.IPv4(127, 0, 0, 1)) || int(binary.BigEndian.Uint16(response[8:10])) != f.targetPort {
			t.Fatal("QUIC routeOnly changed SOCKS UDP target")
		}
		key := string(response[10:n])
		if wanted[key] == 0 {
			t.Fatalf("QUIC wrong route, payload modification or duplicate: %q", key)
		}
		wanted[key]--
	}
	for _, count := range wanted {
		if count != 0 {
			t.Fatal("QUIC missing exact origin receipt")
		}
	}
}
