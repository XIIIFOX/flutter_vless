package native_dns_preservation_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dns "github.com/miekg/dns"
	appdns "github.com/xtls/xray-core/app/dns"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/infra/conf/serial"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const dohChildSpec = "FLUTTER_VLESS_DOH_CHILD_SPEC"
const dohAddressEnvironment = "FLUTTER_VLESS_FIXTURE_DOH_ADDRESS"
const dohHostEnvironment = "FLUTTER_VLESS_FIXTURE_DOH_HOST"

type dohOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (output *dohOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	count := len(data)
	remaining := 65536 - len(output.data)
	if len(data) > remaining {
		data = data[:remaining]
		output.truncated = true
	}
	output.data = append(output.data, data...)
	return count, nil // consume all pipe bytes, even after the capture limit
}

func (output *dohOutput) snapshot() ([]byte, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.data...), output.truncated
}

type dohMaterial struct {
	ca, foreignCA []byte
	good, wrong   tls.Certificate
}

// Pure crypto/material construction: no Core, default roots, sockets or OS trust.
func makeDoHMaterial(t *testing.T) dohMaterial {
	t.Helper()
	makeCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	ca, key, caPEM := makeCA("owned DoH fixture CA")
	_, _, foreign := makeCA("unrelated DoH fixture CA")
	leaf := func(name string, serial int64) tls.Certificate {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		result, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	return dohMaterial{ca: caPEM, foreignCA: foreign, good: leaf("resolver.invalid", 2), wrong: leaf("other.invalid", 3)}
}

func dohDocument(proxyPort int, apiAddress, resolverAddress, question string) map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"api": map[string]any{"tag": "caller-api", "listen": apiAddress, "services": []string{"StatsService"}}, "stats": map[string]any{},
		"policy": map[string]any{"system": map[string]any{"statsInboundUplink": false, "statsInboundDownlink": false, "statsOutboundUplink": false, "statsOutboundDownlink": false}},
		"outbounds": []any{
			map[string]any{"tag": "proxy", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "endpoint.invalid", "port": proxyPort}}}},
			map[string]any{"tag": "dns-direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "AsIs", "finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}, map[string]any{"action": "block"}}}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"dns": map[string]any{"queryStrategy": "UseIP", "disableCache": true, "disableFallback": true,
			"hosts":   map[string]any{"endpoint.invalid": "127.0.0.2", "resolver.invalid": "127.0.0.1", "static.invalid": "192.0.2.14"},
			"servers": []any{map[string]any{"address": resolverAddress, "domains": []string{"full:" + question}, "tag": "caller-doh", "skipFallback": true, "timeoutMs": 700}, "tcp://9.9.9.9"}},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"caller-doh"}, "outboundTag": "dns-direct"},
			map[string]any{"type": "field", "domain": []string{"full:remote-marker.invalid"}, "outboundTag": "proxy"},
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "block"},
		}},
	}
}

func TestNativeDoHMaterialOnly(t *testing.T) {
	// The actual static-host matcher is inert: no Core instance, DNS client,
	// listener or resolver. Schema folding must not alter domain-rule syntax.
	for _, tc := range []struct {
		key, question string
		match         bool
	}{
		{"resolver.invalid", "resolver.invalid", true},
		{"full:resolver.invalid", "resolver.invalid", true},
		{"full:ReSoLvEr.InVaLiD", "resolver.invalid", true},
		{"FULL:resolver.invalid", "resolver.invalid", false},
		{"full:resolver.invalid.", "resolver.invalid", false},
		{"reſolver.invalid", "resolver.invalid", false},
		{"full:Kelvin.invalid", "kelvin.invalid", true},
		{"full:İnternal.invalid", "internal.invalid", true},
	} {
		raw, err := json.Marshal(map[string]any{"dns": map[string]any{"hosts": map[string]any{tc.key: "192.0.2.53"}}})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := serial.DecodeJSONConfig(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		mappings, err := decoded.DNSConfig.Hosts.Build()
		if err != nil {
			t.Fatal(err)
		}
		hosts, err := appdns.NewStaticHosts(mappings)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := hosts.Lookup(tc.question, dnsfeature.IPOption{IPv4Enable: true})
		count := 0
		if tc.match {
			count = 1
		}
		if err != nil || len(answer) != count || tc.match && answer[0].String() != "192.0.2.53" {
			t.Fatalf("Core static-host semantics differ for %q: %v %v", tc.key, answer, err)
		}
	}
	output := new(dohOutput)
	input := bytes.Repeat([]byte("synthetic-output"), 20000)
	if count, err := output.Write(input); err != nil || count != len(input) {
		t.Fatal("bounded writer stopped draining")
	}
	captured, truncated := output.snapshot()
	if !truncated || len(captured) != 65536 || !bytes.Equal(captured, input[:65536]) {
		t.Fatal("child output capture is not bounded")
	}
	captured[0] ^= 1
	if second, _ := output.snapshot(); second[0] != input[0] {
		t.Fatal("child output snapshot aliases live storage")
	}
	material := makeDoHMaterial(t)
	for name, leaf := range map[string]tls.Certificate{"good": material.good, "wrong-name": material.wrong} {
		certificate, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(material.ca)
		_, err = certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: "resolver.invalid"})
		if (err == nil) != (name == "good") {
			t.Fatal("synthetic CA/name control failed", name, err)
		}
	}
	leaf, err := x509.ParseCertificate(material.good.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	foreign := x509.NewCertPool()
	foreign.AppendCertsFromPEM(material.foreignCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: foreign, DNSName: "resolver.invalid"}); err == nil {
		t.Fatal("unrelated CA trusted the fixture")
	}
	data, err := json.Marshal(dohDocument(18071, "127.0.0.1:18072", "https://resolver.invalid:18073/dns-query", "tls-probe.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configuration.Build(); err != nil {
		t.Fatal(err)
	}
}

type dohSpec struct {
	Prepared, Source, API, Question, Mode string
	Port                                  int
}

func assertDoHProxyTLS(t *testing.T, source, effective map[string]any, directory string) {
	t.Helper()
	sourceTLS := source["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
	effectiveTLS := effective["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
	encoded, err := json.Marshal(sourceTLS)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if err := json.Unmarshal(encoded, &expected); err != nil {
		t.Fatal(err)
	}
	if expected["certificates"].([]any)[0].(map[string]any)["certificateFile"] != "proxy-ca.pem" {
		t.Fatal("source certificate path was not retained")
	}
	expected["certificates"].([]any)[0].(map[string]any)["certificateFile"] = filepath.Join(directory, "proxy-ca.pem")
	// This is the existing mandatory privacy adaptation in both preparers.
	// Continue comparing every other TLS field, including verification flags.
	expected["masterKeyLog"] = ""
	if !reflect.DeepEqual(expected, effectiveTLS) {
		t.Fatal("effective TLS fields differ beyond the certificate path and private key-log policy")
	}
}

// The same whole-TLS assertion as the child, exercised before any runtime.
// Only native file exporters and Core Decode/Build execute here.
func testDoHProxyCertificatePreparation(t *testing.T) {
	material := makeDoHMaterial(t)
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "proxy-ca.pem"), material.ca, 0600); err != nil {
		t.Fatal(err)
	}
	source := dohDocument(18071, "127.0.0.1:18072", "https://resolver.invalid:18073/dns-query", "tls-probe.invalid")
	source["outbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{
		"security": "tls", "tlsSettings": map[string]any{
			"serverName": "resolver.invalid", "disableSystemRoot": true,
			"certificates": []any{map[string]any{"certificateFile": "proxy-ca.pem", "usage": "verify", "oneTimeLoading": true}},
		},
	}
	document, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	bound := certificateDocument(t, bindCertificateFixture(t, document, directory))
	prepared, _ := prepare(t, bound)
	assertDoHProxyTLS(t, source, certificateDocument(t, prepared), directory)
	if _, err := certificateBuild(prepared); err != nil {
		t.Fatal("prepared TLS file profile failed Core Build")
	}
	after, _ := json.Marshal(source)
	if !bytes.Equal(document, after) {
		t.Fatal("TLS assertion changed the source profile")
	}
}

func testNativeHTTPSDoH(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("HTTPS DoH runtime is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	material := makeDoHMaterial(t)
	proxyMaterial := makeDoHMaterial(t)
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caPath, wrongCAPath := write("ca.pem", material.ca), write("unrelated-ca.pem", material.foreignCA)
	write("proxy-ca.pem", proxyMaterial.ca)
	for name, certificate := range map[string]*tls.Certificate{"server": &material.good, "wrong-name": &material.wrong} {
		key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		certFile := write(name+"-certificate.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))
		keyFile := write(name+"-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
		loaded, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		*certificate = loaded
	}
	emptyRoots := filepath.Join(directory, "empty-roots")
	if err := os.Mkdir(emptyRoots, 0700); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	mode := "good"
	hellos, requests, proxyTLS := map[string]int{}, map[string]int{}, map[string]int{}
	origin := new(fixture)
	completed := false
	// Registered before listeners: include late owned callbacks after drain.
	t.Cleanup(func() {
		if !completed {
			return
		}
		mu.Lock()
		good, full, badCA, badName := requests["good"], requests["good-full-hosts"], requests["bad-ca"], requests["bad-name"]
		mu.Unlock()
		if good != 4 || full != 4 || badCA != 0 || badName != 0 {
			t.Error("late DoH request count changed", good, full, badCA, badName)
		}
		seen, failures := origin.snapshot()
		if !reflect.DeepEqual(seen, []string{"HTTP remote-marker.invalid", "HTTP remote-marker.invalid", "HTTP remote-marker.invalid", "HTTP remote-marker.invalid"}) || len(failures) != 0 {
			t.Error("DoH source proxy/bootstrap marker failed", seen, failures)
		}
	})
	proxyPort := socksMarkerWithTLS(t, origin, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			if hello.ServerName != "resolver.invalid" {
				return nil, errors.New("certificate-asset proxy SNI changed")
			}
			proxyTLS[mode]++
			return &proxyMaterial.good, nil
		},
	})
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	question := fmt.Sprintf("tls-%x.invalid", nonce)
	var authority string
	tlsConfig := &tls.Config{NextProtos: []string{"h2"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		if hello.ServerName != "resolver.invalid" {
			return nil, errors.New("DoH SNI changed")
		}
		hellos[mode]++
		if mode == "bad-name" {
			return &material.wrong, nil
		}
		return &material.good, nil
	}}
	resolver := listener(t, func(raw net.Conn) {
		secured := tls.Server(raw, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			return
		} // expected negative certificate controls
		server := new(http2.Server)
		server.ServeConn(secured, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			if r.TLS == nil || r.TLS.NegotiatedProtocol != "h2" || r.Method != "POST" || r.Host != authority || r.URL.RequestURI() != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
				origin.fail(errors.New("DoH TLS/HTTP2 host/path/method changed"))
				w.WriteHeader(400)
				return
			}
			packet, err := io.ReadAll(io.LimitReader(r.Body, 4097))
			query := new(dns.Msg)
			if err != nil || len(packet) > 4096 || query.Unpack(packet) != nil || len(query.Question) != 1 || query.Question[0].Name != question+"." || query.Question[0].Qclass != dns.ClassINET {
				origin.fail(errors.New("DoH wire question changed"))
				w.WriteHeader(400)
				return
			}
			answer := new(dns.Msg)
			answer.SetReply(query)
			header := dns.RR_Header{Name: query.Question[0].Name, Rrtype: query.Question[0].Qtype, Class: dns.ClassINET, Ttl: 1}
			switch query.Question[0].Qtype {
			case dns.TypeA:
				answer.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.0.2.77")}}
			case dns.TypeAAAA:
				answer.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8:77::1")}}
			default:
				origin.fail(errors.New("unexpected DoH record type"))
				w.WriteHeader(400)
				return
			}
			mu.Lock()
			requests[mode]++
			mu.Unlock()
			encoded, err := answer.Pack()
			if err != nil {
				origin.fail(err)
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, err = w.Write(encoded)
			origin.fail(err)
		})})
	})
	authority = fmt.Sprintf("resolver.invalid:%d", resolver.Addr().(*net.TCPAddr).Port)
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	source := dohDocument(proxyPort, reservation.Addr().String(), "https://"+authority+"/dns-query", question)
	// A separate explicit CA keeps proxy TLS independent of the DoH negative
	// system-root controls. The source remains portable; only effective file
	// fields are frozen by the production native binder before Core preflight.
	source["outbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{
		"security": "tls", "tlsSettings": map[string]any{
			"serverName": "resolver.invalid", "disableSystemRoot": true,
			"certificates": []any{map[string]any{"certificateFile": "proxy-ca.pem", "usage": "verify", "oneTimeLoading": true}},
		},
	}
	prepareFiles := func(input map[string]any) ([]byte, int) {
		document, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		bound := bindCertificateFixture(t, document, directory)
		var candidate map[string]any
		if err := json.Unmarshal(bound, &candidate); err != nil {
			t.Fatal(err)
		}
		return prepare(t, candidate)
	}
	prepared, port := prepareFiles(source)
	sourceJSON, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	preparedPath, sourcePath := write("effective.json", prepared), write("source.json", sourceJSON)
	_ = reservation.Close()
	for _, variant := range []string{"good", "bad-ca", "bad-name", "good-full-hosts"} {
		childPrepared, childSource, childPort := preparedPath, sourcePath, port
		if variant == "good-full-hosts" {
			var fullSource map[string]any
			if err := json.Unmarshal(sourceJSON, &fullSource); err != nil {
				t.Fatal(err)
			}
			hosts := fullSource["dns"].(map[string]any)["hosts"].(map[string]any)
			delete(hosts, "resolver.invalid")
			// Core folds only the exact IPv4-mapped prefix to an IPv4 address.
			// Keep this raw caller spelling through native admission and handoff.
			hosts["full:resolver.invalid"] = "[::ffff:127.0.0.1]"
			fullPrepared, fullPort := prepareFiles(fullSource)
			fullJSON, err := json.Marshal(fullSource)
			if err != nil {
				t.Fatal(err)
			}
			// The app's environment is absent in the child which owns Core.
			// Compare the whole prepared profile with the literal control before
			// starting that child; URL substrings and host keys stay opaque.
			t.Setenv(dohAddressEnvironment, "https://"+authority+"/dns-query")
			t.Setenv(dohHostEnvironment, "[::ffff:127.0.0.1]")
			fullSource["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["address"] = "env:" + dohAddressEnvironment
			hosts["full:resolver.invalid"] = "env:" + dohHostEnvironment
			environmentJSON, err := json.Marshal(fullSource)
			if err != nil {
				t.Fatal(err)
			}
			frozen := prepareEndpointAddress(t, bindCertificateFixture(t, environmentJSON, directory))
			var literal map[string]any
			if json.Unmarshal(fullPrepared, &literal) != nil || !reflect.DeepEqual(literal, frozen) {
				t.Fatal("DoH environment preparation differs from literal control")
			}
			fullPrepared, err = json.Marshal(frozen)
			if err != nil {
				t.Fatal(err)
			}
			childPrepared, childSource, childPort = write("effective-full.json", fullPrepared), write("source-full.json", fullJSON), fullPort
		}
		mu.Lock()
		mode = variant
		mu.Unlock()
		data, err := json.Marshal(dohSpec{Prepared: childPrepared, Source: childSource, Port: childPort, API: source["api"].(map[string]any)["listen"].(string), Question: question, Mode: variant})
		if err != nil {
			t.Fatal(err)
		}
		path := write("child.json", data)
		childCtx, stop := context.WithTimeout(ctx, 8*time.Second)
		command := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestNativeHTTPSDoHChild$", "-test.v", "-test.timeout=8s")
		command.WaitDelay = time.Second
		for _, entry := range os.Environ() {
			key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
			if key != "SSL_CERT_FILE" && key != "SSL_CERT_DIR" && key != "GODEBUG" && key != dohChildSpec && key != dohAddressEnvironment && key != dohHostEnvironment && !strings.HasPrefix(key, "XRAY_") && !strings.HasPrefix(key, "XRAY.") {
				command.Env = append(command.Env, entry)
			}
		}
		trust := caPath
		if variant == "bad-ca" {
			trust = wrongCAPath
		}
		command.Env = append(command.Env, "SSL_CERT_FILE="+trust, "SSL_CERT_DIR="+emptyRoots, "GODEBUG=x509sslcertoverrideplatform=1", dohChildSpec+"="+path,
			dohAddressEnvironment+"=https://unreachable.invalid/dns-query", dohHostEnvironment+"=127.0.0.2")
		capture := new(dohOutput)
		command.Stdout, command.Stderr = capture, capture
		err = command.Run()
		output, truncated := capture.snapshot()
		stop()
		if err != nil || truncated || !bytes.Contains(output, []byte("DOH_CHILD_OK="+variant)) || !bytes.Contains(output, []byte("--- PASS: TestNativeHTTPSDoHChild")) {
			t.Fatalf("bounded DoH child %s failed: %v: %s", variant, err, output)
		}
		mu.Lock()
		h, r, p := hellos[variant], requests[variant], proxyTLS[variant]
		mu.Unlock()
		positive := variant == "good" || variant == "good-full-hosts"
		if h == 0 || p == 0 || positive && r != 4 || !positive && r != 0 {
			t.Fatal("DoH handshake/request causal control failed", variant, h, r)
		}
		t.Log("TLS_CERTIFICATE_ASSET_BYTES_PASS=" + variant)
		if variant == "good-full-hosts" {
			t.Log("DNS_ADDRESS_DOH_ENVIRONMENT_FROZEN_PASS")
			t.Log("DNS_IPV4_MAPPED_DOH_PASS")
		}
	}
	completed = true
	t.Log("PASS named HTTPS DoH preserves bare/full: hosts, SNI/Host/path and caller A/AAAA policy; untrusted and wrong-name certificates fail without OS fallback; caller API and private endpoint pins survive")
}

func TestNativeHTTPSDoHChild(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("DoH child runtime is CI-only")
	}
	data, err := os.ReadFile(os.Getenv(dohChildSpec))
	if err != nil {
		t.Fatal(err)
	}
	var spec dohSpec
	if len(data) > 4096 || json.Unmarshal(data, &spec) != nil || (spec.Mode != "good" && spec.Mode != "good-full-hosts" && spec.Mode != "bad-ca" && spec.Mode != "bad-name") {
		t.Fatal("invalid owned DoH child specification")
	}
	var attempts atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("forbidden DoH OS lookup")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if attempts.Load() != 0 {
			t.Error("DoH attempted OS resolver")
		}
	})
	prepared, err := os.ReadFile(spec.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	sourceJSON, err := os.ReadFile(spec.Source)
	if err != nil {
		t.Fatal(err)
	}
	var source, effective map[string]any
	if json.Unmarshal(sourceJSON, &source) != nil || json.Unmarshal(prepared, &effective) != nil {
		t.Fatal("invalid DoH documents")
	}
	assertCallerServiceRoots(t, source, effective)
	if !reflect.DeepEqual(source["dns"], effective["dns"]) || !reflect.DeepEqual(source["outbounds"].([]any)[0].(map[string]any)["settings"], effective["outbounds"].([]any)[0].(map[string]any)["settings"]) {
		t.Fatal("DoH source DNS/proxy settings changed")
	}
	assertDoHProxyTLS(t, source, effective, filepath.Dir(spec.Prepared))
	configuration, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		t.Fatal(err)
	}
	built, err := configuration.Build()
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
	})
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	api, err := grpc.NewClient(spec.API, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	checkAPI := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		reply, err := statscommand.NewStatsServiceClient(api).QueryStats(ctx, &statscommand.QueryStatsRequest{})
		if err != nil || len(reply.GetStat()) != 0 {
			t.Fatal("DoH caller API/counter policy changed", err)
		}
	}
	checkAPI()
	if spec.Mode == "good" || spec.Mode == "good-full-hosts" {
		for _, udp := range []bool{false, true} {
			for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
				answer := query(t, spec.Port, udp, spec.Question, kind)
				if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
					t.Fatal("HTTPS DoH address answer missing", answer)
				}
				if kind == dns.TypeA {
					record, ok := answer.Answer[0].(*dns.A)
					if !ok || record.A.String() != "192.0.2.77" {
						t.Fatal("DoH A changed", answer)
					}
				} else {
					record, ok := answer.Answer[0].(*dns.AAAA)
					if !ok || record.AAAA.String() != "2001:db8:77::1" {
						t.Fatal("DoH AAAA changed", answer)
					}
				}
			}
		}
	} else {
		connection, _ := connect(t, spec.Port, 1, netip.MustParseAddrPort("198.18.0.2:53"), "")
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		question := new(dns.Msg)
		question.SetQuestion(spec.Question+".", dns.TypeA)
		packet, err := question.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if err := binaryWriteDNS(connection, packet); err != nil {
			t.Fatal(err)
		}
		var size [2]byte
		if _, err := io.ReadFull(connection, size[:]); err == nil {
			length := int(size[0])<<8 | int(size[1])
			if length < 12 || length > 4096 {
				t.Fatal("invalid negative DoH reply")
			}
			packet = make([]byte, length)
			if _, err := io.ReadFull(connection, packet); err != nil {
				t.Fatal(err)
			}
			answer := new(dns.Msg)
			if answer.Unpack(packet) != nil || !answer.Response || answer.Id != question.Id || !reflect.DeepEqual(answer.Question, question.Question) || len(answer.Answer) != 0 {
				t.Fatal("untrusted DoH returned addresses or changed question")
			}
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal("negative DoH ended without bounded timeout/reply", err)
		}
		_ = connection.Close()
	}
	static := query(t, spec.Port, false, "static.invalid", dns.TypeA)
	if static.Rcode != dns.RcodeSuccess || len(static.Answer) != 1 {
		t.Fatal("DoH failure changed caller static hosts")
	}
	if record, ok := static.Answer[0].(*dns.A); !ok || record.A.String() != "192.0.2.14" {
		t.Fatal("DoH failure changed static host value")
	}
	connection, _ := connect(t, spec.Port, 1, netip.MustParseAddrPort("0.0.0.0:80"), "remote-marker.invalid")
	defer connection.Close()
	if _, err := io.WriteString(connection, "GET /proof HTTP/1.1\r\nHost: remote-marker.invalid\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	_ = response.Body.Close()
	if err != nil || string(body) != "PINNED_ENDPOINT_OK" {
		t.Fatal("DoH candidate lost its proxy/bootstrap marker", err)
	}
	checkAPI()
	fmt.Println("DOH_CHILD_OK=" + spec.Mode)
}

func binaryWriteDNS(writer io.Writer, packet []byte) error {
	frame := append([]byte{byte(len(packet) >> 8), byte(len(packet))}, packet...)
	_, err := writer.Write(frame)
	return err
}
