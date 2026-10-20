package native_dns_preservation_test

// A separately bounded CI phase: native-prepared independent XHTTP download,
// owned TLS roots and HTTP/2 fronts over the existing cleartext VLESS backend.
// This does not qualify Core inbound TLS, H3, or a platform VPN socket hook.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"golang.org/x/net/http2"
)

const xhttpTLSChildSpec = "FLUTTER_VLESS_XHTTP_TLS_CHILD_SPEC"

type xhttpTLSSpec struct {
	Prepared, Origin, Mode, Nonce string
	Port                          int
}

type xhttpTLSMaterial struct {
	ca, foreign      []byte
	upload, download tls.Certificate
}

func makeXHTTPTLSMaterial(t *testing.T) xhttpTLSMaterial {
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
	ca, key, caPEM := makeCA("owned XHTTP TLS fixture CA")
	_, _, foreign := makeCA("unrelated XHTTP TLS fixture CA")
	leaf := func(name string, number int64) tls.Certificate {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(number), DNSNames: []string{name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		encodedKey, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}))
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	return xhttpTLSMaterial{caPEM, foreign, leaf("upload-tls.invalid", 2), leaf("download-tls.invalid", 3)}
}

func xhttpTLSRootPool(t *testing.T, certificate []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		t.Fatal("owned XHTTP root was not parsed")
	}
	return pool
}

func TestNativeXHTTPTLS(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("XHTTP TLS runtime is CI-only")
	}
	if os.Getenv("NATIVE_DNS_PREPARER") == "" {
		t.Fatal("production native preparer required")
	}
	t.Run("WindowsPreparer", testNativeXHTTPTLS)
	if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
		t.Run("ApplePreparer", func(t *testing.T) { t.Setenv("NATIVE_DNS_PREPARER", apple); testNativeXHTTPTLS(t) })
	}
}

func testNativeXHTTPTLS(t *testing.T) {
	var attempts atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("forbidden XHTTP TLS OS resolution")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if attempts.Load() != 0 {
			t.Error("XHTTP TLS attempted OS resolution")
		}
	})
	for _, mode := range []string{"independent", "wrong_ca", "wrong_sni"} {
		if t.Run(mode, func(t *testing.T) { runNativeXHTTPTLS(t, mode) }) {
			// t.Run includes all listener/Core cleanup and the final observer.
			t.Logf("XHTTP_TLS_H2_PASS mode=%s", mode)
		}
	}
}

type xhttpTLSCAFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Planning owns listeners and certificate files only: no Core, HTTP Serve or
// Accept worker runs until this exact case is activated after native export.
type xhttpTLSPlan struct {
	mode, nonce, directory, assetsDirectory, sourcePath string
	source                                              map[string]any
	sourceData                                          []byte
	material                                            xhttpTLSMaterial
	trust                                               []byte
	downloadName                                        string
	origin                                              *httptest.Server
	pending                                             map[string]net.Listener
	backendPort, uploadPort, downloadPort, privatePort  int
	caFiles                                             []xhttpTLSCAFile
}

func (p *xhttpTLSPlan) closePending() {
	for name, listener := range p.pending {
		_ = listener.Close()
		delete(p.pending, name)
	}
}

func (p *xhttpTLSPlan) claim(t *testing.T, name string) net.Listener {
	t.Helper()
	listener := p.pending[name]
	if listener == nil {
		t.Fatal("XHTTP TLS reservation already consumed", name)
	}
	delete(p.pending, name)
	return listener
}

func xhttpTLSWriteNew(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeError := file.Write(data)
	closeError := file.Close()
	if writeError != nil || closeError != nil {
		t.Fatal("XHTTP TLS private input write failed", writeError, closeError)
	}
}

func (p *xhttpTLSPlan) saveSource(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(p.source)
	if err != nil {
		t.Fatal(err)
	}
	xhttpTLSWriteNew(t, p.sourcePath, data)
	p.sourceData = data
}

func planXHTTPTLS(t *testing.T, mode, directory string, reservePrivate bool) *xhttpTLSPlan {
	t.Helper()
	if mode != "independent" && mode != "wrong_ca" && mode != "wrong_sni" {
		t.Fatal("unknown XHTTP TLS planned mode")
	}
	p := &xhttpTLSPlan{mode: mode, directory: directory, assetsDirectory: filepath.Join(directory, "assets"),
		sourcePath: filepath.Join(directory, "source.json"), material: makeXHTTPTLSMaterial(t), pending: map[string]net.Listener{}}
	t.Cleanup(p.closePending)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	p.nonce = hex.EncodeToString(nonce[:])
	p.origin = httptest.NewUnstartedServer(nil)
	p.pending["origin"] = p.origin.Listener
	reserve := func(name string) int {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p.pending[name] = listener
		return listener.Addr().(*net.TCPAddr).Port
	}
	p.backendPort, p.uploadPort, p.downloadPort = reserve("backend"), reserve("upload"), reserve("download")
	if reservePrivate {
		p.privatePort = reserve("private")
	}
	p.downloadName, p.trust = "download-tls.invalid", p.material.ca
	if mode == "wrong_ca" {
		p.trust = p.material.foreign
	}
	if mode == "wrong_sni" {
		p.downloadName = "wrong-download.invalid"
	}
	if err := os.Mkdir(p.assetsDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	caPath, downloadCAPath := filepath.Join(p.assetsDirectory, "upload-ca.pem"), filepath.Join(p.assetsDirectory, "download-ca.pem")
	for _, entry := range []struct {
		path string
		data []byte
	}{{caPath, p.material.ca}, {downloadCAPath, p.trust}} {
		xhttpTLSWriteNew(t, entry.path, entry.data)
		p.caFiles = append(p.caFiles, xhttpTLSCAFile{entry.path, fmt.Sprintf("%x", sha256.Sum256(entry.data))})
	}
	tlsSettings := func(name, ca string) map[string]any {
		return map[string]any{"serverName": name, "alpn": []string{"h2"}, "disableSystemRoot": true, "masterKeyLog": "",
			"certificates": []any{map[string]any{"usage": "verify", "certificateFile": ca}}}
	}
	headers := xhttpHeaderData()
	headers["X-Fixture-Nonce"] = p.nonce
	download := map[string]any{"address": "endpoint.invalid", "port": p.downloadPort, "network": "xhttp", "security": "tls",
		"tlsSettings": tlsSettings(p.downloadName, downloadCAPath), "sockopt": map[string]any{"tcpKeepAliveIdle": 7},
		"xhttpSettings": map[string]any{"path": "/download", "host": "download.invalid", "headers": headers}}
	stream := map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": tlsSettings("upload-tls.invalid", caPath),
		"sockopt": map[string]any{"penetrate": false}, "xhttpSettings": map[string]any{"path": "/upload", "host": "upload.invalid",
			"mode": "packet-up", "headers": headers, "downloadSettings": download}}
	p.source = map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{}, "outbounds": []any{
		map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"address": "endpoint.invalid", "port": p.uploadPort,
			"id": "11111111-1111-4111-8111-111111111111", "encryption": "none"}, "streamSettings": stream},
		map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}},
		"dns": map[string]any{"hosts": map[string]any{"endpoint.invalid": "127.0.0.2"}, "queryStrategy": "UseIPv4", "servers": []string{"tcp://9.9.9.9"}}}
	return p
}

func runNativeXHTTPTLS(t *testing.T, mode string) {
	plan := planXHTTPTLS(t, mode, t.TempDir(), false)
	plan.saveSource(t)
	activateXHTTPTLS(t, plan, func(t *testing.T) ([]byte, int) { return prepare(t, plan.source) })
}

func activateXHTTPTLS(t *testing.T, plan *xhttpTLSPlan, preparedInput func(*testing.T) ([]byte, int)) {
	mode, material, nonce := plan.mode, plan.material, plan.nonce
	payload := append([]byte(nonce+":"), xhttpPayload()...)
	observations := new(fixture)
	var uploadHellos, downloadHellos, uploadH2, downloadH2, badCertificates atomic.Int64
	var uploadHTTP, downloadHTTP, originBodies atomic.Int64
	var stopping atomic.Bool
	completed := false
	// First cleanup registration observes counters after every later close/join.
	t.Cleanup(func() {
		_, failures := observations.snapshot()
		if !completed {
			return
		}
		if len(failures) != 0 {
			t.Error("XHTTP TLS fixture errors", failures)
		}
		if mode == "independent" {
			if uploadHellos.Load() < 1 || downloadHellos.Load() < 1 || uploadH2.Load() < 1 || downloadH2.Load() < 1 ||
				uploadHTTP.Load() < 1 || downloadHTTP.Load() != 1 || originBodies.Load() != 1 || badCertificates.Load() != 0 {
				t.Error("XHTTP TLS positive handshake/header/payload counts changed")
			}
		} else if downloadHellos.Load() < 1 || badCertificates.Load() < 1 || downloadH2.Load() != 0 ||
			downloadHTTP.Load() != 0 || originBodies.Load() != 0 {
			t.Error("XHTTP TLS negative lacks certificate rejection or admitted application data")
		}
	})

	t.Cleanup(plan.closePending)
	origin := plan.origin
	origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
		if mode != "independent" || err != nil || r.Method != "POST" || r.Host != "payload.invalid" ||
			r.URL.Path != "/echo" || r.Header.Get("X-Fixture-Nonce") != nonce || !bytes.Equal(body, payload) {
			observations.fail(errors.New("XHTTP TLS origin application bytes changed"))
			http.Error(w, "fixture mismatch", http.StatusBadRequest)
			return
		}
		originBodies.Add(1)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, err = w.Write(body)
		observations.fail(err)
	})
	_ = plan.claim(t, "origin")
	origin.Config.ReadHeaderTimeout = 5 * time.Second
	origin.Start()
	t.Cleanup(func() { origin.CloseClientConnections(); origin.Close() })
	originAddress := netip.MustParseAddrPort(strings.TrimPrefix(origin.URL, "http://"))

	backendPort := plan.backendPort
	const identity = "11111111-1111-4111-8111-111111111111"
	backendSource := map[string]any{"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": backendPort, "protocol": "vless",
			"settings":       map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": identity}}},
			"streamSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/fixture", "host": "backend.invalid", "mode": "packet-up"}}}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"domainStrategy": "ForceIPv4",
			"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{originAddress.Addr().String() + "/32"}, "port": strconv.Itoa(int(originAddress.Port()))}}}}}}
	backendData, err := json.Marshal(backendSource)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(backendData))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	backendCore, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backendCore.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := plan.claim(t, "backend").Close(); err != nil {
		t.Fatal(err)
	}
	if err := backendCore.Start(); err != nil {
		t.Fatal(err)
	}
	backend, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", backendPort))

	downloadName, trust := plan.downloadName, plan.trust
	// Prove the exact intended CA/name mismatch independently of a socket EOF.
	leaf, err := x509.ParseCertificate(material.download.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, verifyError := leaf.Verify(x509.VerifyOptions{Roots: xhttpTLSRootPool(t, trust), DNSName: downloadName})
	var badCA x509.UnknownAuthorityError
	var badName x509.HostnameError
	if mode == "independent" && verifyError != nil || mode == "wrong_ca" && !errors.As(verifyError, &badCA) ||
		mode == "wrong_sni" && !errors.As(verifyError, &badName) {
		t.Fatal("XHTTP TLS certificate control does not have its exact intended cause")
	}

	front := func(role string) int {
		transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
		t.Cleanup(transport.CloseIdleConnections)
		proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(backend)
			request.Out.Host = "backend.invalid"
			request.Out.URL.Path = "/fixture" + strings.TrimPrefix(request.In.URL.Path, "/"+role)
		}, ErrorHandler: func(w http.ResponseWriter, request *http.Request, err error) {
			if !stopping.Load() && request.Context().Err() == nil {
				observations.fail(err)
			}
			http.Error(w, "fixture upstream closed", http.StatusBadGateway)
		}}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			wantName, certificate := "upload-tls.invalid", &material.upload
			if role == "download" {
				wantName, certificate = downloadName, &material.download
				downloadHellos.Add(1)
			} else {
				uploadHellos.Add(1)
			}
			// The pinned default Chrome fingerprint supplies its own offer even
			// with typed alpn=[h2]. The server accepts only h2; assert both the
			// actual pinned offer here and the negotiated protocol below.
			if hello.ServerName != wantName || !reflect.DeepEqual(hello.SupportedProtos, []string{"h2", "http/1.1"}) {
				observations.fail(errors.New("XHTTP TLS ClientHello role/SNI/ALPN changed"))
				return nil, errors.New("fixture ClientHello mismatch")
			}
			return certificate, nil
		}}
		l := networkListenerFrom(t, plan.claim(t, role), func(raw net.Conn) {
			_ = raw.SetDeadline(time.Now().Add(12 * time.Second))
			secured := tls.Server(raw, tlsConfig)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := secured.HandshakeContext(ctx)
			cancel()
			if err != nil {
				// The client must send the actual TLS bad_certificate alert;
				// timeout, EOF and local cleanup are not negative-proof substitutes.
				if role == "download" && mode != "independent" && strings.Contains(err.Error(), "remote error: tls: bad certificate") {
					badCertificates.Add(1)
				} else if !stopping.Load() {
					observations.fail(fmt.Errorf("%s TLS handshake error-class=%T", role, err))
				}
				return
			}
			if secured.ConnectionState().NegotiatedProtocol != "h2" {
				observations.fail(errors.New("XHTTP TLS did not negotiate h2"))
				return
			}
			if role == "download" {
				downloadH2.Add(1)
			} else {
				uploadH2.Add(1)
			}
			new(http2.Server).ServeConn(secured, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || r.TLS.NegotiatedProtocol != "h2" || r.ProtoMajor != 2 || r.Host != role+".invalid" ||
					!strings.HasPrefix(r.URL.Path, "/"+role+"/") || role == "upload" && r.Method != "POST" || role == "download" && r.Method != "GET" {
					observations.fail(errors.New("XHTTP TLS role authority/path/method/protocol changed"))
					http.Error(w, "fixture mismatch", http.StatusBadRequest)
					return
				}
				for key, value := range xhttpHeaderData() {
					if r.Header.Get(key) != value {
						observations.fail(errors.New("XHTTP TLS caller header changed"))
						http.Error(w, "fixture header mismatch", http.StatusBadRequest)
						return
					}
				}
				if r.Header.Get("X-Fixture-Nonce") != nonce {
					observations.fail(errors.New("XHTTP TLS front nonce changed"))
					http.Error(w, "fixture nonce mismatch", http.StatusBadRequest)
					return
				}
				if role == "download" {
					downloadHTTP.Add(1)
				} else {
					uploadHTTP.Add(1)
				}
				proxy.ServeHTTP(w, r)
			})})
		})
		t.Cleanup(func() { stopping.Store(true) })
		return l.Addr().(*net.TCPAddr).Port
	}
	front("upload")
	front("download")
	source := plan.source
	stream := source["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	download := stream["xhttpSettings"].(map[string]any)["downloadSettings"].(map[string]any)
	prepared, port := preparedInput(t)
	before := plan.sourceData
	after, _ := json.Marshal(source)
	if !bytes.Equal(before, after) {
		t.Fatal("native XHTTP TLS preparation mutated source")
	}
	var effective map[string]any
	if err := json.Unmarshal(prepared, &effective); err != nil {
		t.Fatal(err)
	}
	actualStream := effective["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	actualDownload := actualStream["xhttpSettings"].(map[string]any)["downloadSettings"].(map[string]any)
	if !reflect.DeepEqual(actualStream["tlsSettings"], jsonMap(t, stream["tlsSettings"])) ||
		!reflect.DeepEqual(actualDownload["tlsSettings"], jsonMap(t, download["tlsSettings"])) ||
		actualStream["security"] != "tls" || actualDownload["security"] != "tls" ||
		actualDownload["sockopt"].(map[string]any)["tcpKeepAliveIdle"] != float64(7) {
		t.Fatal("native XHTTP independent TLS/CA/SNI/ALPN changed")
	}
	directory := t.TempDir()
	preparedPath, specPath := filepath.Join(directory, "effective.json"), filepath.Join(directory, "child.json")
	if err := os.WriteFile(preparedPath, prepared, 0600); err != nil {
		t.Fatal(err)
	}
	specData, err := json.Marshal(xhttpTLSSpec{Prepared: preparedPath, Origin: originAddress.String(), Mode: mode, Nonce: nonce, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(specPath, specData, 0600); err != nil {
		t.Fatal(err)
	}
	if _, exists := plan.pending["private"]; exists {
		if port != plan.privatePort {
			t.Fatal("Android native private port changed")
		}
		if err := plan.claim(t, "private").Close(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeXHTTPTLSChild$", "-test.v", "-test.timeout=15s")
	command.WaitDelay = time.Second
	for _, entry := range os.Environ() {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if key != xhttpTLSChildSpec && !strings.HasPrefix(key, "XRAY_") && !strings.HasPrefix(key, "XRAY.") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, xhttpTLSChildSpec+"="+specPath)
	capture := new(dohOutput)
	command.Stdout, command.Stderr = capture, capture
	err = command.Run()
	output, truncated := capture.snapshot()
	marker := "XHTTP_TLS_CHILD_OK mode=" + mode
	if err != nil || truncated || bytes.Count(output, []byte(marker)) != 1 || !bytes.Contains(output, []byte("--- PASS: TestNativeXHTTPTLSChild")) {
		t.Fatalf("isolated XHTTP TLS child failed: %v; child=%s", err, output)
	}
	completed = true
}

// JSON round-trip gives the same decoded leaf types without aliasing source.
func jsonMap(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNativeXHTTPTLSChild(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("XHTTP TLS child runtime is CI-only")
	}
	data, err := os.ReadFile(os.Getenv(xhttpTLSChildSpec))
	if err != nil {
		t.Fatal(err)
	}
	var spec xhttpTLSSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Mode != "independent" && spec.Mode != "wrong_ca" && spec.Mode != "wrong_sni" || len(spec.Nonce) != 32 {
		t.Fatal("invalid XHTTP TLS child mode/nonce")
	}
	var attempts atomic.Int64
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("forbidden XHTTP TLS child OS resolution")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		if attempts.Load() != 0 {
			t.Error("XHTTP TLS child attempted OS resolution")
		}
	})
	prepared, err := os.ReadFile(spec.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatal(err)
	}
	clientCore, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := clientCore.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := clientCore.Start(); err != nil {
		t.Fatal(err)
	}
	connection, _ := connect(t, spec.Port, 1, netip.MustParseAddrPort(spec.Origin), "")
	defer connection.Close()
	if spec.Mode != "independent" {
		// Dial reaches the real child TLS client. Do not send application HTTP
		// bytes before its rejection; upload may legitimately start first.
		var reply [1]byte
		n, err := connection.Read(reply[:])
		if n != 0 || err == nil || os.IsTimeout(err) {
			t.Fatal("negative XHTTP TLS did not close without application data")
		}
		t.Logf("XHTTP_TLS_CHILD_OK mode=%s", spec.Mode)
		return
	}
	payload := append([]byte(spec.Nonce+":"), xhttpPayload()...)
	if _, err := fmt.Fprintf(connection, "POST /echo HTTP/1.1\r\nHost: payload.invalid\r\nX-Fixture-Nonce: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", spec.Nonce, len(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(connection, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal("XHTTP TLS response failed", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(payload)+1)))
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatal("XHTTP TLS payload changed", err)
	}
	t.Logf("XHTTP_TLS_CHILD_OK mode=%s", spec.Mode)
}
