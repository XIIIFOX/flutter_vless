package native_dns_preservation_test

// CI-only observation of real H3 certificate rejection and Core.Close. Socket
// type/ownership is unchanged, and all drain assertions precede rescue/exit.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
)

const h3LifetimeModeEnv = "FLUTTER_VLESS_H3_LIFETIME_MODE"
const h3LifetimeCertificateMessage = "tls: failed to verify certificate: x509: certificate signed by unknown authority"

// The pinned default client reports this refusal as INTERNAL_ERROR. Require
// its exact peer certificate reason; an unrelated internal error is no proof.
func h3LifetimeCertificateRejection(err error) bool {
	var peer *quic.TransportError
	return errors.As(err, &peer) && peer.Remote && peer.ErrorCode == quic.InternalError && peer.ErrorMessage == h3LifetimeCertificateMessage
}

type h3LifetimeWorkers struct{ Listen, Send int }

type h3LifetimeCause struct {
	Type, Text                     string
	Transport, Application, Remote bool
	Code                           uint64
	Cancelled, Deadline            bool
}

func h3LifetimeCauseOf(err error) h3LifetimeCause {
	text := fmt.Sprint(err)
	if len(text) > 256 {
		text = text[:256]
	}
	result := h3LifetimeCause{Type: fmt.Sprintf("%T", err), Text: text,
		Cancelled: errors.Is(err, context.Canceled), Deadline: errors.Is(err, context.DeadlineExceeded)}
	var transportError *quic.TransportError
	var applicationError *quic.ApplicationError
	if errors.As(err, &transportError) {
		result.Transport, result.Remote, result.Code = true, transportError.Remote, uint64(transportError.ErrorCode)
	} else if errors.As(err, &applicationError) {
		result.Application, result.Remote, result.Code = true, applicationError.Remote, uint64(applicationError.ErrorCode)
	}
	return result
}

// Only this isolated synthetic fixture installs the bounded observer. Config
// bytes, default QUIC policy and the accepted certificate predicate are unchanged.
type h3LifetimeDiagnostic struct {
	mu           sync.Mutex
	causes       []h3LifetimeCause
	coreMessages []string
}

func (*h3LifetimeDiagnostic) Severity() xlog.Severity { return xlog.Severity_Info }
func (d *h3LifetimeDiagnostic) Handle(message xlog.Message) {
	general, ok := message.(*xlog.GeneralMessage)
	if !ok || general.Severity > xlog.Severity_Info {
		return
	}
	text := message.String()
	if len(text) > 256 {
		text = text[:256]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.coreMessages) < 16 {
		d.coreMessages = append(d.coreMessages, text)
	} else {
		// Keep the final transport error if routine setup messages fill the cap.
		copy(d.coreMessages, d.coreMessages[1:])
		d.coreMessages[len(d.coreMessages)-1] = text
	}
}
func (d *h3LifetimeDiagnostic) recordCause(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.causes) < 16 {
		d.causes = append(d.causes, h3LifetimeCauseOf(err))
	}
}
func (d *h3LifetimeDiagnostic) snapshot() ([]h3LifetimeCause, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]h3LifetimeCause(nil), d.causes...), append([]string(nil), d.coreMessages...)
}

func h3LifetimeWorkerText(stacks []byte) h3LifetimeWorkers {
	var result h3LifetimeWorkers
	for _, stack := range bytes.Split(stacks, []byte("\n\n")) {
		if bytes.Contains(stack, []byte("github.com/apernet/quic-go.(*Transport).listen(")) {
			result.Listen++
		}
		if bytes.Contains(stack, []byte("github.com/apernet/quic-go.(*Transport).runSendQueue(")) {
			result.Send++
		}
	}
	return result
}

func h3LifetimeWorkersNow() (h3LifetimeWorkers, error) {
	for size := 64 << 10; size <= 4<<20; size *= 2 {
		buffer := make([]byte, size)
		if n := runtime.Stack(buffer, true); n < len(buffer) {
			return h3LifetimeWorkerText(buffer[:n]), nil
		}
	}
	return h3LifetimeWorkers{}, errors.New("H3 worker snapshot truncated")
}

// No Read/Write/SetDeadline and no numeric FD probe: RawControl retains this
// exact UDPConn's poll descriptor and reports its own closed state.
func h3LifetimeSocketState(connection *net.UDPConn) string {
	raw, err := connection.SyscallConn()
	if errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	if err != nil {
		return "unknown"
	}
	called := false
	err = raw.Control(func(uintptr) { called = true })
	if errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	if err == nil && called {
		return "open"
	}
	return "unknown"
}

func h3LifetimeDrained(states []string, workers, baseline h3LifetimeWorkers) bool {
	if len(states) != 3 || workers != baseline {
		return false
	}
	for _, state := range states {
		if state != "closed" {
			return false
		}
	}
	return true
}

func testH3LifetimePredicates(t *testing.T) {
	base := h3LifetimeWorkers{1, 1}
	for _, tc := range []struct {
		name   string
		states []string
		worker h3LifetimeWorkers
		want   bool
	}{
		{"closed", []string{"closed", "closed", "closed"}, base, true},
		{"no-attempt", nil, base, false},
		{"missing-attempt", []string{"closed", "closed"}, base, false},
		{"open-socket", []string{"closed", "open", "closed"}, base, false},
		{"unknown-socket", []string{"closed", "unknown", "closed"}, base, false},
		{"read-worker", []string{"closed", "closed", "closed"}, h3LifetimeWorkers{2, 1}, false},
		{"send-worker", []string{"closed", "closed", "closed"}, h3LifetimeWorkers{1, 2}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if h3LifetimeDrained(tc.states, tc.worker, base) != tc.want {
				t.Fatal("H3 drain predicate changed")
			}
		})
	}
	stacks := []byte("goroutine 1 [IO wait]:\ngithub.com/apernet/quic-go.(*Transport).listen(0x1)\n\ngoroutine 2:\ngithub.com/apernet/quic-go.(*Transport).runSendQueue(0x1)\n\ngoroutine 3:\nunrelated.listen()\n")
	if h3LifetimeWorkerText(stacks) != base {
		t.Fatal("targeted worker parser changed")
	}
	for _, code := range []quic.TransportErrorCode{298, 1} {
		diagnostic := h3LifetimeCauseOf(&quic.TransportError{Remote: true, ErrorCode: code})
		if !diagnostic.Transport || !diagnostic.Remote || diagnostic.Code != uint64(code) {
			t.Fatal("typed cause diagnostic lost exact code")
		}
	}
	if diagnostic := h3LifetimeCauseOf(errors.New(strings.Repeat("x", 512))); len(diagnostic.Text) != 256 || diagnostic.Transport {
		t.Fatal("generic cause diagnostic is not bounded")
	}
	for _, tc := range []struct {
		name  string
		cause error
		want  bool
	}{
		{"pinned-peer", &quic.TransportError{Remote: true, ErrorCode: quic.InternalError, ErrorMessage: h3LifetimeCertificateMessage}, true},
		{"wrapped-peer", fmt.Errorf("owned peer: %w", &quic.TransportError{Remote: true, ErrorCode: quic.InternalError, ErrorMessage: h3LifetimeCertificateMessage}), true},
		{"generic-internal", &quic.TransportError{Remote: true, ErrorCode: quic.InternalError, ErrorMessage: "unrelated failure"}, false},
		{"local", &quic.TransportError{ErrorCode: quic.InternalError, ErrorMessage: h3LifetimeCertificateMessage}, false},
		{"wrong-code", &quic.TransportError{Remote: true, ErrorCode: 298, ErrorMessage: h3LifetimeCertificateMessage}, false},
		{"wrong-reason", &quic.TransportError{Remote: true, ErrorCode: quic.InternalError, ErrorMessage: h3LifetimeCertificateMessage + " unrelated suffix"}, false},
		{"application", &quic.ApplicationError{Remote: true, ErrorCode: 1, ErrorMessage: h3LifetimeCertificateMessage}, false},
		{"absent", nil, false},
	} {
		t.Run("certificate-cause-"+tc.name, func(t *testing.T) {
			if h3LifetimeCertificateRejection(tc.cause) != tc.want {
				t.Fatal("exact peer certificate cause classification changed")
			}
		})
	}
}

func h3LifetimeAuthorized(t *testing.T) {
	t.Helper()
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("H3 lifetime runtime is CI-only")
	}
}

func TestNativeXHTTPH3Lifetime(t *testing.T) {
	h3LifetimeAuthorized(t)
	if os.Getenv("NATIVE_DNS_PREPARER") == "" {
		t.Fatal("production native preparer required")
	}
	if !t.Run("predicates", testH3LifetimePredicates) {
		return
	}
	cases := []struct{ mode, preparer string }{{"raw_numeric", os.Getenv("NATIVE_DNS_PREPARER")}, {"native_cnc_windows", os.Getenv("NATIVE_DNS_PREPARER")}}
	if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
		cases = append(cases, struct{ mode, preparer string }{"native_cnc_apple", apple})
	}
	for _, tc := range cases {
		if t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeXHTTPH3LifetimeChild$", "-test.v", "-test.timeout=35s")
			command.WaitDelay = time.Second
			for _, entry := range os.Environ() {
				key := strings.SplitN(entry, "=", 2)[0]
				upper := strings.ToUpper(key)
				if key != h3LifetimeModeEnv && key != "NATIVE_DNS_PREPARER" && !strings.HasPrefix(upper, "XRAY_") && !strings.HasPrefix(upper, "V2RAY_") && !strings.HasPrefix(upper, "XRAY.") && !strings.HasPrefix(upper, "V2RAY.") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, h3LifetimeModeEnv+"="+tc.mode, "NATIVE_DNS_PREPARER="+tc.preparer)
			capture := new(dohOutput)
			command.Stdout, command.Stderr = capture, capture
			err := command.Run()
			output, truncated := capture.snapshot()
			t.Logf("H3 lifetime child evidence mode=%s\n%s", tc.mode, output)
			marker := "H3_LIFETIME_CHILD_OK mode=" + tc.mode
			if err != nil || truncated || bytes.Count(output, []byte(marker)) != 1 || !bytes.Contains(output, []byte("--- PASS: TestNativeXHTTPH3LifetimeChild")) {
				t.Errorf("H3 lifetime child did not qualify mode=%s exit=%v truncated=%v", tc.mode, err, truncated)
			}
		}) {
			// Child marker follows its assertions; command completion includes all
			// cleanup. Child exit alone is never the drain predicate.
			t.Logf("H3_LIFETIME_PASS mode=%s", tc.mode)
		}
	}
}

type h3LifetimeDialer struct {
	base internet.DefaultSystemDialer
	port xnet.Port
	mu   sync.Mutex
	udp  []*net.UDPConn
	err  error
}

func (d *h3LifetimeDialer) DestIpAddress() xnet.IP { return d.base.DestIpAddress() }

func (d *h3LifetimeDialer) Dial(ctx context.Context, src xnet.Address, destination xnet.Destination, options *internet.SocketConfig) (xnet.Conn, error) {
	connection, err := d.base.Dial(ctx, src, destination, options)
	if err != nil || destination.Network != xnet.Network_UDP {
		return connection, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	wrapper, ok := connection.(*xnet.PacketConnWrapper)
	if destination.Port != d.port || destination.Address.String() != "127.0.0.1" || !ok {
		d.err = errors.New("unexpected H3 physical UDP destination/type")
		_ = connection.Close()
		return nil, d.err
	}
	actual, ok := wrapper.PacketConn.(*net.UDPConn)
	if !ok {
		d.err = errors.New("H3 tracker requires actual UDPConn")
		_ = connection.Close()
		return nil, d.err
	}
	d.udp = append(d.udp, actual)
	return connection, nil // the original object and underlying type, unchanged
}

func (d *h3LifetimeDialer) snapshot() ([]*net.UDPConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*net.UDPConn(nil), d.udp...), d.err
}

func h3LifetimeWait(timeout time.Duration, predicate func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if predicate() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNativeXHTTPH3LifetimeChild(t *testing.T) {
	h3LifetimeAuthorized(t)
	mode := os.Getenv(h3LifetimeModeEnv)
	if mode != "raw_numeric" && mode != "native_cnc_windows" && mode != "native_cnc_apple" {
		t.Fatal("H3_SETUP invalid child mode")
	}
	var lookups atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("forbidden H3 lifetime OS resolution")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	defer func() { net.DefaultResolver, xnet.DefaultResolver = previous, previousCore }()
	material := makeXHTTPTLSMaterial(t)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal("H3_SETUP nonce", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	packet, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("H3_SETUP UDP listener", err)
	}
	port := packet.LocalAddr().(*net.UDPAddr).Port
	var contexts, rejected, setupHTTP, badHTTP, badCause atomic.Int64
	var negative atomic.Bool
	diagnostic := new(h3LifetimeDiagnostic)
	serverTransport := &quic.Transport{Conn: packet, ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
		contexts.Add(1)
		context.AfterFunc(ctx, func() {
			defer contexts.Add(-1)
			diagnostic.recordCause(context.Cause(ctx))
			if h3LifetimeCertificateRejection(context.Cause(ctx)) {
				rejected.Add(1)
			} else if negative.Load() {
				badCause.Add(1)
			}
		})
		return ctx, nil
	}}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{material.download}, MinVersion: tls.VersionTLS13}
	listener, err := serverTransport.ListenEarly(http3.ConfigureTLSConfig(serverTLS), &quic.Config{Allow0RTT: false})
	if err != nil {
		_ = packet.Close()
		t.Fatal("H3_SETUP QUIC listener", err)
	}
	server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.TLS == nil || r.TLS.NegotiatedProtocol != "h3" || r.TLS.ServerName != "download-tls.invalid" || r.URL.Path != "/setup/"+nonce {
			badHTTP.Add(1)
			http.Error(w, "unexpected fixture request", http.StatusBadRequest)
			return
		}
		setupHTTP.Add(1)
		_, _ = io.WriteString(w, nonce)
	})}
	served := make(chan error, 1)
	go func() { served <- server.ServeListener(listener) }()
	// Always close the supplied listener/PacketConn too; ServeListener does not
	// transfer their ownership to the HTTP3 server.
	defer func() {
		_ = listener.Close()
		_ = packet.Close()
		_ = serverTransport.Close()
		closed := make(chan error, 1)
		go func() { closed <- server.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Error("H3_CLEANUP server close", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("H3_CLEANUP server close did not join")
		}
		select {
		case err := <-served:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Error("H3_CLEANUP unexpected server result", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("H3_CLEANUP server did not join")
		}
		if !h3LifetimeWait(time.Second, func() bool { return contexts.Load() == 0 }) {
			t.Error("H3_CLEANUP context observers did not join")
		}
	}()
	// Real success control, independent of the negative Core ownership result.
	positive := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: xhttpTLSRootPool(t, material.ca), ServerName: "download-tls.invalid"}}
	positiveClient := &http.Client{Transport: positive, Timeout: 3 * time.Second}
	response, err := positiveClient.Get(fmt.Sprintf("https://127.0.0.1:%d/setup/%s", port, nonce))
	if err != nil {
		_ = positive.Close()
		t.Fatal("H3_SETUP real nonce handshake", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 33))
	_ = response.Body.Close()
	if err := positive.Close(); err != nil {
		t.Fatal("H3_SETUP nonce transport close", err)
	}
	if readErr != nil || response.StatusCode != http.StatusOK || string(body) != nonce || setupHTTP.Load() != 1 || badHTTP.Load() != 0 || !h3LifetimeWait(time.Second, func() bool { return contexts.Load() == 0 }) {
		t.Fatal("H3_SETUP real H3 nonce/control cleanup failed")
	}
	classifier, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("H3_SETUP classifier", err)
	}
	openState := h3LifetimeSocketState(classifier)
	_ = classifier.Close()
	if openState != "open" || h3LifetimeSocketState(classifier) != "closed" {
		t.Fatal("H3_SETUP passive close classifier failed")
	}
	var baseline h3LifetimeWorkers
	if !h3LifetimeWait(time.Second, func() bool {
		var err error
		baseline, err = h3LifetimeWorkersNow()
		return err == nil && baseline == (h3LifetimeWorkers{1, 1})
	}) {
		t.Fatal("H3_SETUP server worker baseline unavailable")
	}
	negative.Store(true)

	caPath := filepath.Join(t.TempDir(), "foreign-ca.pem")
	if err := os.WriteFile(caPath, material.foreign, 0600); err != nil {
		t.Fatal("H3_SETUP CA file", err)
	}
	// Bind the same foreign root to the real server certificate: exact expected
	// x509 cause complements the exact remote QUIC certificate reason, not EOF.
	leaf, err := x509.ParseCertificate(material.download.Certificate[0])
	if err != nil {
		t.Fatal("H3_SETUP leaf parse", err)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: xhttpTLSRootPool(t, material.foreign), DNSName: "download-tls.invalid"})
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(verifyErr, &unknownAuthority) || "tls: failed to verify certificate: "+verifyErr.Error() != h3LifetimeCertificateMessage {
		t.Fatal("H3_SETUP wrong-CA cause unavailable")
	}
	host := "127.0.0.1"
	if mode != "raw_numeric" {
		host = "endpoint.invalid"
	}
	tlsSettings := map[string]any{"serverName": "download-tls.invalid", "alpn": []string{"h3"}, "disableSystemRoot": true, "masterKeyLog": "", "certificates": []any{map[string]any{"usage": "verify", "certificateFile": caPath}}}
	source := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"address": host, "port": port, "id": "11111111-1111-4111-8111-111111111111", "encryption": "none"}, "streamSettings": map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": tlsSettings, "xhttpSettings": map[string]any{"host": "download.invalid", "path": "/negative/" + nonce, "mode": "stream-one"}}}}, "dns": map[string]any{"queryStrategy": "UseIPv4", "servers": []string{"tcp://9.9.9.9"}}}
	sourceBefore, _ := json.Marshal(source)
	var prepared []byte
	var privatePort int
	if mode == "raw_numeric" {
		reserved, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal("H3_SETUP SOCKS reservation", e)
		}
		privatePort = reserved.Addr().(*net.TCPAddr).Port
		_ = reserved.Close()
		source["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": privatePort, "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "session-user", "pass": "session-password"}}}}}
		prepared, err = json.Marshal(source)
	} else {
		prepared, privatePort = prepare(t, source)
		after, _ := json.Marshal(source)
		if !bytes.Equal(sourceBefore, after) {
			t.Fatal("H3_SETUP native source mutation")
		}
		var effective map[string]any
		if err = json.Unmarshal(prepared, &effective); err != nil {
			t.Fatal("H3_SETUP native JSON", err)
		}
		outbounds := effective["outbounds"].([]any)
		stream := outbounds[0].(map[string]any)["streamSettings"].(map[string]any)
		if !reflect.DeepEqual(jsonMap(t, tlsSettings), stream["tlsSettings"]) {
			t.Fatal("H3_SETUP native TLS changed")
		}
		options := stream["sockopt"].(map[string]any)
		tag, _ := options["dialerProxy"].(string)
		loop := false
		for _, entry := range outbounds {
			o := entry.(map[string]any)
			if o["tag"] == tag && o["protocol"] == "loopback" {
				loop = true
			}
		}
		if tag == "" || !loop || options["domainStrategy"] != "AsIs" {
			t.Fatal("H3_SETUP actual native cnc pin graph missing")
		}
	}
	if err != nil {
		t.Fatal("H3_SETUP config", err)
	}
	configuration, err := serial.DecodeJSONConfig(bytes.NewReader(prepared))
	if err != nil {
		t.Fatal("H3_SETUP decode", err)
	}
	built, err := configuration.Build()
	if err != nil {
		t.Fatal("H3_SETUP build", err)
	}
	clientCore, err := core.New(built)
	if err != nil {
		t.Fatal("H3_SETUP Core", err)
	}
	tracker := &h3LifetimeDialer{port: xnet.Port(port)}
	internet.UseAlternativeSystemDialer(tracker)
	closeDone := make(chan error, 1)
	var closeOnce sync.Once
	startClose := func() { closeOnce.Do(func() { go func() { closeDone <- clientCore.Close(); close(closeDone) }() }) }
	// Rescue is intentionally registered now but runs AFTER ownership evidence.
	defer func() {
		connections, _ := tracker.snapshot()
		for _, c := range connections {
			_ = c.Close()
		}
		startClose()
		select {
		case err := <-closeDone:
			if err != nil {
				t.Error("H3_CLEANUP Core.Close", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("H3_CLEANUP Core.Close did not join")
		}
		if !h3LifetimeWait(2*time.Second, func() bool { w, e := h3LifetimeWorkersNow(); return e == nil && w == baseline }) {
			t.Error("H3_CLEANUP rescued client transport workers did not drain")
		}
		internet.UseAlternativeSystemDialer(nil)
	}()
	if err := clientCore.Start(); err != nil {
		t.Fatal("H3_SETUP start", err)
	}
	xlog.RegisterHandler(diagnostic)
	t.Logf("H3_LIFETIME_SOURCE mode=%s config_sha256=%x baseline_listen=%d baseline_send=%d", mode, sha256.Sum256(prepared), baseline.Listen, baseline.Send)
	for attempt := 1; attempt <= 3; attempt++ {
		connection, _ := connect(t, privatePort, 1, netip.MustParseAddrPort("192.0.2.7:18083"), "")
		var one [1]byte
		n, readErr := connection.Read(one[:])
		_ = connection.Close()
		if n != 0 || readErr == nil || os.IsTimeout(readErr) {
			t.Fatal("H3_SETUP certificate rejection did not close input")
		}
		if !h3LifetimeWait(time.Second, func() bool { return rejected.Load() == int64(attempt) && contexts.Load() == 0 }) {
			connections, trackerError := tracker.snapshot()
			states := make([]string, 0, len(connections))
			for _, connection := range connections {
				states = append(states, h3LifetimeSocketState(connection))
			}
			workers, workerError := h3LifetimeWorkersNow()
			causes, messages := diagnostic.snapshot()
			evidence, _ := json.Marshal(struct {
				Causes       []h3LifetimeCause
				CoreMessages []string
			}{causes, messages})
			t.Logf("H3_SETUP_DIAGNOSTIC mode=%s attempt=%d before_core_close=true contexts=%d rejected=%d bad_cause=%d setup_http=%d bad_http=%d sockets=%d socket_states=%v tracker_error=%v listen=%d send=%d worker_error=%v evidence=%s", mode, attempt, contexts.Load(), rejected.Load(), badCause.Load(), setupHTTP.Load(), badHTTP.Load(), len(connections), states, trackerError, workers.Listen, workers.Send, workerError, evidence)
			t.Fatal("H3_SETUP exact remote certificate rejection missing")
		}
		connections, err := tracker.snapshot()
		if err != nil || len(connections) != attempt || badHTTP.Load() != 0 || setupHTTP.Load() != 1 || badCause.Load() != 0 {
			t.Fatal("H3_SETUP unexpected physical socket/handshake/HTTP count", err)
		}
		t.Logf("H3_LIFETIME_REJECTION mode=%s attempt=%d peer_transport_code=1 cause=unknown_authority sockets=%d", mode, attempt, len(connections))
	}
	startClose()
	coreClosed := false
	select {
	case err := <-closeDone:
		coreClosed = err == nil
		if err != nil {
			t.Error("H3_LIFETIME Core.Close error", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("H3_LIFETIME Core.Close did not return")
	}
	var states []string
	var workers h3LifetimeWorkers
	var observationErr error
	drained := h3LifetimeWait(3*time.Second, func() bool {
		connections, err := tracker.snapshot()
		if err != nil {
			observationErr = err
			return false
		}
		states = nil
		for _, c := range connections {
			states = append(states, h3LifetimeSocketState(c))
		}
		workers, observationErr = h3LifetimeWorkersNow()
		return observationErr == nil && h3LifetimeDrained(states, workers, baseline)
	})
	// This is the causal assertion boundary. Server, UDP connections and process
	// are still alive; no rescue deadline/close has been applied to client sockets.
	t.Logf("H3_LIFETIME_OBSERVED mode=%s repetitions=3 core_closed=%v socket_states=%v listen=%d send=%d baseline_listen=%d baseline_send=%d typed_rejections=%d server_http=%d os_lookups=%d", mode, coreClosed, states, workers.Listen, workers.Send, baseline.Listen, baseline.Send, rejected.Load(), badHTTP.Load(), lookups.Load())
	if !drained || !coreClosed || observationErr != nil || lookups.Load() != 0 {
		t.Errorf("H3_LIFETIME_RESOURCE_RETAINED mode=%s observation_error=%v", mode, observationErr)
	}
	if !t.Failed() {
		t.Logf("H3_LIFETIME_CHILD_OK mode=%s", mode)
	}
}
