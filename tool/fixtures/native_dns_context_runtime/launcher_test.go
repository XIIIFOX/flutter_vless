package native_dns_context_runtime_test

// The separate native launcher is exercised only by the remote runtime job.
// It receives trusted side policy, keeps caller DNS, serves authenticated SOCKS
// bytes, and must close its own DNS socket before reporting a clean stop.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	featuredns "github.com/xtls/xray-core/features/dns"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const nativeLauncherCapability = "native-instance-preview-1"

type launcherResponse struct {
	Schema                 int    `json:"schema"`
	Capability             string `json:"capability"`
	CoreCommit             string `json:"core_commit"`
	Status                 string `json:"status"`
	Stage                  string `json:"stage"`
	SourceDigest           string `json:"source_digest"`
	PolicyEpoch            string `json:"policy_epoch"`
	HostQualified          bool   `json:"host_qualified"`
	SystemResolverAttempts int64  `json:"system_resolver_attempts"`
}

func requireLauncherResponse(t *testing.T, result launcherResponse, status string) {
	t.Helper()
	if result.Status != status || result.Schema != 1 || result.Capability != nativeLauncherCapability ||
		result.CoreCommit != "92ccc939aaf4f8965f369cf0b142e005aeaa11d5" || result.HostQualified || result.SystemResolverAttempts != 0 {
		t.Fatal("native child did not report the exact unqualified capability/status")
	}
}

func launcherArguments(command, path, resolver string) []string {
	return []string{command, "--config", path, "--resolver", resolver, "--egress-index", "1", "--capability", nativeLauncherCapability, "--timeout-ms", "4000"}
}

func decodeLauncherResponse(data []byte, result *launcherResponse) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(result) != nil {
		return errors.New("unexpected child response schema")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("unexpected child trailing output")
	}
	return nil
}

func launcherOnce(t *testing.T, binary string, args []string, expected string) launcherResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	var output, stderr bytes.Buffer
	command.Stdout, command.Stderr = &output, &stderr
	err := command.Run()
	if expected == "failed" && err == nil || expected != "failed" && err != nil || ctx.Err() != nil {
		t.Fatal("unexpected native preparation child exit")
	}
	var result launcherResponse
	if decodeLauncherResponse(output.Bytes(), &result) != nil || stderr.Len() != 0 {
		t.Fatal("native child exposed unstructured output")
	}
	requireLauncherResponse(t, result, expected)
	return result
}

type launcherChild struct {
	command       *exec.Cmd
	input         io.WriteCloser
	read          *os.File
	events        <-chan launcherResponse
	readEnded     <-chan error
	ended         <-chan error
	cancel        context.CancelFunc
	stderr        *bytes.Buffer
	stopped       bool
	reaped        bool
	readerDrained bool
	digest        string
	epoch         string
}

func startLauncherChild(t *testing.T, binary, path, resolver, digest string) *launcherChild {
	return startLauncherCommand(t, binary, launcherArguments("run", path, resolver), digest, "")
}

func startLauncherCommand(t *testing.T, binary string, arguments []string, digest, epoch string) *launcherChild {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	command := exec.CommandContext(ctx, binary, arguments...)
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		cancel()
		input.Close()
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	command.Stdout, command.Stderr = write, stderr
	if err := command.Start(); err != nil {
		cancel()
		input.Close()
		read.Close()
		write.Close()
		t.Fatal("native child start", err)
	}
	_ = write.Close()
	events, readEnded, ended := make(chan launcherResponse, 8), make(chan error, 1), make(chan error, 1)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(read)
		scanner.Buffer(make([]byte, 4096), 32768)
		for scanner.Scan() {
			var result launcherResponse
			if decodeLauncherResponse(scanner.Bytes(), &result) != nil {
				readEnded <- errors.New("unstructured child output")
				return
			}
			select {
			case events <- result:
			default:
				readEnded <- errors.New("excess child output")
				return
			}
		}
		readEnded <- scanner.Err()
	}()
	go func() { ended <- command.Wait() }()
	child := &launcherChild{command: command, input: input, read: read, events: events, readEnded: readEnded, ended: ended, cancel: cancel, stderr: stderr, digest: digest, epoch: epoch}
	t.Cleanup(func() {
		if !child.stopped {
			cancel()
			if !child.reaped {
				select {
				case <-ended:
					child.reaped = true
				case <-time.After(5 * time.Second):
					t.Error("owned native child not reaped")
				}
			}
			_ = input.Close()
			_ = read.Close()
			if !child.readerDrained {
				select {
				case <-readEnded:
					child.readerDrained = true
				case <-time.After(2 * time.Second):
					t.Error("owned native child reader survived cleanup")
				}
			}
		}
		cancel()
	})
	result := child.next(t)
	requireLauncherResponse(t, result, "started")
	if result.SourceDigest != digest || result.PolicyEpoch != epoch {
		t.Fatal("prepared child source/session binding changed")
	}
	return child
}

func (child *launcherChild) next(t *testing.T) launcherResponse {
	return child.nextBefore(t, time.Now().Add(6*time.Second))
}

func (child *launcherChild) nextBefore(t *testing.T, deadline time.Time) launcherResponse {
	t.Helper()
	select {
	case result, ok := <-child.events:
		if !ok {
			t.Fatal("native child ended before protocol response")
		}
		return result
	case <-time.After(time.Until(deadline)):
		t.Fatal("native child protocol deadline")
	}
	return launcherResponse{}
}

func (child *launcherChild) stop(t *testing.T) {
	child.stopBefore(t, time.Now().Add(6*time.Second))
}

func (child *launcherChild) stopBefore(t *testing.T, deadline time.Time) {
	t.Helper()
	if _, err := io.WriteString(child.input, "stop\n"); err != nil {
		t.Fatal("native child control write")
	}
	child.awaitStop(t, deadline)
}

func (child *launcherChild) awaitStop(t *testing.T, deadline time.Time) {
	t.Helper()
	result := child.nextBefore(t, deadline)
	requireLauncherResponse(t, result, "stopped")
	if result.SourceDigest != child.digest || result.PolicyEpoch != child.epoch {
		t.Fatal("stopped response belongs to another prepared source")
	}
	select {
	case err := <-child.ended:
		child.reaped = true
		if err != nil {
			t.Fatal("native child stop exit")
		}
	case <-time.After(time.Until(deadline)):
		t.Fatal("native child exit deadline")
	}
	select {
	case err := <-child.readEnded:
		child.readerDrained = true
		if err != nil {
			t.Fatal("native child incomplete output")
		}
	case <-time.After(time.Until(deadline)):
		t.Fatal("native child output did not close")
	}
	if _, ok := <-child.events; ok {
		t.Fatal("unexpected extra native child response")
	}
	if child.stderr.Len() != 0 {
		t.Fatal("native child exposed stderr")
	}
	if !time.Now().Before(deadline) {
		t.Fatal("native child stop exceeded its shared budget")
	}
	child.stopped = true
	_ = child.input.Close()
	_ = child.read.Close()
	child.cancel()
}

func launcherDocument(t *testing.T) (path string, port int, digest string, original []byte) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close() // Test allocation only; production bind races remain item 5.
	document := map[string]any{
		"log": map[string]any{"loglevel": "none", "access": "/private-canary-access", "error": "/private-canary-error"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "tag": "caller-private-inbound",
			"settings": map[string]any{"auth": "password", "udp": false, "accounts": []any{map[string]any{"user": "preview-user", "pass": "preview-password"}}}}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4"}}, map[string]any{"protocol": "freedom"}},
		"dns":       map[string]any{"queryStrategy": "UseIPv4", "hosts": map[string]any{"full:static.invalid": "127.0.0.1"}},
	}
	original, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "caller.json")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(original)
	return path, port, hex.EncodeToString(hash[:]), original
}

func launcherHTTP(port int, name string, targetPort int) (string, error) {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	readExact := func(expected []byte) error {
		data := make([]byte, len(expected))
		if _, err := io.ReadFull(conn, data); err != nil {
			return err
		}
		if !bytes.Equal(data, expected) {
			return errors.New("native SOCKS authentication failed")
		}
		return nil
	}
	if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
		return "", err
	}
	if err = readExact([]byte{5, 2}); err != nil {
		return "", err
	}
	user, password := "preview-user", "preview-password"
	auth := append([]byte{1, byte(len(user))}, []byte(user)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if _, err = conn.Write(auth); err != nil {
		return "", err
	}
	if err = readExact([]byte{1, 0}); err != nil {
		return "", err
	}
	request := append([]byte{5, 1, 0, 3, byte(len(name))}, []byte(name)...)
	request = binary.BigEndian.AppendUint16(request, uint16(targetPort))
	if _, err = conn.Write(request); err != nil {
		return "", err
	}
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	if header[0] != 5 || header[1] != 0 {
		return "", errors.New("native SOCKS request rejected")
	}
	size := 0
	switch header[3] {
	case 1:
		size = 6
	case 4:
		size = 18
	default:
		return "", errors.New("unexpected SOCKS reply family")
	}
	if _, err = io.CopyN(io.Discard, conn, int64(size)); err != nil {
		return "", err
	}
	if _, err = fmt.Fprintf(conn, "GET /native-child HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", name); err != nil {
		return "", err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil || response.StatusCode != 200 {
		return "", errors.New("native HTTP response failed")
	}
	return string(body), nil
}

func TestAcceptanceNativeDNSLauncher(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("Actual native entry is CI-only")
	}
	binary := os.Getenv("FLUTTER_VLESS_NATIVE_PREVIEW")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("exact native preview binary required")
	}
	launcherOnce(t, binary, []string{"capabilities"}, "available")
	t.Log("PHASE native launcher: closed capability, private structural preparation, no constructor DNS")
	origin := newLoopServer(t, "tcp4", "127.0.0.1:0", markerProtocol("unused", "NATIVE_CHILD_HTTP"))
	stallEntered, stallEnded := make(chan struct{}), make(chan struct{})
	dnsA := newLoopServer(t, "tcp4", "127.0.0.1:0", localDefaultDNS("127.0.0.1", stallEntered, stallEnded))
	dnsB := newLoopServer(t, "tcp4", "127.0.0.1:0", localDefaultDNS("127.0.0.1", nil, nil))
	pathA, portA, digestA, sourceA := launcherDocument(t)
	pathB, portB, digestB, sourceB := launcherDocument(t)
	prepared := launcherOnce(t, binary, launcherArguments("check", pathA, dnsA.listener.Addr().String()), "prepared")
	if prepared.SourceDigest != digestA || dnsA.activity() != 0 || dnsB.activity() != 0 {
		t.Fatal("structural native preparation had side effects")
	}
	bad := launcherArguments("check", pathA, "private-resolver.invalid:53")
	if launcherOnce(t, binary, bad, "failed").Stage != "arguments" {
		t.Fatal("named native resolver admitted")
	}
	a := startLauncherChild(t, binary, pathA, dnsA.listener.Addr().String(), digestA)
	b := startLauncherChild(t, binary, pathB, dnsB.listener.Addr().String(), digestB)
	var rejected map[string]any
	if json.Unmarshal(sourceA, &rejected) != nil {
		t.Fatal("synthetic candidate decode")
	}
	rejected["dns"].(map[string]any)["servers"] = []any{"https+local://private-canary.invalid/dns-query"}
	rejectedBytes, err := json.Marshal(rejected)
	if err != nil {
		t.Fatal(err)
	}
	rejectedPath := filepath.Join(t.TempDir(), "rejected.json")
	if os.WriteFile(rejectedPath, rejectedBytes, 0600) != nil {
		t.Fatal("synthetic candidate write")
	}
	beforeA, beforeB := dnsA.activity(), dnsB.activity()
	if launcherOnce(t, binary, launcherArguments("check", rejectedPath, dnsA.listener.Addr().String()), "failed").Stage != "prepare" ||
		dnsA.activity() != beforeA || dnsB.activity() != beforeB || origin.activity() != 0 {
		t.Fatal("rejected native preparation had runtime side effects")
	}
	targetPort := origin.listener.Addr().(*net.TCPAddr).Port
	for index, port := range []int{portA, portB} {
		beforeA, beforeB := dnsA.activity(), dnsB.activity()
		if result, err := launcherHTTP(port, "default.invalid", targetPort); err != nil || result != "NATIVE_CHILD_HTTP" {
			t.Fatal("native entry did not transfer actual caller DNS HTTP bytes", err)
		}
		if index == 0 && (dnsA.activity() != beforeA+1 || dnsB.activity() != beforeB) ||
			index == 1 && (dnsA.activity() != beforeA || dnsB.activity() != beforeB+1) {
			t.Fatal("native child used a foreign policy resolver")
		}
	}
	before := dnsA.activity()
	if result, err := launcherHTTP(portA, "static.invalid", targetPort); err != nil || result != "NATIVE_CHILD_HTTP" || dnsA.activity() != before {
		t.Fatal("native entry lost caller static-host precedence", err)
	}
	t.Log("PHASE native launcher: owner-specific policy sockets, authenticated HTTP, caller hosts preserved")
	requestEnded := make(chan error, 1)
	requestStarted := time.Now()
	stopDeadline := requestStarted.Add(2 * time.Second)
	// This source has an implicit local client (no servers). Its pinned timeout
	// is four seconds, as is the explicit native policy and socket deadline.
	// Start the budget BEFORE the SOCKS request, so the earliest natural timeout
	// is later than this entire stop/EOF/reap budget, not a sequence of waits.
	earliestQueryDeadline := requestStarted.Add(featuredns.NativeLocalResolverTimeout)
	if time.Until(earliestQueryDeadline) < 3500*time.Millisecond {
		t.Fatal("causal local timeout control changed")
	}
	go func() { _, err := launcherHTTP(portA, "stall.invalid", targetPort); requestEnded <- err }()
	select {
	case <-stallEntered:
	case <-time.After(time.Until(stopDeadline)):
		t.Fatal("native child's actual DNS socket did not stall")
	}
	a.stopBefore(t, stopDeadline)
	select {
	case <-stallEnded:
	case <-time.After(time.Until(stopDeadline)):
		t.Fatal("native child reported stop without closing its DNS socket")
	}
	select {
	case err := <-requestEnded:
		if err == nil {
			t.Fatal("closed native request returned success")
		}
	case <-time.After(time.Until(stopDeadline)):
		t.Fatal("native request survived stop")
	}
	if !time.Now().Before(stopDeadline) || time.Until(earliestQueryDeadline) < 1500*time.Millisecond {
		t.Fatal("native stop reached EOF only after its causal budget/remaining query bound")
	}
	if result, err := launcherHTTP(portB, "default.invalid", targetPort); err != nil || result != "NATIVE_CHILD_HTTP" {
		t.Fatal("stopping A affected independent B", err)
	}
	if err := b.input.Close(); err != nil {
		t.Fatal("parent EOF close")
	}
	b.awaitStop(t, time.Now().Add(6*time.Second))
	for path, expected := range map[string][]byte{pathA: sourceA, pathB: sourceB} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("native launcher changed caller source")
		}
	}
	for _, server := range []*loopServer{dnsA, dnsB, origin} {
		_, failures := server.observations()
		if len(failures) != 0 {
			t.Fatal("native fixture saw protocol errors")
		}
	}
	t.Log("PHASE native launcher: bounded native stop drained stalled socket before natural timeout, B survived, child output EOF/reap, source unchanged")
	t.Run("PrivateManagedPolicy", func(t *testing.T) { testLauncherPrivateManagedPolicy(t, binary) })
}
