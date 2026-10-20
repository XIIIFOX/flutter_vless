package native_dns_preservation_test

// The JVM exports actual Android producers; only this separately authorized
// Linux CI test starts ordinary pinned Core and owned IPv4 loopback sockets.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

type androidChainMetadata struct {
	Version             int    `json:"version"`
	ConfigSHA256        string `json:"configSHA256"`
	SourceSHA256        string `json:"sourceSHA256"`
	PreparedSHA256      string `json:"preparedSHA256"`
	PrivatePort         int    `json:"privatePort"`
	OuterPort           int    `json:"outerPort"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	ManagedInboundTag   string `json:"managedInboundTag"`
	ExpectedLogicalHost string `json:"expectedLogicalHost"`
	ExpectedLogicalPort int    `json:"expectedLogicalPort"`
	ExpectedTargetHost  string `json:"expectedTargetHost"`
	ExpectedTargetPort  int    `json:"expectedTargetPort"`
}

func androidChainPrivateFile(t *testing.T, path string, limit int64) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > limit {
		t.Fatal("Android export must be a bounded fresh private regular file", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func androidChainExport(t *testing.T, root, evidence string, outerPort, privatePort int) string {
	t.Helper()
	directory := filepath.Join(evidence, "export-pair")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal("Android export directory must be fresh", err)
	}
	for _, name := range []string{"config.json", "metadata.json"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("Android export file already exists", err)
		}
	}
	python := os.Getenv("ANDROID_LOGICAL_CHAIN_PYTHON")
	if !filepath.IsAbs(root) || !filepath.IsAbs(evidence) || !filepath.IsAbs(python) {
		t.Fatal("CI runner must supply absolute owned paths")
	}
	log, err := os.OpenFile(filepath.Join(evidence, "gradle-export.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	signals, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signals, 150*time.Second)
	defer cancel()
	command := exec.Command(python, filepath.Join(root, "tool", "with_android_local_runtime.py"),
		":flutter_vless_android:testDebugUnitTest", "--tests",
		"com.github.tfox.flutter_vless.xray.core.AndroidLogicalChainExportTest.exportExactPreparedLogicalChainRuntime",
		"--rerun-tasks", "--no-daemon", "--max-workers=2", "-Pkotlin.compiler.execution.strategy=in-process", "--stacktrace")
	command.Dir = root
	command.Env = append(os.Environ(), "FLVLESS_EXPORT_LOGICAL_CHAIN_DIR="+directory,
		fmt.Sprintf("FLVLESS_CHAIN_OUTER_PORT=%d", outerPort), fmt.Sprintf("FLVLESS_CHAIN_PRIVATE_PORT=%d", privatePort))
	command.Stdout, command.Stderr = log, log
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal("Android export did not start", err)
	}
	waited := false
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	// SIGINT lets the existing Python finally restore verification metadata.
	// The owned process group also contains Gradle's --no-daemon JVM children.
	stop := func() {
		if waited {
			return
		}
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGINT)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		waited = true
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	defer stop()
	select {
	case err := <-done:
		waited = true
		// A completed wrapper must not leave a single-use Gradle child behind.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err != nil {
			t.Fatal("selected Android export failed; see bounded owned Gradle log", err)
		}
	case <-ctx.Done():
		t.Fatal("selected Android export interrupted or exceeded its deadline")
	}
	return directory
}

func androidChainReadConnect(connection net.Conn, host string, port int) error {
	var greeting [3]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
		return errors.New("nested SOCKS no-auth greeting changed")
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return err
	}
	wanted := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	wanted = binary.BigEndian.AppendUint16(wanted, uint16(port))
	actual := make([]byte, len(wanted))
	if _, err := io.ReadFull(connection, actual); err != nil || !bytes.Equal(actual, wanted) {
		return errors.New("nested SOCKS destination was not the exact logical ATYP3 host and port")
	}
	_, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	return err
}

func TestAndroidLogicalChainRuntime(t *testing.T) {
	if runtime.GOOS != "linux" || !strings.EqualFold(os.Getenv("CI"), "true") || !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("Android native-output runtime requires Linux GitHub CI")
	}
	observed := new(fixture)
	var active, connections, logical, target, echoes, systemAttempts atomic.Int64
	complete := false
	t.Cleanup(func() {
		_, failures := observed.snapshot()
		if complete && (connections.Load() != 1 || logical.Load() != 1 || target.Load() != 1 || echoes.Load() != 1 || active.Load() != 0 || systemAttempts.Load() != 0 || len(failures) != 0) {
			t.Error("Android logical chain counters/drain changed", connections.Load(), logical.Load(), target.Load(), echoes.Load(), active.Load(), systemAttempts.Load(), failures)
		}
		if complete && !t.Failed() {
			t.Log("ANDROID_LOGICAL_CHAIN_RUNTIME_PASS=1")
		}
	})
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	outer := networkListener(t, "tcp4", "127.0.0.1:0", func(connection net.Conn) {
		connections.Add(1)
		active.Add(1)
		defer active.Add(-1)
		if err := androidChainReadConnect(connection, "inside-only.invalid", 1080); err != nil {
			observed.fail(err)
			return
		}
		logical.Add(1)
		if err := androidChainReadConnect(connection, "nonce.invalid", 18083); err != nil {
			observed.fail(err)
			return
		}
		target.Add(1)
		packet := make([]byte, len(nonce))
		if _, err := io.ReadFull(connection, packet); err != nil || !bytes.Equal(packet, nonce[:]) {
			observed.fail(errors.New("nested SOCKS nonce payload changed"))
			return
		}
		if _, err := connection.Write(packet); err != nil {
			observed.fail(err)
			return
		}
		echoes.Add(1)
		var extra [1]byte
		n, err := connection.Read(extra[:])
		if !fakeDNSControlReadClosed(n, err, runtime.GOOS) {
			observed.fail(errors.New("logical-chain carrier did not close explicitly"))
		}
	})
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	privatePort := reservation.Addr().(*net.TCPAddr).Port
	outerPort := outer.Addr().(*net.TCPAddr).Port
	directory := androidChainExport(t, os.Getenv("ANDROID_LOGICAL_CHAIN_REPO"), os.Getenv("ANDROID_LOGICAL_CHAIN_EVIDENCE"), outerPort, privatePort)
	prepared := androidChainPrivateFile(t, filepath.Join(directory, "config.json"), 1<<20)
	var metadata androidChainMetadata
	if err := json.Unmarshal(androidChainPrivateFile(t, filepath.Join(directory, "metadata.json"), 16384), &metadata); err != nil {
		t.Fatal(err)
	}
	configHash := fmt.Sprintf("%x", sha256.Sum256(prepared))
	for _, value := range []string{metadata.ConfigSHA256, metadata.SourceSHA256, metadata.PreparedSHA256} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			t.Fatal("Android source/output hash is not a SHA256")
		}
	}
	if metadata.Version != 1 || metadata.ConfigSHA256 != configHash || metadata.PrivatePort != privatePort || metadata.OuterPort != outerPort ||
		metadata.Username != "android-chain" || metadata.Password != "synthetic-chain-token" || metadata.ManagedInboundTag == "" ||
		metadata.ExpectedLogicalHost != "inside-only.invalid" || metadata.ExpectedLogicalPort != 1080 || metadata.ExpectedTargetHost != "nonce.invalid" || metadata.ExpectedTargetPort != 18083 {
		t.Fatal("Android fresh native-output metadata binding changed")
	}
	var document map[string]any
	if err := json.Unmarshal(prepared, &document); err != nil {
		t.Fatal(err)
	}
	for _, raw := range document["outbounds"].([]any) {
		handler := raw.(map[string]any)
		if handler["tag"] == "proxy" {
			if handler["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["domainStrategy"] != "AsIs" ||
				handler["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["address"] != "inside-only.invalid" {
				t.Fatal("native logical endpoint was physically resolved or changed before Core")
			}
		}
	}
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden Android logical-chain OS DNS lookup")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	// This selected test runs alone in its child process. Retain both traps
	// through all cleanup and process exit, including detached late Core work.
	built, err := schemaFieldsBuild(prepared)
	if err != nil {
		t.Fatal("exact Android native-output bytes failed ordinary pinned Core Build", err)
	}
	engine, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		observed.fail(engine.Close())
		deadline := time.Now().Add(3 * time.Second)
		for active.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if active.Load() != 0 {
			t.Error("Android logical-chain carrier did not drain after Core.Close")
		}
	})
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", privatePort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := connection.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil || reply != [2]byte{5, 2} {
		t.Fatal("Android private listener did not require password authentication", err)
	}
	authentication := append([]byte{1, byte(len(metadata.Username))}, metadata.Username...)
	authentication = append(authentication, byte(len(metadata.Password)))
	authentication = append(authentication, metadata.Password...)
	if _, err := connection.Write(authentication); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(connection, reply[:]); err != nil || reply != [2]byte{1, 0} {
		t.Fatal("Android synthetic session authentication failed", err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(metadata.ExpectedTargetHost))}, metadata.ExpectedTargetHost...)
	request = binary.BigEndian.AppendUint16(request, uint16(metadata.ExpectedTargetPort))
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	var response [10]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil || !bytes.Equal(response[:4], []byte{5, 0, 0, 1}) {
		t.Fatal("Android managed SOCKS CONNECT failed", err)
	}
	if _, err := connection.Write(nonce[:]); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(nonce))
	if _, err := io.ReadFull(connection, got); err != nil || !bytes.Equal(got, nonce[:]) {
		t.Fatal("actual Android prepared chained SOCKS payload failed", err)
	}
	if retained := androidChainPrivateFile(t, filepath.Join(directory, "config.json"), 1<<20); !bytes.Equal(retained, prepared) {
		t.Fatal("runtime retargeted native output JSON")
	}
	t.Log("ANDROID_LOGICAL_CHAIN_EXPORT_CONFIG_SHA256=" + configHash)
	complete = true
}
