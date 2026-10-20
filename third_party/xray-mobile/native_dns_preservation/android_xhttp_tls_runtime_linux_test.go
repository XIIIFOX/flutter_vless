package native_dns_preservation_test

// Actual Android producers export once before the three shared TLS fixtures
// activate sequentially. Linux-only process ownership must not enter Apple or
// Windows test compilation; this qualifies no Android device or SDK runtime.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type androidTLSEntry struct {
	Mode                       string           `json:"mode"`
	SourcePath                 string           `json:"sourcePath"`
	SourceSHA256               string           `json:"sourceSHA256"`
	OutputDirectory            string           `json:"outputDirectory"`
	PrivatePort                int              `json:"privatePort"`
	UploadPort                 int              `json:"uploadPort"`
	DownloadPort               int              `json:"downloadPort"`
	CertificateAssetsDirectory string           `json:"certificateAssetsDirectory"`
	CAFiles                    []xhttpTLSCAFile `json:"caFiles"`
}

type androidTLSBatch struct {
	Version int               `json:"version"`
	Entries []androidTLSEntry `json:"entries"`
}

type androidTLSMetadata struct {
	Version                    int              `json:"version"`
	Mode                       string           `json:"mode"`
	SourceSHA256               string           `json:"sourceSHA256"`
	PreparedSHA256             string           `json:"preparedSHA256"`
	ConfigSHA256               string           `json:"configSHA256"`
	PrivatePort                int              `json:"privatePort"`
	UploadPort                 int              `json:"uploadPort"`
	DownloadPort               int              `json:"downloadPort"`
	CertificateAssetsDirectory string           `json:"certificateAssetsDirectory"`
	CAFiles                    []xhttpTLSCAFile `json:"caFiles"`
	ManagedInboundTag          string           `json:"managedInboundTag"`
	Username                   string           `json:"username"`
	Password                   string           `json:"password"`
}

func androidTLSDigest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func androidTLSHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

// Syntax/identity checks are inert and shared by the CI fixture's controls.
func androidTLSValidateBatch(batch androidTLSBatch) error {
	if batch.Version != 1 || len(batch.Entries) != 3 {
		return errors.New("Android TLS batch version/count changed")
	}
	ports, paths := map[int]bool{}, map[string]bool{}
	for index, mode := range []string{"independent", "wrong_ca", "wrong_sni"} {
		entry := batch.Entries[index]
		if entry.Mode != mode || !androidTLSHash(entry.SourceSHA256) || len(entry.CAFiles) != 2 {
			return errors.New("Android TLS mode/source/CA count changed")
		}
		for _, path := range []string{entry.SourcePath, entry.OutputDirectory, entry.CertificateAssetsDirectory} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || paths[path] {
				return errors.New("Android TLS path is not unique absolute identity")
			}
			paths[path] = true
		}
		for _, port := range []int{entry.PrivatePort, entry.UploadPort, entry.DownloadPort} {
			if port < 1 || port > 65535 || ports[port] {
				return errors.New("Android TLS port identity is invalid or repeated")
			}
			ports[port] = true
		}
		for caIndex, name := range []string{"upload-ca.pem", "download-ca.pem"} {
			ca := entry.CAFiles[caIndex]
			if ca.Path != filepath.Join(entry.CertificateAssetsDirectory, name) || !androidTLSHash(ca.SHA256) {
				return errors.New("Android TLS CA path/hash changed")
			}
		}
	}
	return nil
}

func testAndroidTLSBatchContract(t *testing.T) {
	batch := androidTLSBatch{Version: 1}
	for index, mode := range []string{"independent", "wrong_ca", "wrong_sni"} {
		directory := filepath.Join("/owned", mode)
		batch.Entries = append(batch.Entries, androidTLSEntry{Mode: mode, SourcePath: filepath.Join(directory, "source.json"), SourceSHA256: strings.Repeat("a", 64),
			OutputDirectory: filepath.Join(directory, "export"), CertificateAssetsDirectory: filepath.Join(directory, "assets"),
			PrivatePort: 18000 + index*3, UploadPort: 18001 + index*3, DownloadPort: 18002 + index*3,
			CAFiles: []xhttpTLSCAFile{{filepath.Join(directory, "assets", "upload-ca.pem"), strings.Repeat("b", 64)}, {filepath.Join(directory, "assets", "download-ca.pem"), strings.Repeat("c", 64)}}})
	}
	if err := androidTLSValidateBatch(batch); err != nil {
		t.Fatal("valid inert Android TLS batch rejected", err)
	}
	for _, change := range []struct {
		name  string
		apply func(*androidTLSBatch)
	}{
		{"version", func(b *androidTLSBatch) { b.Version = 2 }},
		{"missing-mode", func(b *androidTLSBatch) { b.Entries = b.Entries[:2] }},
		{"mode-order", func(b *androidTLSBatch) { b.Entries[0].Mode = "wrong_ca" }},
		{"repeated-port", func(b *androidTLSBatch) { b.Entries[1].PrivatePort = b.Entries[0].PrivatePort }},
		{"repeated-output", func(b *androidTLSBatch) { b.Entries[1].OutputDirectory = b.Entries[0].OutputDirectory }},
		{"relative-source", func(b *androidTLSBatch) { b.Entries[0].SourcePath = "source.json" }},
		{"invalid-source-hash", func(b *androidTLSBatch) { b.Entries[0].SourceSHA256 = "not-sha256" }},
		{"escaped-ca", func(b *androidTLSBatch) { b.Entries[0].CAFiles[0].Path = "/outside/upload-ca.pem" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			data, _ := json.Marshal(batch)
			var bad androidTLSBatch
			if err := json.Unmarshal(data, &bad); err != nil {
				t.Fatal(err)
			}
			change.apply(&bad)
			if androidTLSValidateBatch(bad) == nil {
				t.Fatal("invalid Android TLS batch admitted")
			}
		})
	}
}

func androidTLSExport(t *testing.T, root, directory, manifest string) {
	t.Helper()
	python := os.Getenv("ANDROID_LOGICAL_CHAIN_PYTHON")
	if !filepath.IsAbs(root) || !filepath.IsAbs(directory) || !filepath.IsAbs(python) || !filepath.IsAbs(manifest) {
		t.Fatal("Android TLS runner paths must be absolute")
	}
	log, err := os.OpenFile(filepath.Join(directory, "gradle-export.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
		"com.github.tfox.flutter_vless.xray.core.AndroidXhttpTlsExportTest.exportExactPreparedXhttpTlsBatchRuntime",
		"--rerun-tasks", "--no-daemon", "--max-workers=2", "-Pkotlin.compiler.execution.strategy=in-process", "--stacktrace")
	command.Dir = root
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "FLVLESS_EXPORT_XHTTP_TLS_BATCH=") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "FLVLESS_EXPORT_XHTTP_TLS_BATCH="+manifest)
	command.Stdout, command.Stderr = log, log
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal("Android TLS batch export did not start", err)
	}
	waited := false
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
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
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err != nil {
			t.Fatal("selected Android TLS export failed; see owned Gradle log", err)
		}
	case <-ctx.Done():
		t.Fatal("selected Android TLS export interrupted or exceeded deadline")
	}
}

func androidTLSCheckInputs(t *testing.T, entry androidTLSEntry, source []byte) {
	t.Helper()
	actual := androidChainPrivateFile(t, entry.SourcePath, 1<<20)
	if !bytes.Equal(actual, source) || androidTLSDigest(actual) != entry.SourceSHA256 {
		t.Fatal("Android TLS planned source changed")
	}
	for _, ca := range entry.CAFiles {
		if androidTLSDigest(androidChainPrivateFile(t, ca.Path, 1<<20)) != ca.SHA256 {
			t.Fatal("Android TLS owned CA changed")
		}
	}
}

func androidTLSReadProduct(t *testing.T, entry androidTLSEntry) []byte {
	t.Helper()
	data := androidChainPrivateFile(t, filepath.Join(entry.OutputDirectory, "config.json"), 1<<20)
	metadataData := androidChainPrivateFile(t, filepath.Join(entry.OutputDirectory, "metadata.json"), 16384)
	var metadata androidTLSMetadata
	decoder := json.NewDecoder(bytes.NewReader(metadataData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Version != 1 || metadata.Mode != entry.Mode || metadata.SourceSHA256 != entry.SourceSHA256 || !androidTLSHash(metadata.PreparedSHA256) ||
		metadata.ConfigSHA256 != androidTLSDigest(data) || metadata.PrivatePort != entry.PrivatePort || metadata.UploadPort != entry.UploadPort || metadata.DownloadPort != entry.DownloadPort ||
		metadata.CertificateAssetsDirectory != entry.CertificateAssetsDirectory || !reflect.DeepEqual(metadata.CAFiles, entry.CAFiles) || metadata.ManagedInboundTag == "" ||
		metadata.Username != "session-user" || metadata.Password != "session-password" {
		t.Fatal("Android TLS exact native-output metadata changed")
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if api, present := config["api"]; !present || api != nil {
		t.Fatal("Android TLS input lost explicit api:null")
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatal("Android TLS managed inbound count changed")
	}
	managed, ok := inbounds[0].(map[string]any)
	if !ok || managed["tag"] != metadata.ManagedInboundTag || managed["port"] != float64(entry.PrivatePort) || managed["listen"] != "127.0.0.1" {
		t.Fatal("Android TLS private listener changed")
	}
	settings, ok := managed["settings"].(map[string]any)
	if !ok || settings["auth"] != "password" {
		t.Fatal("Android TLS listener is not authenticated")
	}
	accounts, ok := settings["accounts"].([]any)
	if !ok || len(accounts) != 1 {
		t.Fatal("Android TLS credential count changed")
	}
	account, ok := accounts[0].(map[string]any)
	if !ok || account["user"] != metadata.Username || account["pass"] != metadata.Password {
		t.Fatal("Android TLS synthetic credentials changed")
	}
	return data
}

func TestAndroidXHTTPTLSRuntime(t *testing.T) {
	if runtime.GOOS != "linux" || !strings.EqualFold(os.Getenv("CI"), "true") || !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("Android TLS native-output runtime requires Linux GitHub CI")
	}
	if !t.Run("batch-contract", testAndroidTLSBatchContract) {
		return
	}
	root, evidence := os.Getenv("ANDROID_LOGICAL_CHAIN_REPO"), os.Getenv("ANDROID_LOGICAL_CHAIN_EVIDENCE")
	if !filepath.IsAbs(root) || !filepath.IsAbs(evidence) {
		t.Fatal("Android TLS runner roots must be absolute")
	}
	directory := filepath.Join(evidence, "xhttp-tls")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal("Android TLS evidence must be fresh", err)
	}
	batch := androidTLSBatch{Version: 1}
	plans := []*xhttpTLSPlan{}
	// All nine input ports and all CAs are reserved/materialized before the JVM.
	// No Core or serving worker is constructed during this planning loop.
	for _, mode := range []string{"independent", "wrong_ca", "wrong_sni"} {
		modeDirectory := filepath.Join(directory, mode)
		if err := os.Mkdir(modeDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		plan := planXHTTPTLS(t, mode, modeDirectory, true)
		plan.source["api"] = nil // Android-only: avoid a second private API listener.
		plan.saveSource(t)
		entry := androidTLSEntry{Mode: mode, SourcePath: plan.sourcePath, SourceSHA256: androidTLSDigest(plan.sourceData), OutputDirectory: filepath.Join(modeDirectory, "export"),
			PrivatePort: plan.privatePort, UploadPort: plan.uploadPort, DownloadPort: plan.downloadPort, CertificateAssetsDirectory: plan.assetsDirectory, CAFiles: plan.caFiles}
		if _, err := os.Lstat(entry.OutputDirectory); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("Android TLS export already exists", err)
		}
		batch.Entries = append(batch.Entries, entry)
		plans = append(plans, plan)
	}
	if err := androidTLSValidateBatch(batch); err != nil {
		t.Fatal(err)
	}
	manifestData, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(directory, "manifest.json")
	xhttpTLSWriteNew(t, manifest, manifestData)
	androidTLSExport(t, root, directory, manifest)
	if !bytes.Equal(androidChainPrivateFile(t, manifest, 1<<20), manifestData) {
		t.Fatal("Android TLS batch manifest changed")
	}
	var systemAttempts atomic.Int64
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemAttempts.Add(1)
		return nil, errors.New("forbidden Android XHTTP TLS OS resolution")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		if systemAttempts.Load() != 0 {
			t.Error("Android XHTTP TLS attempted OS resolution")
		}
	})
	// The isolated test process retains these traps through final cleanup/exit.
	for index, plan := range plans {
		entry := batch.Entries[index]
		androidTLSCheckInputs(t, entry, plan.sourceData)
		prepared := androidTLSReadProduct(t, entry)
		if t.Run(entry.Mode, func(t *testing.T) {
			activateXHTTPTLS(t, plan, func(*testing.T) ([]byte, int) { return prepared, entry.PrivatePort })
			androidTLSCheckInputs(t, entry, plan.sourceData)
			if !bytes.Equal(androidChainPrivateFile(t, filepath.Join(entry.OutputDirectory, "config.json"), 1<<20), prepared) {
				t.Fatal("Android TLS final output changed after consumption")
			}
		}) {
			t.Logf("ANDROID_XHTTP_TLS_H2_PASS mode=%s", entry.Mode)
		}
	}
	if !bytes.Equal(androidChainPrivateFile(t, manifest, 1<<20), manifestData) {
		t.Fatal("Android TLS manifest changed after runtime")
	}
}
