package native_dns_preservation_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

type certificatePathCase struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
	Bind   []string       `json:"bind"`
}

// File-only exporter: the source and synthetic key remain in private temporary
// files, never argv/output. The command is bounded/reaped; logs are not printed.
func bindCertificateFixture(t *testing.T, source []byte, directory string) []byte {
	t.Helper()
	return runCertificateFixture(t, source, directory, false)
}

func runCertificateFixture(t *testing.T, source []byte, directory string, reject bool) []byte {
	t.Helper()
	preparer := os.Getenv("NATIVE_DNS_PREPARER")
	if preparer == "" {
		t.Fatal("native certificate exporter required")
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.json"), filepath.Join(dir, "effective.json")
	if err := os.WriteFile(input, source, 0600); err != nil {
		t.Fatal("cannot save certificate fixture source")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, preparer, "--bind-certificate-fixture", input, output, directory)
	cmd.WaitDelay = time.Second
	capture := new(dohOutput)
	cmd.Stdout, cmd.Stderr = capture, capture
	err := cmd.Run()
	_, truncated := capture.snapshot()
	if original, readErr := os.ReadFile(input); readErr != nil || !bytes.Equal(source, original) {
		t.Fatal("native certificate binding changed source file")
	}
	if reject {
		failure, ok := err.(*exec.ExitError)
		if !ok || failure.ExitCode() != 3 || ctx.Err() != nil || truncated {
			t.Fatal("invalid certificate root did not fail at bounded native admission")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("rejected certificate candidate published output")
		}
		return nil
	}
	if err != nil || ctx.Err() != nil || truncated {
		t.Fatal("bounded native certificate binding failed")
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal("native certificate output missing")
	}
	defer file.Close()
	result, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(result) > 65536 {
		t.Fatal("invalid native certificate output size")
	}
	return result
}

func certificateBuild(data []byte) (proto.Message, error) {
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return decoded.Build() // Read certificate files only; never Core.New/Start.
}

func certificateDocument(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal("invalid certificate fixture document")
	}
	return value
}

func certificateExpected(t *testing.T, tc certificatePathCase, root string) []byte {
	t.Helper()
	bindings := make([]dnsAddressBinding, 0, len(tc.Bind))
	for _, pointer := range tc.Bind {
		path := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
		var value any = tc.Config
		for index, part := range path {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			path[index] = part
			switch object := value.(type) {
			case map[string]any:
				value = object[part]
			case []any:
				n, err := strconv.Atoi(part)
				if err != nil || n < 0 || n >= len(object) {
					t.Fatal("invalid certificate binding index")
				}
				value = object[n]
			default:
				t.Fatal("invalid certificate binding pointer")
			}
		}
		raw, ok := value.(string)
		if !ok || raw == "" || filepath.IsAbs(raw) {
			t.Fatal("relative certificate fixture binding required")
		}
		bindings = append(bindings, dnsAddressBinding{Path: path, Value: filepath.Clean(filepath.Join(root, raw))})
	}
	return dnsLiteralControl(t, dnsAddressCase{Config: tc.Config, Bindings: bindings})
}

// Core Decode/Build and optional native file-only exporters. PEM generation and
// file reads never construct a Core, TLS client, listener or trust-store change.
func testCertificatePaths(t *testing.T, native bool) {
	data := selectorFixture(t, "certificate-paths.json")
	material := makeDoHMaterial(t)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: material.good.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(material.good.PrivateKey)
	if err != nil {
		t.Fatal("cannot serialize synthetic certificate key")
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	var cases []certificatePathCase
	if json.Unmarshal(data, &cases) != nil || len(cases) != 8 {
		t.Fatal("eight shared certificate path cases required")
	}
	inline := cases[5].Config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["certificates"].([]any)[0].(map[string]any)
	inline["certificate"], inline["key"] = []any{string(certificate)}, []any{string(key)}
	root, oldRoot := t.TempDir(), t.TempDir()
	for name, content := range map[string][]byte{"fixture.pem": certificate, "fixture.key": key} {
		if os.WriteFile(filepath.Join(root, name), content, 0600) != nil || os.WriteFile(filepath.Join(oldRoot, name), material.foreignCA, 0600) != nil {
			t.Fatal("cannot save synthetic certificate files")
		}
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			source, _ := json.Marshal(tc.Config)
			t.Setenv("xray.location.cert", root)
			t.Setenv("XRAY_LOCATION_CERT", oldRoot)
			fromExact, err := certificateBuild(source)
			if err != nil {
				t.Fatal("source relative certificate files did not build through exact Core root")
			}
			if os.Unsetenv("xray.location.cert") != nil {
				t.Fatal("cannot scope certificate environment")
			}
			t.Setenv("XRAY_LOCATION_CERT", root)
			fromAlias, err := certificateBuild(source)
			if err != nil || !proto.Equal(fromExact, fromAlias) {
				t.Fatal("Core certificate root alias changed compiled source")
			}
			expected := certificateExpected(t, tc, root)
			want, err := certificateBuild(expected)
			if err != nil {
				t.Fatal("literal absolute certificate control failed Core Build")
			}
			if native {
				bound := bindCertificateFixture(t, source, root)
				if !reflect.DeepEqual(certificateDocument(t, bound), certificateDocument(t, expected)) {
					t.Fatal("certificate binding changed fields outside the active file pointers")
				}
				t.Setenv("xray.location.cert", oldRoot)
				t.Setenv("XRAY_LOCATION_CERT", oldRoot)
				got, err := certificateBuild(bound)
				if err != nil || !proto.Equal(want, got) {
					t.Fatal("bound certificate config differs from full literal protobuf after environment handoff")
				}
				if !reflect.DeepEqual(certificateDocument(t, bindCertificateFixture(t, bound, oldRoot)), certificateDocument(t, expected)) {
					t.Fatal("absolute certificate paths were rebound or not idempotent")
				}
			}
			if after, _ := json.Marshal(tc.Config); !bytes.Equal(source, after) {
				t.Fatal("certificate preparation mutated caller JSON")
			}
		})
	}
	for _, tc := range cases[6:] {
		t.Run(tc.Name+"-missing-file", func(t *testing.T) {
			for _, pointer := range tc.Bind {
				path := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
				missing := dnsLiteralControl(t, dnsAddressCase{Config: tc.Config, Bindings: []dnsAddressBinding{{Path: path, Value: "missing-specialized.pem"}}})
				if native {
					missing = bindCertificateFixture(t, missing, root)
				}
				t.Setenv("xray.location.cert", root)
				if _, err := certificateBuild(missing); err == nil {
					t.Fatal("missing specialized TLS file did not fail actual Core Build")
				}
			}
		})
	}
	t.Run("missing-root-and-referenced-file", func(t *testing.T) {
		source, _ := json.Marshal(cases[5].Config)
		if native {
			runCertificateFixture(t, source, filepath.Join(root, "absent-directory"), true)
		}
		for _, name := range []string{"certificateFile", "keyFile"} {
			missing := certificateDocument(t, source)
			entry := missing["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["certificates"].([]any)[0].(map[string]any)
			filename, content := "missing.pem", certificate
			if name == "keyFile" {
				filename, content = "missing.key", key
			}
			entry[name] = filename
			if os.WriteFile(filepath.Join(oldRoot, filename), content, 0600) != nil {
				t.Fatal("cannot save old certificate-root control")
			}
			data, _ := json.Marshal(missing)
			t.Setenv("xray.location.cert", oldRoot)
			if _, err := certificateBuild(data); err != nil {
				t.Fatal("old root positive control failed")
			}
			if native {
				data = bindCertificateFixture(t, data, root)
			} else {
				t.Setenv("xray.location.cert", root)
			}
			if _, err := certificateBuild(data); err == nil {
				t.Fatal("missing referenced file silently used inline data or old CERT root")
			}
		}
	})
	for name, expected := range map[string][]byte{"fixture.pem": certificate, "fixture.key": key} {
		if actual, err := os.ReadFile(filepath.Join(root, name)); err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("certificate preparation changed caller file material")
		}
	}
}

func TestNativeCertificatePaths(t *testing.T) {
	if os.Getenv("NATIVE_DNS_PREPARER") == "" {
		t.Fatal("production native certificate exporter required")
	}
	t.Run("WindowsPreparer", func(t *testing.T) { testCertificatePaths(t, true); testDoHProxyCertificatePreparation(t) })
	if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
		t.Run("ApplePreparer", func(t *testing.T) {
			t.Setenv("NATIVE_DNS_PREPARER", apple)
			testCertificatePaths(t, true)
			testDoHProxyCertificatePreparation(t)
		})
	}
}
