package XRay

import (
	"encoding/json"
	"github.com/xtls/xray-core/infra/conf"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	xlog "github.com/xtls/xray-core/common/log"
)

type privacyLogger struct {
	sync.Mutex
	messages []string
}

func (l *privacyLogger) LogInput(s string) {
	l.Lock()
	defer l.Unlock()
	l.messages = append(l.messages, s)
}
func (l *privacyLogger) text() string {
	l.Lock()
	defer l.Unlock()
	return strings.Join(l.messages, "\n")
}

func TestPrivateConfigStreamsAndCredentials(t *testing.T) {
	input := `{"LOG":{"LogLevel":"ERROR","access":"canary","DNSLOG":true},"Outbounds":[{"settings":{"id":"uuid-canary","password":"password-canary","large":9007199254740993},"StreamSettings":{"TLSSettings":{"MasterKeyLog":"tls-canary"},"RealitySettings":{"SHOW":true,"MASTERKEYLOG":"key-canary","serverName":"sni-canary"},"XHTTPSettings":{"headers":{"SHOW":"keep","Log":"header-canary"},"Extra":{"DownloadSettings":{"RealitySettings":{"show":true,"masterKeyLog":"nested-canary"}}}}}}],"Inbounds":[{"streamSettings":{"splithttpSettings":{"downloadSettings":{"tlsSettings":{"masterKeyLog":"inbound-canary"}}}}}]}`
	output, severity, enabled, err := privateConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	text := string(output)
	if severity != xlog.Severity_Error || !enabled {
		t.Fatal("strict level not retained")
	}
	for _, marker := range []string{"tls-canary", "key-canary", "nested-canary", "inbound-canary"} {
		if strings.Contains(text, marker) {
			t.Fatalf("diagnostic path retained: %s", marker)
		}
	}
	for _, marker := range []string{"uuid-canary", "password-canary", "sni-canary", "header-canary", "9007199254740993"} {
		if !strings.Contains(text, marker) {
			t.Fatalf("legitimate value lost: %s", marker)
		}
	}
	var config map[string]any
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatal(err)
	}
	log := config["log"].(map[string]any)
	if log["access"] != "none" || log["error"] != "none" || log["dnsLog"] != false || log["loglevel"] != "error" {
		t.Fatal(log)
	}
	if strings.Contains(text, `"show":true`) {
		t.Fatal("raw Reality prints remain")
	}
}

func TestPrivateConfigLevelsAndInvalidRepresentations(t *testing.T) {
	for _, level := range []string{"debug", "info", "warning", "error", "none", "ERROR"} {
		output, _, enabled, err := privateConfig([]byte(`{"log":{"loglevel":"` + level + `"}}`))
		if err != nil {
			t.Fatal(err)
		}
		want := strings.ToLower(level)
		if want != "error" && want != "none" {
			want = "warning"
		}
		if !strings.Contains(string(output), `"loglevel":"`+want+`"`) || enabled != (want != "none") {
			t.Fatalf("level %s", level)
		}
	}
	for _, config := range []string{`null`, `{} {}`, `{"log":{},"LOG":{}}`, `{"log":{"access":"none","Access":""}}`, `{"inbounds":[{"streamSettings":{"realitySettings":{"show":false,"SHOW":true}}}]}`, `{"outbounds":[{"streamSettings":{"xhttpSettings":{"extra":{"downloadSettings":"invalid"}}}}]}`} {
		if _, _, _, err := privateConfig([]byte(config)); err == nil {
			t.Fatalf("accepted %s", config)
		}
	}
	if _, _, enabled, err := privateConfig([]byte(`{"log":{"error":"none"}}`)); err != nil || enabled {
		t.Fatal("explicit disabled error output weakened")
	}
}

func TestPrivateStartSuppressesOriginalErrorsAndRuntimeOutput(t *testing.T) {
	// Local core only: no inbound, outbound blackhole; never creates a VPN or external connection.
	originalOut, originalErr := os.Stdout, os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = writer, writer
	defer func() { os.Stdout, os.Stderr = originalOut, originalErr; reader.Close(); writer.Close(); Stop() }()
	logger := &privacyLogger{}
	marker := "uuid-password-domain-canary.invalid"
	for _, config := range []string{`{"outbounds":[{"protocol":"` + marker + `"}]}`, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"` + marker + `","port":443,"users":[{"id":"password-canary"}]}]}}]}`, `{"log":{"loglevel":"debug"},"inbounds":"` + marker + `"}`} {
		err := StartPrivate([]byte(config), logger)
		if err == nil {
			t.Fatal("invalid config started")
		}
		if strings.Contains(err.Error(), "canary") || !strings.HasPrefix(err.Error(), "Xray startup failed:") {
			t.Fatalf("unsafe/missing error stage: %v", err)
		}
	}
	if err := StartPrivate([]byte(`{"log":{"access":"","error":"","loglevel":"debug"},"outbounds":[{"protocol":"blackhole"}]}`), logger); err != nil {
		t.Fatal(err)
	}
	xlog.Record(&xlog.AccessMessage{From: marker, To: marker, Reason: marker})
	xlog.Record(&xlog.GeneralMessage{Severity: xlog.Severity_Error, Content: marker})
	xlog.Record(&xlog.GeneralMessage{Severity: xlog.Severity_Info, Content: marker})
	Stop()
	writer.Close()
	os.Stdout, os.Stderr = originalOut, originalErr
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "canary") || strings.Contains(logger.text(), "canary") {
		t.Fatalf("private data escaped: stdout=%q callback=%q", output, logger.text())
	}
	if !strings.Contains(logger.text(), "Xray runtime error") || !strings.Contains(logger.text(), "Xray startup failed: build configuration") {
		t.Fatalf("safe diagnostic stages missing: %q", logger.text())
	}
}

func TestPrivateRealmKeyLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key-canary")
	// Reproduce the sink without sending TLS traffic: GetTLSConfig opens the file.
	unsafe := &xtls.Config{MasterKeyLog: path}
	unsafe.GetTLSConfig()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("control did not open key log", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	stream := map[string]any{"FinalMask": map[string]any{
		"QuicParams": map[string]any{"Debug": true},
		"UDP": []any{map[string]any{"Type": "realm", "Settings": map[string]any{
			"url": "realm://token@realm.example/id", "stunServers": []string{"127.0.0.1:3478"},
			"TLSConfig": map[string]any{"MasterKeyLog": path, "serverName": "sni-canary"}}}}}}
	raw, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"streamSettings": stream}}})
	output, _, _, err := privateConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), path) || strings.Contains(string(output), `"debug":true`) {
		t.Fatal("finalmask diagnostics survive")
	}
	var config map[string]any
	json.Unmarshal(output, &config)
	prepared := config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["finalmask"].(map[string]any)
	settings := prepared["udp"].([]any)[0].(map[string]any)["settings"].(map[string]any)
	raw, _ = json.Marshal(settings["tlsConfig"])
	var tlsSettings conf.TLSConfig
	if err = json.Unmarshal(raw, &tlsSettings); err != nil {
		t.Fatal(err)
	}
	built, err := tlsSettings.Build()
	if err != nil {
		t.Fatal(err)
	}
	built.(*xtls.Config).GetTLSConfig()
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("sanitized TLS created key file", err)
	}
}
