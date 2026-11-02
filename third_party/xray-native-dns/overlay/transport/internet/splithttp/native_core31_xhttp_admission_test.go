//go:build flutter_vless_core31_followups

package splithttp_test

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/net/http2"
)

func TestCore31XHTTPInvalidH2ParamsAdmission(t *testing.T) {
	if os.Getenv("CI") != "true" || runtime.GOOS == "darwin" && os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("Core31 native execution is CI-only")
	}
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	jsonSource := func(params string) string {
		return fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":"00000000-0000-4000-8000-000000000031"}],"decryption":"none"},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/core31","h2Params":%s}}}],"outbounds":[{"protocol":"freedom"}]}`, port, params)
	}
	// A valid sibling goes through the real JSON builder and Core start before
	// the negative case. Observe SETTINGS on the wire, not a protobuf field.
	validConfig, err := serial.DecodeJSONConfig(strings.NewReader(jsonSource(`{"MaxConcurrentStreams":7,"MaxReadFrameSize":32768}`)))
	if err != nil {
		t.Fatal(err)
	}
	validBuilt, err := validConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	validCore, err := core.New(validBuilt)
	if err != nil {
		t.Fatal(err)
	}
	defer validCore.Close()
	if err := validCore.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte(http2.ClientPreface)); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	framer := http2.NewFramer(connection, connection)
	if err := framer.WriteSettings(); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	frame, err := framer.ReadFrame()
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok || settings.IsAck() {
		connection.Close()
		t.Fatal("valid JSON did not produce initial H2 SETTINGS")
	}
	values := map[http2.SettingID]uint32{}
	if err := settings.ForeachSetting(func(s http2.Setting) error { values[s.ID] = s.Val; return nil }); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if values[http2.SettingMaxConcurrentStreams] != 7 || values[http2.SettingMaxFrameSize] != 32768 {
		connection.Close()
		t.Fatal("valid h2Params lost between JSON and listener", values)
	}
	_ = connection.Close()
	if err := validCore.Close(); err != nil {
		t.Fatal(err)
	}
	// Valid outer JSON and a valid, ordinary HTTP server setting name, but an
	// invalid value type. This is reachable through ordinary user config import.
	source := jsonSource(`{"MaxConcurrentStreams":"invalid-type"}`)
	config, err := serial.DecodeJSONConfig(strings.NewReader(source))
	if err != nil {
		t.Fatal("outer fixture JSON is invalid", err)
	}
	built, buildError := config.Build()
	stage := "build"
	if buildError == nil {
		instance, err := core.New(built)
		if err == nil {
			stage = "start"
			err = instance.Start()
			closed := make(chan error, 1)
			go func() { closed <- instance.Close() }()
			select {
			case closeError := <-closed:
				if closeError != nil {
					t.Fatal(closeError)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("rejected Core did not close")
			}
		}
		if err == nil {
			t.Fatal("malformed h2Params reached a running Core listener")
		}
	}
	// A Core startup failure must not leave the bound port behind after Close.
	probe, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal("invalid h2Params leaked its listener after failed Core startup and Close", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("CORE31_XHTTP_H2_REJECT_PASS stage=%s listener_reusable=true valid_settings=true", stage)
}
