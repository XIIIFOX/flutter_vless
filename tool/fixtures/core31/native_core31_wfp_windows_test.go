//go:build windows && flutter_vless_core31_followups

package tun

// This tests the actual Core TUN filter installer in an elevated disposable
// Windows runner. Loopback stands in for the TUN interface; no adapter, route,
// DNS or persistent firewall setting is changed. Temporary dynamic WFP filters
// are installed and removed. The client is a copied executable so it
// cannot accidentally receive Core's own application-ID exemption.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type core31WFPProbe struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type core31WFPReply struct {
	Results []string `json:"results"`
}

// Selected only by a parent with an exact private environment payload.
func TestNativeCore31WFPChild(t *testing.T) {
	if os.Getenv("CORE31_WFP_CHILD") != "1" {
		t.Fatal("WFP child must be invoked by its owning runtime fixture")
	}
	var probes []core31WFPProbe
	if err := json.Unmarshal([]byte(os.Getenv("CORE31_WFP_PROBES")), &probes); err != nil || len(probes) != 8 {
		t.Fatal("invalid bounded child probe contract", err)
	}
	nonce := os.Getenv("CORE31_WFP_NONCE")
	if len(nonce) != 32 {
		t.Fatal("invalid nonce")
	}
	result := core31WFPReply{}
	for _, p := range probes {
		result.Results = append(result.Results, core31WFPExchange(p, nonce))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("CORE31_WFP_CHILD_JSON " + string(encoded))
}

func core31WFPExchange(p core31WFPProbe, nonce string) string {
	c, err := net.DialTimeout(p.Network, p.Address, 400*time.Millisecond)
	if err == nil {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(400 * time.Millisecond))
		_, err = c.Write([]byte(nonce))
		if err == nil {
			b := make([]byte, len(nonce))
			_, err = io.ReadFull(c, b)
			if err == nil && string(b) == nonce {
				return "exact_payload"
			}
			if err == nil {
				return "wrong_payload"
			}
		}
	}
	if errors.Is(err, windows.WSAEACCES) {
		return "kernel_access_denied"
	}
	return fmt.Sprintf("unexpected:%T:%v", err, err)
}

func core31WFPChild(t *testing.T, exe string, probes []core31WFPProbe, nonce string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	data, err := json.Marshal(probes)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNativeCore31WFPChild$", "-test.v", "-test.timeout=6s")
	cmd.Env = append(os.Environ(), "CORE31_WFP_CHILD=1", "CORE31_WFP_PROBES="+string(data), "CORE31_WFP_NONCE="+nonce)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("owned WFP client failed/drain timeout: %v: %s", err, output)
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatal("owned child not reaped")
	}
	var lines []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "CORE31_WFP_CHILD_JSON ") {
			lines = append(lines, strings.TrimPrefix(line, "CORE31_WFP_CHILD_JSON "))
		}
	}
	if len(lines) != 1 || bytes.Contains(output, []byte("--- SKIP:")) || !bytes.Contains(output, []byte("--- PASS: TestNativeCore31WFPChild")) {
		t.Fatalf("child evidence missing, duplicated or skipped: %s", output)
	}
	var reply core31WFPReply
	if err := json.Unmarshal([]byte(lines[0]), &reply); err != nil || len(reply.Results) != len(probes) {
		t.Fatal("malformed child evidence", err)
	}
	return reply.Results
}

type core31WFPPeer struct {
	TCP    net.Listener
	UDP    net.PacketConn
	wg     sync.WaitGroup
	mu     sync.Mutex
	active map[net.Conn]bool
	faults []string
}

func core31WFPPeers(t *testing.T, tcpPort string, udpPort string) (*core31WFPPeer, []core31WFPProbe) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:"+tcpPort)
	if err != nil {
		t.Fatal("required owned TCP port unavailable", err)
	}
	u, err := net.ListenPacket("udp4", "127.0.0.1:"+udpPort)
	if err != nil {
		_ = l.Close()
		t.Fatal("required owned UDP port unavailable", err)
	}
	p := &core31WFPPeer{TCP: l, UDP: u, active: map[net.Conn]bool{}}
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.active[c] = true
			p.wg.Add(1)
			p.mu.Unlock()
			go func() {
				defer p.wg.Done()
				defer c.Close()
				defer func() { p.mu.Lock(); delete(p.active, c); p.mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				data := make([]byte, 32)
				if _, err := io.ReadFull(c, data); err != nil {
					p.mu.Lock()
					p.faults = append(p.faults, err.Error())
					p.mu.Unlock()
					return
				}
				if _, err := c.Write(data); err != nil {
					p.mu.Lock()
					p.faults = append(p.faults, err.Error())
					p.mu.Unlock()
				}
			}()
		}
	}()
	go func() {
		defer p.wg.Done()
		b := make([]byte, 128)
		for {
			n, a, err := u.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err = u.WriteTo(b[:n], a); err != nil {
				p.mu.Lock()
				p.faults = append(p.faults, err.Error())
				p.mu.Unlock()
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		_ = u.Close()
		// Accept loop must finish before waiting, and active clients have deadlines.
		p.mu.Lock()
		for c := range p.active {
			_ = c.Close()
		}
		p.mu.Unlock()
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned WFP peers did not drain")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.active) != 0 || len(p.faults) != 0 {
			t.Errorf("peer resources/faults: active=%d faults=%v", len(p.active), p.faults)
		}
	})
	return p, []core31WFPProbe{{"tcp4", l.Addr().String()}, {"udp4", u.LocalAddr().String()}}
}

// Query the real WFP engine instead of inferring deletion from Close alone.
func core31WFPFilterIDs(t *testing.T, engine windows.Handle) []uint64 {
	t.Helper()
	create := modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	enum := modfwpuclnt.NewProc("FwpmFilterEnum0")
	destroy := modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	var handle windows.Handle
	if err := fwpmResult(create.Call(uintptr(engine), 0, uintptr(unsafe.Pointer(&handle)))); err != nil {
		t.Fatal(err)
	}
	defer destroy.Call(uintptr(engine), uintptr(handle))
	var ids []uint64
	for batches := 0; batches < 100; batches++ {
		var entries **fwpmFilter0
		var count uint32
		if err := fwpmResult(enum.Call(uintptr(engine), uintptr(handle), 1000, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count)))); err != nil {
			t.Fatal(err)
		}
		if count > 1000 {
			t.Fatal("invalid WFP enum count")
		}
		if count > 0 && entries == nil {
			t.Fatal("nil WFP enum body")
		}
		for _, f := range unsafe.Slice(entries, int(count)) {
			if f == nil {
				t.Fatal("nil WFP filter")
			}
			if strings.HasPrefix(windows.UTF16PtrToString(f.displayData.name), "Xray TUN:") {
				ids = append(ids, f.filterID)
			}
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
		if count < 1000 {
			slices.Sort(ids)
			return ids
		}
	}
	t.Fatal("unbounded WFP enumeration")
	return nil
}

func TestNativeCore31WFPPortsAndCleanup(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") || runtime.GOOS != "windows" {
		t.Fatal("Core WFP runtime is Windows Actions-only")
	}
	wantDNS := []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853"}
	got, err := ExpandWfpBlockLeak([]string{"DNS", "TCP/0853", "udp/853"})
	if err != nil || !reflect.DeepEqual(got, wantDNS) {
		t.Fatal("DNS expansion/dedup failed", got, err)
	}
	for _, value := range []string{"tcp/0", "udp/65536", "tcp/-1", "icmp/853", "tcp/notaport"} {
		if _, err := ExpandWfpBlockLeak([]string{value}); err == nil {
			t.Fatal("invalid port accepted", value)
		}
	}
	_, custom := core31WFPPeers(t, "0", "0")
	_, tlsDNS := core31WFPPeers(t, "853", "853")
	_, tcpPort, err := net.SplitHostPort(custom[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	_, udpPort, err := net.SplitHostPort(custom[1].Address)
	if err != nil {
		t.Fatal(err)
	}
	if tcpPort == udpPort {
		t.Fatal("custom ports must differ for protocol isolation controls")
	}
	_, crossProtocol := core31WFPPeers(t, udpPort, tcpPort)
	_, unlisted := core31WFPPeers(t, "0", "0")
	selected := append(custom, tlsDNS...)
	probes := append(append(append([]core31WFPProbe{}, selected...), crossProtocol...), unlisted...)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(t.TempDir(), "independent-core31-client.exe")
	if err := os.WriteFile(child, data, 0700); err != nil {
		t.Fatal(err)
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	expect := func(stage string, want string) {
		t.Helper()
		seen := core31WFPChild(t, child, probes, nonce)
		for i, result := range seen {
			wanted := want
			if stage == "outside-TUN-blocked" && i >= len(selected) {
				wanted = "exact_payload"
			}
			if result != wanted {
				t.Fatalf("%s %s %s: got %s want %s", stage, probes[i].Network, probes[i].Address, result, wanted)
			}
		}
		t.Logf("CORE31_WFP_PHASE_PASS mode=%s cases=%d", stage, len(seen))
	}
	expect("before", "exact_payload")
	var leaks []string
	for _, p := range selected {
		_, port, err := net.SplitHostPort(p.Address)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = strconv.Atoi(port); err != nil {
			t.Fatal(err)
		}
		proto := "udp"
		if strings.HasPrefix(p.Network, "tcp") {
			proto = "tcp"
		}
		leaks = append(leaks, proto+"/"+port)
	}
	expanded, err := ExpandWfpBlockLeak(leaks)
	if err != nil {
		t.Fatal(err)
	}
	block := newLeakFilters(expanded, true, true)
	observer, err := openWFPEngine()
	if err != nil {
		t.Fatal("elevated WFP engine required; no skip", err)
	}
	defer closeWFPEngine(observer)
	before := core31WFPFilterIDs(t, observer)
	engine, err := blockLeaks(0, block)
	if err != nil {
		t.Fatal("real WFP install failed", err)
	}
	defer func() {
		if engine != 0 {
			closeWFPEngine(engine)
		}
	}()
	during := core31WFPFilterIDs(t, observer)
	if len(during) <= len(before) {
		t.Fatal("no real Core WFP filters appeared")
	}
	expect("outside-TUN-blocked", "kernel_access_denied")
	for _, p := range probes {
		if got := core31WFPExchange(p, nonce); got != "exact_payload" {
			t.Fatal("Core application-ID exemption failed", p, got)
		}
	}
	t.Log("CORE31_WFP_SELF_EXEMPT_PASS")
	closeWFPEngine(engine)
	engine = 0
	if after := core31WFPFilterIDs(t, observer); !reflect.DeepEqual(before, after) {
		t.Fatal("dynamic Core filters were not removed", len(before), len(after))
	}
	expect("after-close", "exact_payload")
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loopback winipcfg.LUID
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			loopback, err = winipcfg.LUIDFromIndex(uint32(iface.Index))
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if loopback == 0 {
		t.Fatal("real loopback LUID missing")
	}
	engine, err = blockLeaks(loopback, block)
	if err != nil {
		t.Fatal(err)
	}
	expect("through-TUN-interface-permitted", "exact_payload")
	closeWFPEngine(engine)
	engine = 0
	if after := core31WFPFilterIDs(t, observer); !reflect.DeepEqual(before, after) {
		t.Fatal("through-TUN dynamic Core filters remained")
	}
	expect("final-recovery", "exact_payload")
	t.Log("CORE31_WFP_CLEANUP_PASS filters_delta=0 ports=4")
}
