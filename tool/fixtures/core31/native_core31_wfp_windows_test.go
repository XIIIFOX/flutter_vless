//go:build windows && flutter_vless_core31_followups

package tun

// Exercise Core TUN filters in an elevated disposable Windows runner. The
// client uses a different executable path to avoid Xray's AppID exemption.
// Only the dynamic test session's filters are installed and removed.
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
		if err := c.SetDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
			return fmt.Sprintf("deadline:%v", err)
		}
		var n int
		n, err = c.Write([]byte(nonce))
		if err == nil {
			if n != len(nonce) {
				return "short_write"
			}
			b := make([]byte, len(nonce))
			_, err = io.ReadFull(c, b)
			if err == nil && string(b) == nonce {
				return "exact_payload"
			}
			if err == nil {
				return "wrong_payload"
			}
			// Windows WFP can silently drop UDP after a successful send. This
			// observation is NEVER sufficient to pass by itself: the parent also
			// requires exact installed port filters, zero nonce receipts at that
			// owned origin, healthy simultaneous controls and later recovery.
			var networkError net.Error
			if p.Network == "udp4" && errors.As(err, &networkError) && networkError.Timeout() {
				return "bounded_no_reply"
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
	seen   map[core31WFPProbe]map[string]int
	want   map[core31WFPProbe]map[string]int
}

func (p *core31WFPPeer) record(probe core31WFPProbe, data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	nonce := string(data)
	if len(data) != 32 {
		p.faults = append(p.faults, "unexpected nonce length at "+probe.Network)
	}
	if _, known := p.want[probe][nonce]; !known {
		p.faults = append(p.faults, "unowned nonce reached "+probe.Network)
	}
	p.seen[probe][nonce]++
}

func (p *core31WFPPeer) expect(probe core31WFPProbe, nonce string, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.want[probe][nonce] = count
}

func (p *core31WFPPeer) checkReceipt(t *testing.T, probe core31WFPProbe, nonce string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if got, want := p.seen[probe][nonce], p.want[probe][nonce]; got != want {
		t.Fatalf("owned origin receipt mismatch for %s %s: got=%d want=%d", probe.Network, probe.Address, got, want)
	}
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
	tcpProbe, udpProbe := core31WFPProbe{"tcp4", l.Addr().String()}, core31WFPProbe{"udp4", u.LocalAddr().String()}
	p := &core31WFPPeer{TCP: l, UDP: u, active: map[net.Conn]bool{},
		seen: map[core31WFPProbe]map[string]int{tcpProbe: {}, udpProbe: {}},
		want: map[core31WFPProbe]map[string]int{tcpProbe: {}, udpProbe: {}},
	}
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
				p.record(tcpProbe, data)
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
			p.record(udpProbe, b[:n])
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
		// Check again after every reader has stopped. A delayed blocked nonce
		// arriving after a phase's immediate snapshot must still fail the test.
		for probe, nonces := range p.want {
			for nonce, want := range nonces {
				if got := p.seen[probe][nonce]; got != want {
					t.Errorf("final owned origin receipt mismatch for %s %s: got=%d want=%d", probe.Network, probe.Address, got, want)
				}
			}
		}
	})
	return p, []core31WFPProbe{tcpProbe, udpProbe}
}

type core31WFPCondition struct {
	field     windows.GUID
	matchType uint32
	valueType uint32
	value     uint64
}

type core31WFPFilter struct {
	id         uint64
	name       string
	layer      windows.GUID
	action     uint32
	conditions []core31WFPCondition
}

// Copy the real WFP inventory before freeing the native enum allocation. Its
// port/interface conditions establish what was installed, not only its name.
func core31WFPFilters(t *testing.T, engine windows.Handle) []core31WFPFilter {
	t.Helper()
	create := modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	enum := modfwpuclnt.NewProc("FwpmFilterEnum0")
	destroy := modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	var handle windows.Handle
	if err := fwpmResult(create.Call(uintptr(engine), 0, uintptr(unsafe.Pointer(&handle)))); err != nil {
		t.Fatal(err)
	}
	defer destroy.Call(uintptr(engine), uintptr(handle))
	var filters []core31WFPFilter
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
				if f.numFilterConditions > 64 || f.numFilterConditions > 0 && f.filterCondition == nil {
					t.Fatal("invalid WFP condition array")
				}
				item := core31WFPFilter{id: f.filterID, name: windows.UTF16PtrToString(f.displayData.name), layer: f.layerKey, action: f.action.typ}
				for _, condition := range unsafe.Slice(f.filterCondition, int(f.numFilterConditions)) {
					copied := core31WFPCondition{field: condition.fieldKey, matchType: condition.matchType, valueType: condition.conditionValue.typ}
					switch copied.valueType {
					case fwpUint8:
						copied.value = uint64(uint8(condition.conditionValue.value))
					case fwpUint16:
						copied.value = uint64(uint16(condition.conditionValue.value))
					case fwpUint32:
						copied.value = uint64(uint32(condition.conditionValue.value))
					case fwpUint64:
						if condition.conditionValue.value == 0 {
							t.Fatal("nil WFP UINT64 value")
						}
						copied.value = *(*uint64)(unsafe.Pointer(condition.conditionValue.value))
					}
					item.conditions = append(item.conditions, copied)
				}
				filters = append(filters, item)
			}
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
		if count < 1000 {
			return filters
		}
	}
	t.Fatal("unbounded WFP enumeration")
	return nil
}

func core31WFPFilterIDs(t *testing.T, engine windows.Handle) []uint64 {
	t.Helper()
	var ids []uint64
	for _, filter := range core31WFPFilters(t, engine) {
		ids = append(ids, filter.id)
	}
	slices.Sort(ids)
	return ids
}

// Check exact protocol/port blocks and the TUN and loopback permits in all four
// ALE layers. Return the owned loopback permit IDs for the negative control.
func core31WFPRequirePortFilters(t *testing.T, filters []core31WFPFilter, baseline []uint64, selected []core31WFPProbe, tun winipcfg.LUID) []uint64 {
	t.Helper()
	layers := map[windows.GUID]windows.GUID{
		fwpmLayerALEAuthConnectV4:    fwpmConditionIPNexthopInterface,
		fwpmLayerALEAuthConnectV6:    fwpmConditionIPNexthopInterface,
		fwpmLayerALEAuthRecvAcceptV4: fwpmConditionIPArrivalInterface,
		fwpmLayerALEAuthRecvAcceptV6: fwpmConditionIPArrivalInterface,
	}
	type key struct {
		layer windows.GUID
		proto uint64
		port  uint64
	}
	blocks := map[key]int{}
	permits := map[windows.GUID]map[string]int{}
	var loopbackIDs []uint64
	wanted := map[key]bool{}
	for layer := range layers {
		permits[layer] = map[string]int{}
		for _, probe := range selected {
			_, port, err := net.SplitHostPort(probe.Address)
			if err != nil {
				t.Fatal(err)
			}
			number, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			protocol := uint64(windows.IPPROTO_UDP)
			if probe.Network == "tcp4" {
				protocol = uint64(windows.IPPROTO_TCP)
			}
			wanted[key{layer, protocol, number}] = true
		}
	}
	for _, filter := range filters {
		if slices.Contains(baseline, filter.id) {
			continue
		}
		via, knownLayer := layers[filter.layer]
		if !knownLayer {
			t.Fatal("owned WFP filter on an unexpected layer")
		}
		condition := func(field windows.GUID, matchType, valueType uint32, value uint64) bool {
			return slices.Contains(filter.conditions, core31WFPCondition{field, matchType, valueType, value})
		}
		if filter.action == fwpActionPermit {
			const prefix = "Xray TUN: permit "
			if !strings.HasPrefix(filter.name, prefix) {
				t.Fatal("unexpected owned WFP permit name")
			}
			name := strings.TrimPrefix(filter.name, prefix)
			permits[filter.layer][name]++
			switch name {
			case "Xray":
				if len(filter.conditions) != 1 || !condition(fwpmConditionALEAppID, fwpMatchEqual, fwpByteBlobType, 0) {
					t.Fatal("Core application exemption metadata mismatch")
				}
			case "loopback":
				if len(filter.conditions) != 1 || !condition(fwpmConditionFlags, fwpMatchFlagsAllSet, fwpUint32, fwpConditionFlagIsLoopback) {
					t.Fatal("Core loopback exemption metadata mismatch")
				}
				loopbackIDs = append(loopbackIDs, filter.id)
			case "through the TUN":
				if len(filter.conditions) != 2 || !condition(fwpmConditionIPLocalInterface, fwpMatchEqual, fwpUint64, uint64(tun)) ||
					!condition(via, fwpMatchEqual, fwpUint64, uint64(tun)) {
					t.Fatal("Core TUN permit does not require the selected LUID twice")
				}
			}
			continue
		}
		if filter.action != fwpActionBlock || len(filter.conditions) != 2 {
			t.Fatal("unexpected owned WFP port-rule action or conditions")
		}
		conditions := map[windows.GUID]core31WFPCondition{}
		for _, condition := range filter.conditions {
			if condition.matchType != fwpMatchEqual {
				t.Fatal("owned WFP port filter uses an unexpected comparison")
			}
			conditions[condition.field] = condition
		}
		protocol, port := conditions[fwpmConditionIPProtocol], conditions[fwpmConditionIPRemotePort]
		if protocol.valueType != fwpUint8 || port.valueType != fwpUint16 {
			t.Fatal("installed WFP rule omitted typed protocol/remote-port conditions")
		}
		entry := key{filter.layer, protocol.value, port.value}
		if !wanted[entry] {
			t.Fatal("installed WFP rule targets an unselected protocol/port")
		}
		blocks[entry]++
	}
	for entry := range wanted {
		if blocks[entry] != 1 {
			t.Fatal("missing or duplicated installed protocol/port block")
		}
	}
	for layer := range layers {
		want := map[string]int{"Xray": 1, "loopback": 1, "through the TUN": 1}
		if layer == fwpmLayerALEAuthConnectV6 || layer == fwpmLayerALEAuthRecvAcceptV6 {
			want["IPv6 neighbor and multicast listener discovery"] = 1
			want["DHCPv6"] = 1
		} else {
			want["DHCP"] = 1
		}
		if !reflect.DeepEqual(permits[layer], want) {
			t.Fatalf("unexpected owned Core WFP permits: %v", permits[layer])
		}
	}
	return loopbackIDs
}

func TestNativeCore31WFPPortsAndCleanup(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") || runtime.GOOS != "windows" {
		t.Fatal("Core WFP runtime is Windows Actions-only")
	}
	wantDNS := []string{"53", "853", "windnsclient", "tcp/853", "udp/853"}
	got, err := ExpandWfpBlockLeak([]string{"DNS", "TCP/0853", "udp/853"})
	if err != nil || !reflect.DeepEqual(got, wantDNS) {
		t.Fatal("DNS expansion/dedup failed", got, err)
	}
	got, err = ExpandWfpBlockLeak([]string{"ALL", "allexceptlan", "tcp/1-65535", "udp/1000-2000", "[2001:db8::123/64]:icmp"})
	want := []string{"all", "allexceptlan", "53", "853", "windnsclient", "tcp", "udp/1000-2000", "[2001:db8::/64]:icmp"}
	if err != nil || !reflect.DeepEqual(got, want) || !BlocksSystemDNS(got) {
		t.Fatal("extended WFP syntax or system DNS detection differs", got, err)
	}
	t.Log("CORE31_WFP_EXTENDED_VALUES_PASS")
	for _, value := range []string{"tcp/0", "udp/65536", "tcp/-1", "icmp/853", "tcp/notaport"} {
		if _, err := ExpandWfpBlockLeak([]string{value}); err == nil {
			t.Fatal("invalid port accepted", value)
		}
	}
	customPeer, custom := core31WFPPeers(t, "0", "0")
	tlsDNSPeer, tlsDNS := core31WFPPeers(t, "853", "853")
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
	crossPeer, crossProtocol := core31WFPPeers(t, udpPort, tcpPort)
	unlistedPeer, unlisted := core31WFPPeers(t, "0", "0")
	selected := append(custom, tlsDNS...)
	probes := append(append(append([]core31WFPProbe{}, selected...), crossProtocol...), unlisted...)
	owners := map[core31WFPProbe]*core31WFPPeer{}
	for index, peer := range []*core31WFPPeer{customPeer, tlsDNSPeer, crossPeer, unlistedPeer} {
		for _, probe := range probes[index*2 : index*2+2] {
			if owners[probe] != nil {
				t.Fatal("duplicate owned protocol/port endpoint")
			}
			owners[probe] = peer
		}
	}
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
	newNonce := func() string {
		t.Helper()
		var nonceBytes [16]byte
		if _, err := rand.Read(nonceBytes[:]); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(nonceBytes[:])
	}
	register := func(nonce string, blocked bool) {
		for i, probe := range probes {
			count := 1
			if blocked && i < len(selected) {
				count = 0
			}
			owners[probe].expect(probe, nonce, count)
		}
	}
	receiptPhases := 0
	expect := func(stage string, blocked bool) {
		t.Helper()
		nonce := newNonce()
		register(nonce, blocked)
		seen := core31WFPChild(t, child, probes, nonce)
		for i, result := range seen {
			wanted := "exact_payload"
			if blocked && i < len(selected) {
				wanted = "kernel_access_denied"
				if probes[i].Network == "udp4" {
					wanted = "bounded_no_reply"
				}
			}
			// An explicit UDP WSAEACCES is also conclusive. The silent-drop
			// alternative remains restricted to full-send + typed read timeout,
			// and both alternatives require zero owned origin receipts below.
			udpDenied := wanted == "bounded_no_reply" && result == "kernel_access_denied"
			if result != wanted && !udpDenied {
				t.Fatalf("%s %s %s: got %s want %s", stage, probes[i].Network, probes[i].Address, result, wanted)
			}
			owners[probes[i]].checkReceipt(t, probes[i], nonce)
		}
		receiptPhases++
		t.Logf("CORE31_WFP_PHASE_PASS mode=%s cases=%d", stage, len(seen))
	}
	expect("before", false)
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
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loopback, outside winipcfg.LUID
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			t.Fatal(err)
		}
		if iface.Flags&net.FlagLoopback != 0 {
			loopback = luid
		} else if outside == 0 {
			outside = luid
		}
	}
	if loopback == 0 || outside == 0 || loopback == outside {
		t.Fatal("real distinct loopback/nonloopback LUIDs required")
	}
	observer, err := openWFPEngine()
	if err != nil {
		t.Fatal("elevated WFP engine required; no skip", err)
	}
	defer closeWFPEngine(observer)
	before := core31WFPFilterIDs(t, observer)
	// Use a real distinct LUID, not zero/unspecified, as the nonmatching TUN.
	// All test packets are addressed to loopback; no interface is reconfigured.
	engine, err := blockLeaks(outside, block)
	if err != nil {
		t.Fatal("real WFP install failed", err)
	}
	defer func() {
		if engine != 0 {
			closeWFPEngine(engine)
		}
	}()
	loopbackIDs := core31WFPRequirePortFilters(t, core31WFPFilters(t, observer), before, selected, outside)
	expect("outside-TUN-loopback-permitted", false)
	// Fault control: remove just the four verified permits of this dynamic test
	// session to exercise the real port blocks without a physical network peer.
	// Production always keeps these loopback permits.
	deleteFilter := modfwpuclnt.NewProc("FwpmFilterDeleteById0")
	for _, id := range loopbackIDs {
		if err := fwpmResult(deleteFilter.Call(uintptr(engine), uintptr(id))); err != nil {
			t.Fatal("remove fixture-owned loopback permit", err)
		}
	}
	expect("without-test-loopback-permits-blocked", true)
	nonce := newNonce()
	register(nonce, false)
	for _, p := range probes {
		if got := core31WFPExchange(p, nonce); got != "exact_payload" {
			t.Fatal("Core application-ID exemption failed", p, got)
		}
		owners[p].checkReceipt(t, p, nonce)
	}
	receiptPhases++
	t.Log("CORE31_WFP_SELF_EXEMPT_PASS")
	closeWFPEngine(engine)
	engine = 0
	if after := core31WFPFilterIDs(t, observer); !reflect.DeepEqual(before, after) {
		t.Fatal("dynamic Core filters were not removed", len(before), len(after))
	}
	expect("after-close", false)
	engine, err = blockLeaks(loopback, block)
	if err != nil {
		t.Fatal(err)
	}
	core31WFPRequirePortFilters(t, core31WFPFilters(t, observer), before, selected, loopback)
	expect("through-TUN-interface-permitted", false)
	closeWFPEngine(engine)
	engine = 0
	if after := core31WFPFilterIDs(t, observer); !reflect.DeepEqual(before, after) {
		t.Fatal("through-TUN dynamic Core filters remained")
	}
	expect("final-recovery", false)
	if receiptPhases != 7 {
		t.Fatal("missing nonce-bound origin receipt phase")
	}
	t.Log("CORE31_WFP_FILTERS_PASS stages=2 blocks=16 tun_permits=4 loopback_permits=4")
	t.Log("CORE31_WFP_RECEIPTS_PASS phases=7 fault_control_selected_zero=true permitted_exact=true")
	t.Log("CORE31_WFP_CLEANUP_PASS filters_delta=0 ports=4")
}
