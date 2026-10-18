package native_dns_context_runtime_test

// This extends TestAcceptanceNativeDNSLauncher, so the exact selected parent
// PASS requires this real child policy/managed-input proof too. CI ONLY.
import (
	"bytes"
	wirebinary "encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const launcherPrivateEpoch = "0123456789abcdef0123456789abcdef"

func launcherPrivateArguments(command, path, resolver, policyPath, epoch string) []string {
	return append(launcherArguments(command, path, resolver), "--private-policy", policyPath, "--policy-epoch", epoch)
}

func testLauncherPrivateManagedPolicy(t *testing.T, binary string) {
	t.Helper()
	dns := newLoopServer(t, "tcp4", "127.0.0.1:0", localDefaultDNS("127.0.0.1", nil, nil))
	path, sourcePort, digest, original := launcherDocument(t)
	ports := managedPorts(t, 2)
	port := ports[0]
	if port == sourcePort {
		port = ports[1]
	}
	policy := map[string]any{"schema": 1, "capability": nativeLauncherCapability, "source_digest": digest, "epoch": launcherPrivateEpoch,
		"virtual_ipv4": "198.18.0.53", "listen": netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)).String(), "username": "native-user", "password": "native-password"}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal("private fixture encode")
	}
	policyPath := filepath.Join(t.TempDir(), "native-private-policy.json")
	writeLauncherPrivatePolicy(t, policyPath, data)
	args := launcherPrivateArguments("check", path, dns.listener.Addr().String(), policyPath, launcherPrivateEpoch)
	checked := launcherOnce(t, binary, args, "prepared")
	if checked.SourceDigest != digest || checked.PolicyEpoch != launcherPrivateEpoch || dns.activity() != 0 {
		t.Fatal("private preparation lost binding or performed DNS")
	}
	child := startLauncherCommand(t, binary, launcherPrivateArguments("run", path, dns.listener.Addr().String(), policyPath, launcherPrivateEpoch), digest, launcherPrivateEpoch)
	beforeCandidates := dns.activity()
	for _, command := range []string{"check", "run"} {
		bad := make(map[string]any, len(policy))
		for key, value := range policy {
			bad[key] = value
		}
		bad["source_digest"] = strings.Repeat("0", 64)
		badData, _ := json.Marshal(bad)
		badPath := filepath.Join(t.TempDir(), "wrong-source-policy.json")
		writeLauncherPrivatePolicy(t, badPath, badData)
		for _, rejected := range [][]string{launcherPrivateArguments(command, path, dns.listener.Addr().String(), badPath, launcherPrivateEpoch), launcherPrivateArguments(command, path, dns.listener.Addr().String(), policyPath, strings.Repeat("f", 32))} {
			result := launcherOnce(t, binary, rejected, "failed")
			if result.Stage != "private-policy" || result.SourceDigest != "" || result.PolicyEpoch != "" {
				t.Fatal("private binding rejection was not closed")
			}
			if dns.activity() != beforeCandidates {
				t.Fatal("rejected private candidate performed DNS")
			}
		}
	}
	if connection, err := managedAuth(port, "private-wrong-user", "private-wrong-password"); err == nil {
		_ = connection.Close()
		t.Fatal("managed child admitted wrong credentials")
	}
	if dns.activity() != beforeCandidates {
		t.Fatal("failed authentication entered private DNS")
	}
	before := dns.activity()
	managedTCPDNS(t, port, "static.invalid.", "127.0.0.1")
	if dns.activity() != before {
		t.Fatal("managed child lost source static hosts")
	}
	managedTCPDNS(t, port, "default.invalid.", "127.0.0.1")
	if dns.activity() != before+1 {
		t.Fatal("managed child did not use retained caller DNS")
	}
	// This same authenticated CONNECT transfers a real DNS reply, then remains
	// in the managed frame loop with its handshake deadline already cleared.
	control, _ := managedConnect(t, port, "native-user", "native-password", 1, netip.MustParseAddrPort("198.18.0.53:53"))
	defer control.Close()
	query := managedDNSPacket(t, 0x3811, "static.invalid.")
	if wirebinary.Write(control, wirebinary.BigEndian, uint16(len(query))) != nil {
		t.Fatal("held managed frame header failed")
	}
	if _, err := control.Write(query); err != nil {
		t.Fatal("held managed frame write failed")
	}
	var responseSize uint16
	if wirebinary.Read(control, wirebinary.BigEndian, &responseSize) != nil || responseSize == 0 || responseSize > 4096 {
		t.Fatal("held managed frame reply missing")
	}
	reply := make([]byte, responseSize)
	if _, err := io.ReadFull(control, reply); err != nil {
		t.Fatal("held managed frame read failed")
	}
	managedDNSResponse(t, reply, 0x3811, "127.0.0.1")
	deadline := time.Now().Add(2 * time.Second)
	if child.input.Close() != nil {
		t.Fatal("private parent EOF failed")
	}
	child.awaitStop(t, deadline)
	_ = control.SetReadDeadline(deadline)
	var one [1]byte
	if _, err := control.Read(one[:]); !errors.Is(err, io.EOF) || !time.Now().Before(deadline) {
		t.Fatal("private native input survived clean child EOF/stop")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatal("private policy mutated caller JSON")
	}
	actualPolicy, err := os.ReadFile(policyPath)
	if err != nil || !bytes.Equal(actualPolicy, data) {
		t.Fatal("private policy file was rewritten")
	}
	if _, failures := dns.observations(); len(failures) != 0 {
		t.Fatal("private child fixture protocol failure")
	}
	t.Log("PHASE private policy: exact source/session binding, caller root DNS via managed TCP, invalid candidates inert, parent EOF closed input and child output")
}
