//go:build flutter_vless_vpn_routing

package XRay

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
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

// Actual public factory/global lifecycle, not a TUN or platform qualification.
// Handshake/framed marker protocol follows the optional Core routing fixture.
func TestNativeRoutingFactoryRuntime(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("native routing factory runtime is CI-only")
	}
	if RoutingCapability() != 1 || hasPublishedRuntime() {
		t.Fatal("optional factory unavailable or another runtime is active")
	}
	f := newRoutingFactoryFixture(t)
	var source, spec []byte
	var port int
	var held net.Conn
	var first *core.Instance
	var firstOwner routingRevoker
	stopped := false
	t.Run("authenticated-alias-default-and-private-guard", func(t *testing.T) {
		source, spec, port = f.start(t, "first")
		first, firstOwner = routingFactorySnapshot()
		held = f.connect(t, port, "alias.invalid", 443)
		f.clients = append(f.clients, held)
		f.exchange(t, held, "alias", "first-alias")
		f.request(t, port, "miss.invalid", 443, "default", "first-default")
		f.request(t, port, "198.18.0.2", 53, "guard", "first-guard")
	})
	t.Run("rejected-candidates-preserve-working-global-and-bytes", func(t *testing.T) {
		if held == nil || first == nil {
			t.Fatal("initial factory did not start")
		}
		beforeSource, beforeSpec := bytes.Clone(source), bytes.Clone(spec)
		var invalid map[string]any
		if err := json.Unmarshal(spec, &invalid); err != nil {
			t.Fatal(err)
		}
		invalid["source_sha256"] = strings.Repeat("0", 64)
		bad, _ := json.Marshal(invalid)
		if CheckRoutingPrivate(source, bad) != 17 || CheckRoutingPrivate(source, spec) != 0 {
			t.Fatal("invalid/valid preflight result changed")
		}
		if StartRoutingPrivate(source, bad, nil) == nil || StartRoutingPrivate(source, spec, nil) == nil {
			t.Fatal("active session replacement was accepted")
		}
		actual, owner := routingFactorySnapshot()
		if actual != first || owner != firstOwner || !bytes.Equal(source, beforeSource) || !bytes.Equal(spec, beforeSpec) {
			t.Fatal("candidate check/start changed the working owner or input bytes")
		}
		f.exchange(t, held, "alias", "after-refusal-held")
		f.request(t, port, "miss.invalid", 443, "default", "after-refusal-fresh")
	})
	t.Run("stop-revokes-private-and-clears-global", func(t *testing.T) {
		if held == nil {
			t.Fatal("initial private control unavailable")
		}
		until := time.Now().Add(2 * time.Second)
		_ = held.SetDeadline(until)
		f.exchange(t, held, "alias", "before-stop-held")
		if !f.stop(until) {
			t.Fatal("Stop exceeded shared deadline")
		}
		actual, owner := routingFactorySnapshot()
		if actual != nil || owner != nil {
			t.Fatal("Stop retained published runtime/owner")
		}
		_ = held.SetReadDeadline(until)
		var b [1]byte
		n, err := held.Read(b[:])
		var failure net.Error
		if n != 0 || err == nil || errors.As(err, &failure) && failure.Timeout() || !routingFactoryClosed(err) {
			t.Fatal("Stop did not explicitly close the private control")
		}
		if !time.Now().Before(until) {
			t.Fatal("Stop/closure exceeded shared deadline")
		}
		stopped = true
	})
	t.Run("restart-fresh-spec-and-owner", func(t *testing.T) {
		if !stopped {
			t.Fatal("prior Stop/closure did not complete")
		}
		if actual, owner := routingFactorySnapshot(); actual != nil || owner != nil {
			t.Fatal("prior Stop incomplete")
		}
		freshSource, freshSpec, freshPort := f.start(t, "second")
		actual, owner := routingFactorySnapshot()
		if actual == nil || actual == first || owner == nil || owner == firstOwner || bytes.Equal(freshSource, source) || bytes.Equal(freshSpec, spec) {
			t.Fatal("restart reused old owner or prepared source/spec")
		}
		f.request(t, freshPort, "alias.invalid", 443, "alias", "restart-alias")
		f.request(t, freshPort, "miss.invalid", 443, "default", "restart-default")
		f.request(t, freshPort, "198.18.0.2", 53, "guard", "restart-guard")
		if !f.stop(time.Now().Add(2 * time.Second)) {
			t.Fatal("restart Stop deadline")
		}
	})
}

type routingFactoryOrigin struct {
	listener net.Listener
	mu       sync.Mutex
	closed   bool
	active   map[net.Conn]bool
	seen     map[string]int
	invalid  int
	wg       sync.WaitGroup
}
type routingFactoryFixture struct {
	t                     *testing.T
	nonce, user, password string
	origins               map[string]*routingFactoryOrigin
	expected              map[string]map[string]int
	clients               []net.Conn
	instance              *core.Instance
	owner                 routingRevoker
	stopping              chan struct{}
}

func routingFactorySnapshot() (*core.Instance, routingRevoker) {
	coreState.RLock()
	defer coreState.RUnlock()
	return coreInstance, coreRoutingOwner
}
func newRoutingFactoryFixture(t *testing.T) *routingFactoryFixture {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	f := &routingFactoryFixture{t: t, nonce: hex.EncodeToString(nonce[:]), origins: map[string]*routingFactoryOrigin{}, expected: map[string]map[string]int{}}
	var attempts atomic.Int64
	previous, previousCore := net.DefaultResolver, xnet.DefaultResolver
	trap := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("factory fixture forbids OS resolver")
	}}
	net.DefaultResolver, xnet.DefaultResolver = trap, trap
	t.Cleanup(func() {
		until := time.Now().Add(3 * time.Second)
		clean := f.stop(until)
		if !clean {
			t.Error("factory Core/owner did not drain")
		}
		for _, c := range f.clients {
			_ = c.Close()
		}
		for name, origin := range f.origins {
			origin.mu.Lock()
			origin.closed = true
			active := make([]net.Conn, 0, len(origin.active))
			for c := range origin.active {
				active = append(active, c)
			}
			origin.mu.Unlock()
			_ = origin.listener.Close()
			for _, c := range active {
				_ = c.Close()
			}
			done := make(chan struct{})
			go func() { origin.wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Until(until)):
				clean = false
				t.Error("marker workers did not drain")
			}
			origin.mu.Lock()
			exact := reflect.DeepEqual(origin.seen, f.expected[name]) && origin.invalid == 0
			origin.mu.Unlock()
			if !exact {
				clean = false
				t.Errorf("marker ledger mismatch for %s", name)
			}
		}
		net.DefaultResolver, xnet.DefaultResolver = previous, previousCore
		if attempts.Load() != 0 {
			clean = false
			t.Error("factory attempted OS resolver")
		}
		if instance, owner := routingFactorySnapshot(); instance != nil || owner != nil {
			clean = false
			t.Error("factory global not empty after cleanup")
		}
		if !time.Now().Before(until) {
			clean = false
			t.Error("factory cleanup exceeded shared deadline")
		}
		if clean {
			t.Log("factory cleanup: Core/owner empty; private controls/listeners/marker workers drained; OS resolver attempts=0")
		}
	})
	for _, name := range []string{"alias", "default", "guard"} {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		o := &routingFactoryOrigin{listener: l, active: map[net.Conn]bool{}, seen: map[string]int{}}
		f.origins[name], f.expected[name] = o, map[string]int{}
		o.wg.Add(1)
		go func(name string, o *routingFactoryOrigin) {
			defer o.wg.Done()
			for {
				c, err := o.listener.Accept()
				if err != nil {
					return
				}
				o.mu.Lock()
				if o.closed {
					o.mu.Unlock()
					_ = c.Close()
					return
				}
				o.active[c] = true
				o.wg.Add(1)
				o.mu.Unlock()
				go func() {
					defer o.wg.Done()
					defer c.Close()
					defer func() { o.mu.Lock(); delete(o.active, c); o.mu.Unlock() }()
					for {
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						payload, err := routingFactoryFrame(c)
						if err != nil {
							return
						}
						o.mu.Lock()
						valid := bytes.HasPrefix(payload, []byte(f.nonce+"/"))
						if valid {
							o.seen[string(payload)]++
						} else {
							o.invalid++
						}
						o.mu.Unlock()
						if !valid || routingFactoryWrite(c, append([]byte(name+"|"), payload...)) != nil {
							return
						}
					}
				}()
			}
		}(name, o)
	}
	return f
}

func (f *routingFactoryFixture) stop(until time.Time) bool {
	if f.stopping == nil {
		instance, owner := routingFactorySnapshot()
		if instance == nil && owner == nil {
			return true
		}
		if instance != f.instance || owner != f.owner {
			f.t.Error("refusing to stop foreign factory runtime")
			return false
		}
		f.stopping = make(chan struct{})
		go func() { Stop(); close(f.stopping) }()
	}
	select {
	case <-f.stopping:
		return time.Now().Before(until)
	case <-time.After(time.Until(until)):
		return false
	}
}

func (f *routingFactoryFixture) start(t *testing.T, generation string) ([]byte, []byte, int) {
	t.Helper()
	reserve := func() net.Listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	private, caller := reserve(), reserve()
	port := private.Addr().(*net.TCPAddr).Port
	f.user, f.password = "factory-"+generation, "synthetic-"+f.nonce+generation
	input := func(tag string, port int, settings map[string]any) any {
		return map[string]any{"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": settings}
	}
	outbounds := []any{map[string]any{"tag": "blocked", "protocol": "blackhole"}}
	for _, name := range []string{"alias", "default", "guard"} {
		outbounds = append(outbounds, map[string]any{"tag": name, "protocol": "freedom", "settings": map[string]any{"redirect": f.origins[name].listener.Addr().String()}})
	}
	config := map[string]any{"log": map[string]any{"loglevel": "none"}, "dns": map[string]any{"queryStrategy": "UseIPv4", "hosts": map[string]any{"alias.invalid": "192.0.2.1", "miss.invalid": "192.0.2.2"}},
		"inbounds": []any{input("managed", port, map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": f.user, "pass": f.password}}}), input("caller", caller.Addr().(*net.TCPAddr).Port, map[string]any{"auth": "noauth"})}, "outbounds": outbounds,
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"managed"}, "ip": []string{"198.18.0.2/32"}, "port": "53", "outboundTag": "guard"},
			map[string]any{"type": "field", "inboundTag": []string{"caller"}, "domain": []string{"full:alias.invalid"}, "outboundTag": "alias"},
			map[string]any{"type": "field", "inboundTag": []string{"caller"}, "ip": []string{"198.18.0.2/32"}, "port": "53", "outboundTag": "blocked"}}}}
	source, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(source)
	spec, err := json.Marshal(map[string]any{"version": 1, "source_sha256": hex.EncodeToString(digest[:]), "managed_inbound_index": 0, "managed_inbound_tag": "managed", "auth_user": f.user, "source_inbound_index": 1, "default_outbound_tag": "default", "guard_rule_indices": []int{0}})
	if err != nil {
		t.Fatal(err)
	}
	beforeSource, beforeSpec := bytes.Clone(source), bytes.Clone(spec)
	if CheckRoutingPrivate(source, spec) != 0 {
		t.Fatal("valid reserved-port candidate failed preflight")
	}
	_ = private.Close()
	_ = caller.Close()
	if err := StartRoutingPrivate(source, spec, nil); err != nil {
		t.Fatal("factory start failed", err)
	}
	f.instance, f.owner = routingFactorySnapshot()
	f.stopping = nil
	if f.instance == nil || f.owner == nil || !bytes.Equal(source, beforeSource) || !bytes.Equal(spec, beforeSpec) {
		t.Fatal("factory did not publish intact candidate")
	}
	return source, spec, port
}

func (f *routingFactoryFixture) connect(t *testing.T, port int, host string, targetPort int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	failed := true
	defer func() {
		if failed {
			_ = c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	exchange := func(request, expected []byte) {
		t.Helper()
		if _, err := c.Write(request); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(expected))
		if _, err := io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, expected) {
			t.Fatal("private SOCKS reply mismatch", err)
		}
	}
	exchange([]byte{5, 1, 2}, []byte{5, 2})
	auth := append([]byte{1, byte(len(f.user))}, f.user...)
	auth = append(auth, byte(len(f.password)))
	auth = append(auth, f.password...)
	exchange(auth, []byte{1, 0})
	address := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		address = append([]byte{5, 1, 0, 1}, ip.To4()...)
	}
	address = binary.BigEndian.AppendUint16(address, uint16(targetPort))
	if _, err := c.Write(address); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		t.Fatal("private SOCKS CONNECT mismatch", err)
	}
	failed = false
	return c
}
func (f *routingFactoryFixture) request(t *testing.T, port int, host string, targetPort int, marker, label string) {
	t.Helper()
	c := f.connect(t, port, host, targetPort)
	defer c.Close()
	f.exchange(t, c, marker, label)
}
func (f *routingFactoryFixture) exchange(t *testing.T, c net.Conn, marker, label string) {
	t.Helper()
	payload := []byte(f.nonce + "/" + label)
	if err := routingFactoryWrite(c, payload); err != nil {
		t.Fatal(err)
	}
	answer, err := routingFactoryFrame(c)
	if err != nil || !bytes.Equal(answer, append([]byte(marker+"|"), payload...)) {
		t.Fatal("factory marker bytes mismatch", err)
	}
	f.expected[marker][string(payload)]++
}
func routingFactoryWrite(w io.Writer, payload []byte) error {
	_, err := io.Copy(w, bytes.NewReader(binary.BigEndian.AppendUint16(nil, uint16(len(payload)))))
	if err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(payload))
	return err
}
func routingFactoryFrame(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > 256 {
		return nil, errors.New("invalid marker frame")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func routingFactoryClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(10053)) || errors.Is(err, syscall.Errno(10054)))
}
