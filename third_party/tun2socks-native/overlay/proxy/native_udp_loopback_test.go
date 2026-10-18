package proxy

// Synthetic SOCKS/UDP loopback peers only. These tests never import/start the
// forwarder engine, Core, TUN, devices, routes, or system network configuration.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

type nativeLoopSOCKS struct {
	listener   net.Listener
	mu         sync.Mutex
	connection net.Conn
	closed     bool
	done       chan error
	observed   bool
}

func newNativeLoopSOCKS(t *testing.T, script func(net.Conn) error) *nativeLoopSOCKS {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("synthetic SOCKS listener failed", err)
	}
	server := &nativeLoopSOCKS{listener: listener, done: make(chan error, 1)}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			server.done <- err
			return
		}
		server.mu.Lock()
		server.connection = conn
		closed := server.closed
		server.mu.Unlock()
		defer conn.Close()
		if closed {
			server.done <- net.ErrClosed
			return
		}
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
		err = script(conn)
		_ = conn.Close() // EOF is committed before the script completion evidence.
		server.done <- err
	}()
	t.Cleanup(func() {
		server.close()
		if !server.observed {
			select {
			case <-server.done:
				server.observed = true
			case <-time.After(time.Second):
				t.Error("owned SOCKS worker survived cleanup")
			}
		}
	})
	return server
}

func (s *nativeLoopSOCKS) close() {
	s.mu.Lock()
	s.closed = true
	conn := s.connection
	s.mu.Unlock()
	_ = s.listener.Close()
	if conn != nil {
		_ = conn.Close()
	}
}
func (s *nativeLoopSOCKS) await(t *testing.T) {
	t.Helper()
	select {
	case err := <-s.done:
		s.observed = true
		if err != nil {
			t.Fatal("synthetic SOCKS script failed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned SOCKS script did not end")
	}
}

type nativeUDPResult struct {
	connection net.PacketConn
	err        error
}

func nativeLoopClient(t *testing.T, server *nativeLoopSOCKS) func(time.Duration) nativeUDPResult {
	t.Helper()
	ss := &Socks5{Base: &Base{addr: server.listener.Addr().String()}, user: "fixture-user", pass: "fixture-password"}
	done := make(chan nativeUDPResult, 1)
	go func() { conn, err := nativeBoundUDP(ss); done <- nativeUDPResult{conn, err} }()
	var result nativeUDPResult
	observed := false
	t.Cleanup(func() {
		server.close()
		if !observed {
			select {
			case result = <-done:
				observed = true
			case <-time.After(time.Second):
				t.Error("owned native UDP handshake survived cleanup")
			}
		}
		if result.connection != nil {
			_ = result.connection.Close()
		}
	})
	return func(bound time.Duration) nativeUDPResult {
		t.Helper()
		select {
		case result = <-done:
			observed = true
			return result
		case <-time.After(bound):
			t.Fatal("native UDP handshake exceeded bounded wait")
		}
		return nativeUDPResult{}
	}
}

func nativeReadExact(conn net.Conn, expected []byte) error {
	data := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, data); err != nil {
		return err
	}
	if !bytes.Equal(data, expected) {
		return errors.New("unexpected synthetic SOCKS bytes")
	}
	return nil
}
func nativeSOCKSAuth(conn net.Conn) error {
	if err := nativeReadExact(conn, []byte{5, 1, 2}); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return err
	}
	expected := append([]byte{1, byte(len("fixture-user"))}, []byte("fixture-user")...)
	expected = append(expected, byte(len("fixture-password")))
	expected = append(expected, []byte("fixture-password")...)
	if err := nativeReadExact(conn, expected); err != nil {
		return err
	}
	_, err := conn.Write([]byte{1, 0})
	return err
}
func nativeDeclaredPeer(conn net.Conn) (*net.UDPAddr, error) {
	var request [10]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(request[:8], []byte{5, 3, 0, 1, 127, 0, 0, 1}) {
		return nil, errors.New("UDP request did not declare literal loopback peer")
	}
	port := int(binary.BigEndian.Uint16(request[8:]))
	if port == 0 {
		return nil, errors.New("UDP source was not bound before handshake")
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	probe, err := net.ListenUDP("udp4", peer)
	if err == nil {
		_ = probe.Close()
		return nil, errors.New("declared UDP tuple was not already exclusively occupied")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, errors.New("declared UDP occupancy failed for unrelated reason")
	}
	return peer, nil
}
func nativeRelayReply(conn net.Conn, relay *net.UDPAddr, version, reserved, status byte) error {
	packet := []byte{version, status, reserved, 1, 127, 0, 0, 1}
	packet = binary.BigEndian.AppendUint16(packet, uint16(relay.Port))
	_, err := conn.Write(packet)
	return err
}
func nativeRequireControlEnd(conn net.Conn) error {
	var b [1]byte
	_, err := conn.Read(b[:])
	// An invalid reply may leave unread reply bytes, so an explicit client close
	// can arrive as TCP reset instead of FIN. Both prove closure; timeout cannot.
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		return errors.New("native client did not close rejected control")
	}
	return nil
}
func nativeRequireUDPReleased(t *testing.T, peer *net.UDPAddr) {
	t.Helper()
	if peer == nil {
		t.Fatal("missing declared tuple release evidence")
	}
	packet, err := net.ListenUDP("udp4", peer)
	if err != nil {
		t.Fatal("owned UDP socket remained bound after cleanup", err)
	}
	_ = packet.Close()
}
func nativeLoopRelay(t *testing.T) *net.UDPConn {
	t.Helper()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("synthetic UDP relay failed", err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	return relay
}

func TestNativeUDPClientLoopbackBoundAuthenticatedAndControlEOF(t *testing.T) {
	relay := nativeLoopRelay(t)
	declared := make(chan *net.UDPAddr, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	server := newNativeLoopSOCKS(t, func(control net.Conn) error {
		if err := nativeSOCKSAuth(control); err != nil {
			return err
		}
		peer, err := nativeDeclaredPeer(control)
		if err != nil {
			return err
		}
		declared <- peer
		if err := nativeRelayReply(control, relay.LocalAddr().(*net.UDPAddr), 5, 0, 0); err != nil {
			return err
		}
		select {
		case <-release:
			return nil
		case <-time.After(3 * time.Second):
			return errors.New("synthetic release was not observed")
		}
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	result := nativeLoopClient(t, server)(2 * time.Second)
	if result.err != nil || result.connection == nil {
		t.Fatal("authenticated bound UDP client failed", result.err)
	}
	peer := <-declared
	if !nativeSameUDPSource(result.connection.LocalAddr(), peer) {
		t.Fatal("client socket differs from its authenticated declaration")
	}
	_ = relay.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := result.connection.WriteTo([]byte("actual-numeric-request"), &net.UDPAddr{IP: net.IPv4(198, 18, 0, 53), Port: 53}); err != nil {
		t.Fatal(err)
	}
	var packet [512]byte
	n, source, err := relay.ReadFromUDP(packet[:])
	if err != nil || !nativeSameUDPSource(source, peer) {
		t.Fatal("UDP bytes did not originate from declared tuple", err)
	}
	address, payload, err := socks5.DecodeUDPPacket(packet[:n])
	if err != nil || address.String() != "198.18.0.53:53" || string(payload) != "actual-numeric-request" {
		t.Fatal("actual numeric UDP bytes changed")
	}
	releaseOnce.Do(func() { close(release) })
	server.await(t)
	_ = result.connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := result.connection.ReadFrom(packet[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatal("server control EOF did not close native UDP socket", err)
	}
	nativeRequireUDPReleased(t, peer)
}

func TestNativeUDPClientLoopbackDropsForeignFirstResponse(t *testing.T) {
	relay, foreign := nativeLoopRelay(t), nativeLoopRelay(t)
	declared := make(chan *net.UDPAddr, 1)
	server := newNativeLoopSOCKS(t, func(control net.Conn) error {
		if err := nativeSOCKSAuth(control); err != nil {
			return err
		}
		peer, err := nativeDeclaredPeer(control)
		if err != nil {
			return err
		}
		declared <- peer
		if err := nativeRelayReply(control, relay.LocalAddr().(*net.UDPAddr), 5, 0, 0); err != nil {
			return err
		}
		return nativeRequireControlEnd(control)
	})
	result := nativeLoopClient(t, server)(2 * time.Second)
	if result.err != nil || result.connection == nil {
		t.Fatal("synthetic association failed", result.err)
	}
	peer := <-declared
	_ = result.connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	type response struct {
		data    string
		address net.Addr
		err     error
	}
	read := make(chan response, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		var b [512]byte
		n, a, err := result.connection.ReadFrom(b[:])
		read <- response{string(b[:n]), a, err}
	}()
	t.Cleanup(func() {
		_ = result.connection.Close()
		select {
		case <-readDone:
		case <-time.After(time.Second):
			t.Error("owned UDP read survived cleanup")
		}
	})
	wrong, _ := socks5.EncodeUDPPacket(socks5.Addr{1, 198, 18, 0, 53, 0, 53}, []byte("foreign-first"))
	if _, err := foreign.WriteToUDP(wrong, peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-read:
		t.Fatal("foreign relay source was accepted before legitimate response")
	case <-time.After(30 * time.Millisecond):
	}
	legitimate, _ := socks5.EncodeUDPPacket(socks5.Addr{1, 198, 18, 0, 53, 0, 53}, []byte("legitimate-response"))
	if _, err := relay.WriteToUDP(legitimate, peer); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-read:
		if response.err != nil || response.data != "legitimate-response" || response.address.String() != "198.18.0.53:53" {
			t.Fatal("legitimate fixed-relay response failed", response.err)
		}
	case <-time.After(time.Second):
		t.Fatal("fixed relay response was not received")
	}
	_ = result.connection.Close()
	server.await(t)
	nativeRequireUDPReleased(t, peer)
}

func TestNativeUDPClientLoopbackRejectedReplyReleasesSockets(t *testing.T) {
	relay := nativeLoopRelay(t)
	for _, kind := range []string{"method-downgrade", "method-version", "auth-version", "auth-rejected", "reply-version", "reply-reserved", "reply-rejected"} {
		t.Run(kind, func(t *testing.T) {
			declared := make(chan *net.UDPAddr, 1)
			server := newNativeLoopSOCKS(t, func(control net.Conn) error {
				if kind == "method-downgrade" || kind == "method-version" {
					if err := nativeReadExact(control, []byte{5, 1, 2}); err != nil {
						return err
					}
					reply := []byte{5, 0}
					if kind == "method-version" {
						reply = []byte{4, 2}
					}
					if _, err := control.Write(reply); err != nil {
						return err
					}
					return nativeRequireControlEnd(control)
				}
				if kind == "auth-version" || kind == "auth-rejected" {
					if err := nativeReadExact(control, []byte{5, 1, 2}); err != nil {
						return err
					}
					if _, err := control.Write([]byte{5, 2}); err != nil {
						return err
					}
					expected := append([]byte{1, 12}, []byte("fixture-user")...)
					expected = append(expected, 16)
					expected = append(expected, []byte("fixture-password")...)
					if err := nativeReadExact(control, expected); err != nil {
						return err
					}
					reply := []byte{2, 0}
					if kind == "auth-rejected" {
						reply = []byte{1, 1}
					}
					if _, err := control.Write(reply); err != nil {
						return err
					}
					return nativeRequireControlEnd(control)
				}
				if err := nativeSOCKSAuth(control); err != nil {
					return err
				}
				peer, err := nativeDeclaredPeer(control)
				if err != nil {
					return err
				}
				declared <- peer
				version, reserved, status := byte(5), byte(0), byte(0)
				switch kind {
				case "reply-version":
					version = 4
				case "reply-reserved":
					reserved = 1
				case "reply-rejected":
					status = 1
				}
				if err := nativeRelayReply(control, relay.LocalAddr().(*net.UDPAddr), version, reserved, status); err != nil {
					return err
				}
				return nativeRequireControlEnd(control)
			})
			result := nativeLoopClient(t, server)(2 * time.Second)
			if result.connection != nil || !errors.Is(result.err, errNativeUDP) {
				t.Fatal("invalid authenticated SOCKS reply admitted")
			}
			server.await(t)
			select {
			case peer := <-declared:
				nativeRequireUDPReleased(t, peer)
			default:
			}
		})
	}
}

func TestNativeUDPClientLoopbackStalledHandshakeBoundedAndDrained(t *testing.T) {
	declared := make(chan *net.UDPAddr, 1)
	server := newNativeLoopSOCKS(t, func(control net.Conn) error {
		if err := nativeSOCKSAuth(control); err != nil {
			return err
		}
		peer, err := nativeDeclaredPeer(control)
		if err != nil {
			return err
		}
		declared <- peer
		// No reply: only the client's own three-second handshake deadline can
		// close this control. The fixture's six-second socket bound is later.
		return nativeRequireControlEnd(control)
	})
	started := time.Now()
	result := nativeLoopClient(t, server)(4500 * time.Millisecond)
	if result.connection != nil || !errors.Is(result.err, errNativeUDP) {
		t.Fatal("stalled handshake succeeded")
	}
	if elapsed := time.Since(started); elapsed < 2500*time.Millisecond || elapsed > 4*time.Second {
		t.Fatal("handshake did not use its own bounded deadline", elapsed)
	}
	server.await(t)
	select {
	case peer := <-declared:
		nativeRequireUDPReleased(t, peer)
	default:
		t.Fatal("stall did not reach a bound UDP declaration")
	}
}
