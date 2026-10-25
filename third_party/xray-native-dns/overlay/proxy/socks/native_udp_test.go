package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

type nativeUDPFactory struct {
	calls int
	peer  netip.AddrPort
	ctx   context.Context
}

func (*nativeUDPFactory) BindInput(context.Context, any, any, any, routing.Dispatcher) (routing.Dispatcher, error) {
	return nil, routing.ErrNativeInput
}
func (*nativeUDPFactory) BeginInput(context.Context, any, any, any, net.Conn) (context.Context, func(), error) {
	return nil, nil, routing.ErrNativeInput
}
func (f *nativeUDPFactory) AuthorizeUDPAssociation(ctx context.Context, peer netip.AddrPort) error {
	f.calls++
	f.ctx = ctx
	f.peer = peer
	return nil
}

func TestNativeUDPAuthorizationScopePresenceAndExactContext(t *testing.T) {
	if authorizeNativeUDP(context.Background(), xnet.AnyIP, 0) != nil {
		t.Fatal("legacy UDP changed")
	}
	for _, factory := range []routing.NativeInputFactory{nil, (*nativeUDPFactory)(nil)} {
		if authorizeNativeUDP(routing.ContextWithNativeInputFactory(context.Background(), factory), xnet.LocalHostIP, 12345) == nil {
			t.Fatal("unusable native scope fell back to legacy")
		}
	}
	f := &nativeUDPFactory{}
	ctx := routing.ContextWithNativeInputFactory(context.Background(), f)
	if authorizeNativeUDP(ctx, xnet.LocalHostIP, 12345) != nil || f.calls != 1 || f.ctx != ctx || f.peer != netip.MustParseAddrPort("127.0.0.1:12345") {
		t.Fatal("association lost exact context/tuple")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if authorizeNativeUDP(cancelled, xnet.LocalHostIP, 12345) == nil || f.calls != 1 {
		t.Fatal("cancelled scope reached authorizer")
	}
}

type nativeUDPControl struct {
	bytes.Buffer
	closes int
}

func (*nativeUDPControl) Read([]byte) (int, error) { return 0, io.EOF }
func (c *nativeUDPControl) Close() error           { c.closes++; return nil }
func (*nativeUDPControl) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (*nativeUDPControl) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}
}
func (*nativeUDPControl) SetDeadline(time.Time) error      { return nil }
func (*nativeUDPControl) SetReadDeadline(time.Time) error  { return nil }
func (*nativeUDPControl) SetWriteDeadline(time.Time) error { return nil }

func TestNativeUDPAuthorizationAfterPasswordBeforeListener(t *testing.T) {
	for _, valid := range []bool{false, true} {
		calls := 0
		s := &ServerSession{config: &ServerConfig{AuthType: AuthType_PASSWORD, Accounts: map[string]string{"u": "p"}, UdpEnabled: true}, authorizeUDP: func(address xnet.Address, port xnet.Port) error {
			calls++
			if address.String() != "127.0.0.1" || port != 34567 {
				t.Fatal("wrong tuple")
			}
			return routing.ErrNativeInput
		}}
		password := byte('x')
		if valid {
			password = 'p'
		}
		wire := []byte{5, 1, 2, 1, 1, 'u', 1, password, 5, 3, 0, 1, 127, 0, 0, 1, 0x87, 0x07}
		conn := &nativeUDPControl{}
		_, udp, err := s.Handshake(bytes.NewReader(wire), conn)
		if err == nil || udp != nil {
			t.Fatal("denied association created UDP listener")
		}
		if valid && (calls != 1 || !errors.Is(err, routing.ErrNativeInput)) || !valid && calls != 0 {
			t.Fatal("UDP grant did not follow successful password authentication")
		}
	}
}

type nativeUDPFakePacket struct {
	sources []*net.UDPAddr
	closes  int
	last    net.Addr
}

func (p *nativeUDPFakePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(p.sources) == 0 {
		return 0, nil, io.EOF
	}
	source := p.sources[0]
	p.sources = p.sources[1:]
	b[0] = byte(source.Port)
	return 1, source, nil
}
func (p *nativeUDPFakePacket) WriteTo(b []byte, a net.Addr) (int, error) {
	p.last = a
	return len(b), nil
}
func (p *nativeUDPFakePacket) Close() error { p.closes++; return nil }
func (*nativeUDPFakePacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (*nativeUDPFakePacket) SetDeadline(time.Time) error      { return nil }
func (*nativeUDPFakePacket) SetReadDeadline(time.Time) error  { return nil }
func (*nativeUDPFakePacket) SetWriteDeadline(time.Time) error { return nil }

func TestNativeUDPFixedPeerRejectsWrongIPAndWrongPortFirst(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 34567}
	packet := &nativeUDPFakePacket{sources: []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 2), Port: 34567}, {IP: net.IPv4(127, 0, 0, 1), Port: 34568}, peer}}
	conn := NewTempUDPConn(packet, &nativeUDPControl{}, peer)
	conn.SetTimeout(time.Second)
	defer conn.Close()
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 1 || err != nil || b[0] != byte(34567%256) || conn.ExpectedRemote.Load() != peer {
		t.Fatal("wrong datagram rewrote fixed peer", err)
	}
	if _, err := conn.Write([]byte{1}); err != nil || packet.last != peer {
		t.Fatal("reply did not retain exact fixed peer")
	}
}

func TestNativeUDPEarlyHandshakeCloseNeedsNoTimer(t *testing.T) {
	packet := &nativeUDPFakePacket{}
	control := &nativeUDPControl{}
	conn := NewTempUDPConn(packet, control, &net.UDPAddr{})
	if err := conn.Close(); err != nil || packet.closes != 1 || control.closes != 1 {
		t.Fatal("early cleanup did not close owned sockets")
	}
	if err := conn.Close(); err != nil || packet.closes != 1 || control.closes != 1 {
		t.Fatal("second cleanup closed owned sockets again")
	}
}

func TestNativeUDPPartialCloseWithoutTimerIsIdempotent(t *testing.T) {
	packet := &nativeUDPFakePacket{}
	control := &nativeUDPControl{}
	conn := &TempUDPConn{PacketConn: packet, AssociatedTCPConn: control}
	if err := conn.Close(); err != nil || packet.closes != 1 || control.closes != 1 {
		t.Fatal("partial cleanup did not close owned sockets")
	}
	if err := conn.Close(); err != nil || packet.closes != 1 || control.closes != 1 {
		t.Fatal("second partial cleanup closed owned sockets again")
	}
}
