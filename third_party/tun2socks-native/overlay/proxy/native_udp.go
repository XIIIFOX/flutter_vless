package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/dialer"
	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

var errNativeUDP = errors.New("private UDP association unavailable")

func nativeSameUDPSource(source, expected net.Addr) bool {
	a, ok := source.(*net.UDPAddr)
	b, other := expected.(*net.UDPAddr)
	return ok && other && a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP) && a.Zone == b.Zone
}

// Android development entry only: no wildcard/first-packet grant, DNS lookup,
// reuse socket options, Unix proxy, or unbounded password handshake.
func nativeBoundUDP(ss *Socks5) (_ net.PacketConn, err error) {
	remote, parseErr := netip.ParseAddrPort(ss.Addr())
	if parseErr != nil || remote.Addr() != netip.MustParseAddr("127.0.0.1") || remote.Port() == 0 || ss.unix || len(ss.user) == 0 || len(ss.pass) == 0 {
		return nil, errNativeUDP
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	control, err := dialer.DialContext(ctx, "tcp4", ss.Addr())
	if err != nil {
		return nil, errNativeUDP
	}
	var packet net.PacketConn
	defer func() {
		if err != nil {
			_ = control.Close()
			if packet != nil {
				_ = packet.Close()
			}
		}
	}()
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	// net.ListenPacket uses no REUSEADDR/REUSEPORT for this UDP socket on Android.
	packet, err = net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, errNativeUDP
	}
	peer, ok := packet.LocalAddr().(*net.UDPAddr)
	if !ok || peer.Port == 0 || !peer.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		return nil, errNativeUDP
	}
	request := socks5.SerializeAddr("", peer.AddrPort().Addr(), uint16(peer.Port))
	reply, handshakeErr := socks5.ClientHandshake(control, request, socks5.CmdUDPAssociate, &socks5.User{Username: ss.user, Password: ss.pass})
	if handshakeErr != nil {
		return nil, errNativeUDP
	}
	relay := reply.UDPAddr()
	if relay == nil || relay.Port == 0 || !relay.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		return nil, errNativeUDP
	}
	if control.SetDeadline(time.Time{}) != nil {
		return nil, errNativeUDP
	}
	go func() { _, _ = io.Copy(io.Discard, control); _ = control.Close(); _ = packet.Close() }()
	return &socksPacketConn{PacketConn: packet, rAddr: relay, tcpConn: control}, nil
}
