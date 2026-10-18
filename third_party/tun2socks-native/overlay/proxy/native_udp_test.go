package proxy

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

type nativePacketSource struct {
	packets []net.Addr
	payload []byte
	closed  bool
}

func (p *nativePacketSource) ReadFrom(out []byte) (int, net.Addr, error) {
	if len(p.packets) == 0 {
		return 0, nil, io.EOF
	}
	source := p.packets[0]
	p.packets = p.packets[1:]
	return copy(out, p.payload), source, nil
}
func (*nativePacketSource) WriteTo([]byte, net.Addr) (int, error) { return 0, errors.New("unused") }
func (p *nativePacketSource) Close() error                        { p.closed = true; return nil }
func (*nativePacketSource) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 34567}
}
func (*nativePacketSource) SetDeadline(time.Time) error      { return nil }
func (*nativePacketSource) SetReadDeadline(time.Time) error  { return nil }
func (*nativePacketSource) SetWriteDeadline(time.Time) error { return nil }

func TestNativeUDPClientRefusesForeignResponseBeforeDecoding(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 23456}
	payload, err := socks5.EncodeUDPPacket(socks5.Addr{1, 198, 18, 0, 53, 0, 53}, []byte("private-response"))
	if err != nil {
		t.Fatal(err)
	}
	packet := &nativePacketSource{packets: []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 23457}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 23456}, peer}, payload: payload}
	conn := &socksPacketConn{PacketConn: packet, rAddr: peer}
	var output [128]byte
	n, addr, err := conn.ReadFrom(output[:])
	if err != nil || string(output[:n]) != "private-response" || addr.String() != "198.18.0.53:53" || len(packet.packets) != 0 {
		t.Fatal("untrusted relay response was accepted", err)
	}
}

func TestNativeUDPClientRejectsNonliteralProxyWithoutResolver(t *testing.T) {
	for _, address := range []string{"example.invalid:23456", "0.0.0.0:23456", "[::1]:23456", "127.0.0.1:0"} {
		ss := &Socks5{Base: &Base{addr: address}, user: "u", pass: "p"}
		if conn, err := nativeBoundUDP(ss); err == nil {
			conn.Close()
			t.Fatal("unsupported proxy acquired a UDP control")
		}
	}
}
