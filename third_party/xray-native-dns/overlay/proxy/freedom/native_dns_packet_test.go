package freedom

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

// Memory-only PacketConn. These tests never allocate an OS socket/Core.
type nativeMemoryPacket struct{ writes []string }

func (*nativeMemoryPacket) ReadFrom([]byte) (int, stdnet.Addr, error) { return 0, nil, io.EOF }
func (p *nativeMemoryPacket) WriteTo(data []byte, dest stdnet.Addr) (int, error) {
	p.writes = append(p.writes, dest.String())
	return len(data), nil
}
func (*nativeMemoryPacket) Close() error { return nil }
func (*nativeMemoryPacket) LocalAddr() stdnet.Addr {
	return &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 1}
}
func (*nativeMemoryPacket) SetDeadline(time.Time) error      { return nil }
func (*nativeMemoryPacket) SetReadDeadline(time.Time) error  { return nil }
func (*nativeMemoryPacket) SetWriteDeadline(time.Time) error { return nil }

type nativePacketDNS struct{ calls int }

func (*nativePacketDNS) Type() any    { return dns.ClientType() }
func (*nativePacketDNS) Start() error { return nil }
func (*nativePacketDNS) Close() error { return nil }
func (d *nativePacketDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	d.calls++
	return []net.IP{net.ParseAddress("203.0.113.60").IP()}, 10, nil
}

type nativePacketManager struct{ outbound.Manager }

func nativePacketFixture(t *testing.T) (*internet.NativeDNSOwner, *PacketWriter, *nativeMemoryPacket, *nativePacketDNS) {
	t.Helper()
	key, instance := new(int), new(int)
	owner, err := internet.NewNativeDNSOwner([]internet.NativeDNSBinding{{Key: key, SourceIndex: 0, ProxyType: "xray.proxy.freedom.Config"}})
	if err != nil {
		t.Fatal(err)
	}
	client := &nativePacketDNS{}
	scope, err := internet.BindNativeDNSHandler(internet.ContextWithNativeDNSOwner(context.Background(), owner), instance, key, "", "xray.proxy.freedom.Config", client, &nativePacketManager{})
	if err != nil {
		t.Fatal(err)
	}
	packet := &nativeMemoryPacket{}
	writer := &PacketWriter{NativeDNS: scope, PacketConnWrapper: &net.PacketConnWrapper{PacketConn: packet}, Handler: &Handler{resolveStrategy: internet.DomainStrategy_AS_IS}, ResolvedUDPAddr: utils.NewTypedSyncMap[string, net.Address]()}
	return owner, writer, packet, client
}
func nativeDomainPacket() buf.MultiBuffer {
	buffer := buf.New()
	_, _ = buffer.Write([]byte("synthetic UDP bytes"))
	dest := net.UDPDestination(net.DomainAddress("endpoint.invalid"), 53)
	buffer.UDP = &dest
	return buf.MultiBuffer{buffer}
}
func TestNativeDNSPacketWriterUsesOwnCallerDNSAndRejectsClosedCache(t *testing.T) {
	owner, writer, packet, client := nativePacketFixture(t)
	if err := writer.WriteMultiBuffer(nativeDomainPacket()); err != nil {
		t.Fatal(err)
	}
	if len(packet.writes) != 1 || packet.writes[0] != "203.0.113.60:53" || client.calls != 1 {
		t.Fatal("UDP did not use its instance DNS")
	}
	_ = owner.Close()
	if err := writer.WriteMultiBuffer(nativeDomainPacket()); !errors.Is(err, internet.ErrNativeDNSClosed) {
		t.Fatal("Closed owner reused cached UDP address")
	}
	if len(packet.writes) != 1 || client.calls != 1 {
		t.Fatal("UDP sent or resolved after owner close")
	}
}
func TestNativeDNSPacketWriterWithoutScopeNeverUsesSystemResolver(t *testing.T) {
	_, writer, packet, client := nativePacketFixture(t)
	writer.NativeDNS = nil
	if err := writer.WriteMultiBuffer(nativeDomainPacket()); !errors.Is(err, internet.ErrNativeDNSScope) {
		t.Fatal("Missing UDP scope accepted")
	}
	if len(packet.writes) != 0 || client.calls != 0 {
		t.Fatal("Missing scope used a resolver or packet connection")
	}
}
