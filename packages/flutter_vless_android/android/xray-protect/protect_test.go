package androidprotect

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func broker(t *testing.T, ack byte) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "fv-protect-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	path := filepath.Join(directory, "p.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			data, ancillary := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
			_, n, _, _, err := conn.ReadMsgUnix(data, ancillary)
			if err == nil && data[0] == 'D' {
				var length [2]byte
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := io.ReadFull(conn, length[:]); err == nil {
					query := make([]byte, binary.BigEndian.Uint16(length[:]))
					if _, err := io.ReadFull(conn, query); err == nil {
						var message dnsmessage.Message
						if message.Unpack(query) == nil && len(message.Questions) == 1 {
							message.Header.Response = true
							message.Header.RecursionAvailable = true
							message.Additionals = nil
							q := message.Questions[0]
							if q.Type == dnsmessage.TypeA {
								message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}}}}
							}
							answer, _ := message.Pack()
							binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
							conn.Write(append(length[:], answer...))
						}
					}
				}
				conn.Close()
				continue
			}
			valid := err == nil
			messages, err := syscall.ParseSocketControlMessage(ancillary[:n])
			valid = valid && err == nil && len(messages) == 1
			for _, message := range messages {
				fds, err := syscall.ParseUnixRights(&message)
				valid = valid && err == nil && len(fds) == 1
				for _, fd := range fds {
					kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
					valid = valid && err == nil && (kind == syscall.SOCK_DGRAM || kind == syscall.SOCK_STREAM)
					syscall.Close(fd)
				}
			}
			if valid {
				conn.Write([]byte{ack})
			} else {
				conn.Write([]byte{0})
			}
			conn.Close()
		}
	}()
	return path
}

func TestResolverUsesFramedPhysicalNetworkBroker(t *testing.T) {
	resolver := net.Resolver{PreferGo: true, Dial: resolverDial(broker(t, 1))}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip", "native-control.test.")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(192, 0, 2, 7)) {
		t.Fatalf("physical DNS stream framing failed: %v, %v", ips, err)
	}
}

type rawFD int

func (f rawFD) Control(fn func(uintptr)) error    { fn(uintptr(f)); return nil }
func (f rawFD) Read(fn func(uintptr) bool) error  { fn(uintptr(f)); return nil }
func (f rawFD) Write(fn func(uintptr) bool) error { fn(uintptr(f)); return nil }

func TestRealDescriptorTransferAndDenial(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := protect(broker(t, 1), 'P', rawFD(fd)); err != nil {
		t.Fatal(err)
	}
	if err := protect(broker(t, 0), 'P', rawFD(fd)); err == nil {
		t.Fatal("denial accepted")
	}
	if err := protect(filepath.Join(t.TempDir(), "missing"), 'P', rawFD(fd)); err == nil {
		t.Fatal("missing broker accepted")
	}
}

func TestCoreControllersFailBeforeTCPConnectAndUDPUse(t *testing.T) {
	path := broker(t, 0)
	previous := internet.Controllers
	t.Cleanup(func() { internet.Controllers = previous })
	internet.Controllers = []func(string, string, syscall.RawConn) error{
		func(_, _ string, c syscall.RawConn) error { return protect(path, 'P', c) },
	}
	for _, network := range []xnet.Network{xnet.Network_TCP, xnet.Network_UDP} {
		conn, err := (&internet.DefaultSystemDialer{}).Dial(context.Background(), nil,
			xnet.Destination{Network: network, Address: xnet.LocalHostIP, Port: 9}, nil)
		if conn != nil {
			conn.Close()
			t.Fatal("unprotected socket returned")
		}
		if err == nil || !strings.Contains(err.Error(), "protection denied") {
			t.Fatalf("controller failure lost: %v", err)
		}
	}
	if err := internet.RegisterListenerController(func(_, _ string, c syscall.RawConn) error { return protect(path, 'P', c) }); err != nil {
		t.Fatal(err)
	}
	conn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil)
	if conn != nil {
		conn.Close()
		t.Fatal("unprotected UDP listener returned")
	}
	if err == nil || !strings.Contains(err.Error(), "protection denied") {
		t.Fatalf("listener failure lost: %v", err)
	}
}
