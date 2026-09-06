package androidprotect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

const Environment = "FLUTTER_VLESS_PROTECT_SOCKET"

func exchange(path string, command byte, fd int) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, errors.New("socket protection broker unavailable")
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	unix := conn.(*net.UnixConn)
	var rights []byte
	if fd >= 0 {
		rights = syscall.UnixRights(fd)
	}
	if _, _, err = unix.WriteMsgUnix([]byte{command}, rights, nil); err != nil {
		conn.Close()
		return nil, errors.New("socket protection descriptor transfer failed")
	}
	return conn, nil
}

func protect(path string, command byte, raw syscall.RawConn) error {
	var result error
	err := raw.Control(func(fd uintptr) {
		conn, err := exchange(path, command, int(fd))
		if err != nil {
			result = err
			return
		}
		defer conn.Close()
		var ack [1]byte
		if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
			result = errors.New("socket protection denied or timed out")
		}
	})
	if err != nil {
		return err
	}
	return result
}

// Configure is called once before core startup. The existing resolver object is
// mutated because Xray common/net retains a pointer alias to DefaultResolver.
func Configure(path string) error {
	control := func(network, address string, raw syscall.RawConn) error {
		if network == "unix" || network == "unixpacket" {
			return nil
		}
		return protect(path, 'P', raw)
	}
	if err := internet.RegisterDialerController(control); err != nil {
		return err
	}
	if err := internet.RegisterListenerController(control); err != nil {
		return err
	}
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = resolverDial(path)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Control: control, Timeout: 16 * time.Second}).DialContext
	http.DefaultTransport = transport
	// Prove real FD transfer and protect() success before Kotlin establishes TUN.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	conn, err := exchange(path, 'H', fd)
	if err != nil {
		return err
	}
	defer conn.Close()
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		return errors.New("socket protection capability check failed")
	}
	return nil
}

func resolverDial(path string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := exchange(path, 'D', -1)
		if err != nil {
			return nil, err
		}
		// Go treats this Unix stream as DNS-over-TCP, including its length
		// prefix. Android resolves the wire query on the current physical
		// Network, preserving Private DNS and avoiding the VPN resolver.
		conn.SetDeadline(time.Now().Add(12 * time.Second))
		// Hide UnixConn's PacketConn methods: the local socket is a stream.
		return struct{ net.Conn }{conn}, nil
	}
}
