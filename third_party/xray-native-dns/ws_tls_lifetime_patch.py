"""Bound the opening handshake and release failed WebSocket connections.

The overlay is applied only to checked, disposable Core copies.
"""
import hashlib
from pathlib import Path

PATH = 'transport/internet/websocket/dialer.go'
UPSTREAM_SHA256 = {PATH: '247b1512b2c868f7766a7f40dca88ab69ce248ddc5a58bd9ae57d06deaa01c56'}
PATHS = (PATH,)

_EDITS = (
    ('''	_ "embed"
	"encoding/base64"
	"io"
	"time"

	"github.com/gorilla/websocket"
''', '''	_ "embed"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
'''),
    ('''	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func dialWebSocket(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, ed []byte) (net.Conn, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)

	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
''', '''	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

const wsHandshakeTimeout = 8 * time.Second

// The timeout callback and the dialer may retire the same pending connection.
type handshakeOwnedConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *handshakeOwnedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func dialWebSocket(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, ed []byte) (net.Conn, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)
	ownPendingConn := func(c net.Conn) net.Conn { return c }

	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
'''),
    ('''			if err != nil {
				return nil, errors.New("failed to dial to dest").Base(err)
			}
			return conn, err
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"
''', '''			if err != nil {
				return nil, errors.New("failed to dial to dest").Base(err)
			}
			return ownPendingConn(conn), nil
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: wsHandshakeTimeout,
	}

	protocol := "ws"
'''),
    ('''		tlsConfig := tConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		dialer.TLSClientConfig = tlsConfig
		if fingerprint := tls.GetFingerprint(tConfig.Fingerprint); fingerprint != nil {
			dialer.NetDialTLSContext = func(_ context.Context, _, addr string) (net.Conn, error) {
				// Like the NetDial in the dialer
				var pconn net.Conn
				var err error
				if streamSettings.FinalMask != nil {
					pconn, err = streamSettings.FinalMask.DialTCP(ctx, dest)
				} else {
					pconn, err = internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				}
				if err != nil {
					return nil, errors.New("failed to dial to dest").Base(err)
				}

				// TLS and apply the handshake
				cn := tls.UClient(pconn, tlsConfig, fingerprint).(*tls.UConn)
				if err := cn.WebsocketHandshakeContext(ctx); err != nil {
					errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
					return nil, err
				}
				if !tlsConfig.InsecureSkipVerify {
					if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
						errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
						return nil, err
					}
''', '''		tlsConfig := tConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		dialer.TLSClientConfig = tlsConfig
		if fingerprint := tls.GetFingerprint(tConfig.Fingerprint); fingerprint != nil {
			dialer.NetDialTLSContext = func(handshakeCtx context.Context, _, addr string) (net.Conn, error) {
				// Like the NetDial in the dialer
				var pconn net.Conn
				var err error
				if streamSettings.FinalMask != nil {
					pconn, err = streamSettings.FinalMask.DialTCP(handshakeCtx, dest)
				} else {
					pconn, err = internet.DialSystem(handshakeCtx, dest, streamSettings.SocketSettings)
				}
				if err != nil {
					return nil, errors.New("failed to dial to dest").Base(err)
				}

				// TLS and apply the handshake
				pconn = ownPendingConn(pconn)
				cn := tls.UClient(pconn, tlsConfig, fingerprint).(*tls.UConn)
				if err := cn.WebsocketHandshakeContext(handshakeCtx); err != nil {
					_ = pconn.Close()
					errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
					return nil, err
				}
				if !tlsConfig.InsecureSkipVerify {
					if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
						_ = pconn.Close()
						errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
						return nil, err
					}
'''),
    ('''		header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
	}

	conn, resp, err := dialer.DialContext(ctx, uri, header)
	if err != nil {
		var reason string
		if resp != nil {
''', '''		header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
	}

	dialCtx := ctx
	stopAbort := func() bool { return true }
	var pending *handshakeOwnedConn
	sockopt := streamSettings.SocketSettings
	managed := sockopt != nil && sockopt.DialerProxy != ""
	if managed {
		// A redirected Core pipe does not implement socket deadlines.
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, wsHandshakeTimeout)
		defer cancel()
		ownPendingConn = func(c net.Conn) net.Conn {
			owned := &handshakeOwnedConn{Conn: c}
			pending = owned
			stopAbort = context.AfterFunc(dialCtx, func() { _ = owned.Close() })
			return owned
		}
	}

	conn, resp, err := dialer.DialContext(dialCtx, uri, header)
	if managed {
		// Disarm before canceling the handshake scope or handing off the live
		// connection. A valid 101 received after the deadline cannot win.
		stopped := stopAbort()
		deadline, _ := dialCtx.Deadline()
		if !stopped || dialCtx.Err() != nil || !time.Now().Before(deadline) {
			if pending != nil {
				// Abort the owned pipe without attempting a TLS close_notify.
				_ = pending.Close()
			}
			err = dialCtx.Err()
			if err == nil {
				err = context.DeadlineExceeded
			}
		}
	}
	if err != nil {
		var reason string
		if resp != nil {
'''),
)


def replacements():
    return [(PATH, before, after) for before, after in _EDITS]


def apply(root, replace):
    root = Path(root)
    path = root / PATH
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('Transport lifetime source must be a real file')
        if parent == root:
            break
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != UPSTREAM_SHA256[PATH]:
        raise ValueError('Pinned transport lifetime source mismatch: ' + PATH)
    expected = path.read_text(encoding='utf-8')
    for before, after in _EDITS:
        if expected.count(before) != 1:
            raise ValueError('Pinned transport lifetime replacement boundary changed: ' + PATH)
        expected = expected.replace(before, after, 1)
        replace(PATH, before, after)
    if path.read_text(encoding='utf-8') != expected:
        raise ValueError('Transport lifetime callback did not apply the exact owned edit: ' + PATH)
