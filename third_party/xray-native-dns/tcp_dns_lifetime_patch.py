"""Release a routed TCP DNS query when its existing budget expires.

The overlay is applied only to checked, disposable Core copies.
"""
import hashlib
from pathlib import Path

PATH = 'app/dns/nameserver_tcp.go'
UPSTREAM_SHA256 = {PATH: '0c6cd445ace96944fe04fcddfdd4e64b9553eb3802c6003504ac7880dcbf7765'}
PATHS = (PATH,)

_EDITS = (
    ('''	"context"
	"encoding/binary"
	"net/url"
	"sync/atomic"
	"time"

''', '''	"context"
	"encoding/binary"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

'''),
    ('''	clientIP        net.IP
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(
	url *url.URL,
''', '''	clientIP        net.IP
}

// routedTCPDNSConn owns a routed query and its virtual stream.
type routedTCPDNSConn struct {
	net.Conn
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (c *routedTCPDNSConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(
	url *url.URL,
'''),
    ('''	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		link, err := dispatcher.Dispatch(toDnsContext(ctx, s.destination.String()), *s.destination)
		if err != nil {
			return nil, err
		}

		return cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
		), nil
	}

	errors.LogInfo(context.Background(), "DNS: created TCP client initialized for ", url.String())
''', '''	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		// Preserve the routed DNS session while owning cancellation for this query.
		dispatchCtx, cancel := context.WithCancel(toDnsContext(ctx, s.destination.String()))
		link, err := dispatcher.Dispatch(dispatchCtx, *s.destination)
		if err != nil {
			cancel()
			return nil, err
		}

		conn := cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
		)
		return &routedTCPDNSConn{Conn: conn, cancel: cancel}, nil
	}

	errors.LogInfo(context.Background(), "DNS: created TCP client initialized for ", url.String())
'''),
    ('''				return
			}
			defer conn.Close()
			dnsReqBuf := buf.New()
			err = binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			if err != nil {
''', '''				return
			}
			defer conn.Close()
			_, routed := conn.(*routedTCPDNSConn)
			if routed {
				// The virtual connection has no effective socket deadline.
				stop := context.AfterFunc(dnsCtx, func() { _ = conn.Close() })
				defer stop()
			}
			dnsReqBuf := buf.New()
			err = binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			if err != nil {
'''),
    ('''				return
			}

			s.cacheController.updateRecord(r, rec)
		}(req)
	}
''', '''				return
			}

			if routed && (dnsCtx.Err() != nil || !time.Now().Before(deadline)) {
				return
			}
			s.cacheController.updateRecord(r, rec)
		}(req)
	}
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
