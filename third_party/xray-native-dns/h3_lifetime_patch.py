"""Close the dial-owned XHTTP H3 socket before joining its QUIC transport.

Callers validate the complete pinned source before composing their patches and
supply a guarded replace callback. This helper changes only the exact H3 dial
ownership block and works after unrelated DNS/routing edits in the same file.
"""

PATH = 'transport/internet/splithttp/dialer.go'

BEFORE = '''\t\t\t\tconn, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
\t\t\t\tif err != nil {
\t\t\t\t\treturn nil, err
\t\t\t\t}
\t\t\t\tcontext.AfterFunc(conn.Context(), func() { tr.Close(); pktConn.Close() })'''

AFTER = '''\t\t\t\tcloseOwnedTransport := sync.OnceFunc(func() {
\t\t\t\t\t// Supplied cnc sockets do not implement read deadlines. Close
\t\t\t\t\t// the read source before Transport.Close joins its listener.
\t\t\t\t\t_ = pktConn.Close()
\t\t\t\t\t_ = tr.Close()
\t\t\t\t})
\t\t\t\tconn, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
\t\t\t\tif err != nil {
\t\t\t\t\tcloseOwnedTransport()
\t\t\t\t\treturn nil, err
\t\t\t\t}
\t\t\t\tcontext.AfterFunc(conn.Context(), closeOwnedTransport)'''


def apply(root, replace):
    path = root / PATH
    if path.is_symlink():
        raise ValueError('XHTTP H3 lifetime source must be a real file')
    if path.read_text().count(BEFORE) != 1:
        raise ValueError('Pinned XHTTP H3 lifetime replacement boundary changed')
    replace(PATH, BEFORE, AFTER)
