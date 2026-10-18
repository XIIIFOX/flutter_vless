"""Exact construction-only managed-input seam in a disposable pinned copy."""


def apply(root, replace):
    replace('proxy/socks/protocol.go',
            '\tlocalAddress net.Address\n',
            '\tlocalAddress net.Address\n\tauthorizeUDP func(net.Address, net.Port) error\n')
    replace('proxy/socks/server.go',
            '\t\tlocalAddress: net.IPAddress(conn.LocalAddr().(*net.TCPAddr).IP),',
            '''\t\tlocalAddress: net.IPAddress(conn.LocalAddr().(*net.TCPAddr).IP),
        authorizeUDP: func(address net.Address, port net.Port) error {
            return authorizeNativeUDP(ctx, address, port)
        },''')
    replace('proxy/socks/protocol.go',
            '''\tif request.Command == protocol.RequestCommandUDP {
\t\tif s.config.Address != nil {''',
            '''\tif request.Command == protocol.RequestCommandUDP {
        if s.authorizeUDP != nil && s.authorizeUDP(request.Address, request.Port) != nil {
            _ = writeSocks5Response(writer, statusCmdNotSupport, net.AnyIP, net.Port(0))
            return nil, nil, routing.ErrNativeInput
        }
\t\tif s.config.Address != nil {''')
    replace('proxy/socks/protocol.go',
            '\t"github.com/xtls/xray-core/transport/internet"',
            '\t"github.com/xtls/xray-core/transport/internet"\n\t"github.com/xtls/xray-core/features/routing"')
    # A revoked control socket can fail while writing the UDP Associate reply,
    # before processTCP installs its idle timer. Cleanup must still close both.
    replace('proxy/socks/temp_udp_listen.go',
            '\tc.Timer.SetTimeout(0)\n',
            '\tif c.Timer != nil { c.Timer.SetTimeout(0) }\n')
    path = 'app/proxyman/inbound/inbound.go'
    replace(path, 'type Manager struct {\n', 'type Manager struct {\n\tnativeInputSealed bool\n')
    replace(path,
            '''func (m *Manager) AddHandler(ctx context.Context, handler inbound.Handler) error {
	m.access.Lock()
	defer m.access.Unlock()
''',
            '''func (m *Manager) AddHandler(ctx context.Context, handler inbound.Handler) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.nativeInputSealed { return routing.ErrNativeInput }
''')
    replace(path,
            '''	m.access.Lock()
	defer m.access.Unlock()

	if handler, found := m.taggedHandlers[tag]; found {''',
            '''	m.access.Lock()
	defer m.access.Unlock()
	if m.nativeInputSealed { return routing.ErrNativeInput }

	if handler, found := m.taggedHandlers[tag]; found {''')
    replace(path,
            '\t"github.com/xtls/xray-core/features/inbound"\n',
            '\t"github.com/xtls/xray-core/features/inbound"\n\t"github.com/xtls/xray-core/features/routing"\n')
    replace(path,
            '\treturn NewAlwaysOnInboundHandler(ctx, tag, receiverSettings, proxySettings)',
            '''	handler, err := NewAlwaysOnInboundHandler(ctx, tag, receiverSettings, proxySettings)
	if err != nil { return nil, err }
	if err := configureNativeInput(ctx, config, handler); err != nil {
		_ = handler.Close()
		return nil, err
	}
	return handler, nil''')
    # Dispatcher owns the payload on every path. Strict admission/capacity
    # refusal must not leak a pooled buffer before any ray has been created.
    replace('transport/internet/udp/dispatcher.go',
            '''conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		return
	}''',
            '''conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		payload.Release()
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		return
	}''')
