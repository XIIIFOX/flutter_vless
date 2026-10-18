"""Exact construction-only managed-input seam in a disposable pinned copy."""


def apply(root, replace):
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
