"""Pinned XDRIVE S3/Drive ownership; apply only to a disposable Core copy.

The caller validates upstream SHA-256 entries before composing patches. Every
replacement is also preflighted before the first mutation. No cloud requests,
Core execution, module-cache edits or protobuf changes happen in this helper.
"""

PATHS = (
    'core/xray.go', 'transport/internet/xdrive/xdrive.go',
    'transport/internet/xdrive/client.go', 'transport/internet/xdrive/drive.go',
    'transport/internet/xdrive/s3.go', 'transport/internet/xdrive/storage.go',
)


UPSTREAM_SHA256 = {
    'core/xray.go': '66edf1a9ed6b9683b4f668612e6c6e876830cffb07521517f03a21e630f7ef15',
    'transport/internet/xdrive/xdrive.go': '5a4f0abb61b9a5388dc200454fae8c5f544ab407031d5542e8fd93537f5876c1',
    'transport/internet/xdrive/client.go': '190b7a703bdae2d5cd83b2c71c72c49ca7579057004bb4e6a9d7dea6305bf838',
    'transport/internet/xdrive/drive.go': 'bdb7e5608a2d3d933c0d7d8b070203fffcf7f04d144fdbfd06d8c239d76f9014',
    'transport/internet/xdrive/s3.go': '607e95246f885f784e172551ef70c8645ec775e0d00840f3daac2b852a1f1a18',
    'transport/internet/xdrive/storage.go': '80873c5b071a2142c761a32cd2b6aed94c4decf42da1685f8a6eb72f4ddd38b7',
}


def replacements():
    base = 'transport/internet/xdrive/'
    return [
        ('core/xray.go', '\tctx context.Context\n', '\tnativeXdriveLifetime *internet.NativeServiceLifetime\n\tctx context.Context\n'),
        ('core/xray.go', 'func initInstanceWithConfig(config *Config, server *Instance) (bool, error) {',
         '''func initInstanceWithConfig(config *Config, server *Instance) (done bool, initErr error) {
	server.ctx, server.nativeXdriveLifetime = internet.ContextWithNativeServiceLifetime(server.ctx)
	defer func() { if done { server.nativeXdriveLifetime.Close() } }()'''),
        ('core/xray.go', '\ts.running = false\n', '\ts.running = false\n\ts.nativeXdriveLifetime.Close()\n'),
        (base+'xdrive.go', 'func init() {', 'func NativeLifetimeCapability() int64 { return 2 }\n\nfunc init() {'),
        (base+'xdrive.go', 'storage, err = newStorage(streamSettings)', 'storage, err = newNativeStorage(ctx, streamSettings)'),
        (base+'xdrive.go', '\tstorage, err := newStorage(streamSettings)\n\tif err != nil {\n\t\treturn nil, err\n\t}', '\tstorage, err := newNativeStorage(ctx, streamSettings)\n\tif err != nil {\n\t\treturn nil, err\n\t}'),
        (base+'xdrive.go', '\tspare, warm := takeSpare(config, p)', '''\t// The upstream spare pool is process-wide and schedules detached workers.
\t// Managed Core instances use cold allocation until spares have a Core owner.
\t_, owned := internet.NativeServiceLifetimeFromContext(ctx)
\tvar spare spareRing
\tvar warm bool
\tif !owned {
\t\tspare, warm = takeSpare(config, p)
\t}'''),
        (base+'xdrive.go', '\t\twarmSpares(streamSettings, config, p)', '\t\tif !owned {\n\t\t\twarmSpares(streamSettings, config, p)\n\t\t}'),
        (base+'xdrive.go', 'case <-time.After(25 * time.Millisecond):', 'case <-time.After(25 * time.Millisecond):\n\t\t\tcase <-writer.ctx.Done():\n\t\t\t\treturn'),
        (base+'xdrive.go', 'storage.Put(context.Background(), announceName(session, time.Now()), announce)', 'storage.Put(writer.ctx, announceName(session, time.Now()), announce)'),
        (base+'xdrive.go', 'newSlotConn(context.Background(), slots,', 'newNativeSlotConn(ctx, slots,'),
        (base+'xdrive.go', 'newConn(context.Background(), storage,', 'newNativeConn(ctx, storage,'),
        (base+'xdrive.go', 'listenerCtx, cancel := context.WithCancel(context.Background())', 'listenerCtx, cancel := nativeWorkerContext(ctx)'),
        (base+'drive.go', 'func newDriveStorage(streamSettings *internet.MemoryStreamConfig, config *Config) (*driveStorage, error) {',
         'func newDriveStorage(streamSettings *internet.MemoryStreamConfig, config *Config, lifetime ...context.Context) (*driveStorage, error) {\n\townerContext := nativeLifetimeContext(lifetime)'),
        (base+'drive.go', 'newServiceClient(context.Background(), h1Hosts, streamSettings, driveTimeout, driveMaxInflight)', 'newServiceClient(ownerContext, h1Hosts, streamSettings, driveTimeout, driveMaxInflight)'),
        (base+'drive.go', 'type driveShared struct {', 'type driveShared struct {\n\tnativeContext context.Context'),
        (base+'drive.go', 'driveShared: &driveShared{', 'driveShared: &driveShared{\n\t\t\tnativeContext: ownerContext,'),
        (base+'drive.go', 'func (s *driveStorage) accessToken(ctx context.Context) (string, error) {',
         'func (s *driveStorage) accessToken(ctx context.Context) (string, error) {\n\tctx, release := nativeOperationContext(ctx, s.nativeContext); defer release()\n\tif err := ctx.Err(); err != nil { return "", err }'),
        (base+'drive.go', 'fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)',
         '''ownerCtx, releaseFetch := nativeOperationContext(context.WithoutCancel(ctx), s.nativeContext)
\tdefer releaseFetch()
\tfetchCtx, cancel := context.WithTimeout(ownerCtx, 30*time.Second)'''),
        (base+'drive.go', 'ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)',
         'ctx, cancel := context.WithTimeout(nativeLifetimeContext([]context.Context{s.nativeContext}), 30*time.Second)'),
        (base+'drive.go', 'func (s *driveStorage) do(ctx context.Context, method, target, contentType string, body []byte) (int, []byte, error) {',
         'func (s *driveStorage) do(ctx context.Context, method, target, contentType string, body []byte) (int, []byte, error) {\n\tctx, release := nativeOperationContext(ctx, s.nativeContext); defer release()\n\tif err := ctx.Err(); err != nil { return 0, nil, err }'),
        (base+'drive.go', '''return newServiceClient(connCtx, h1Hosts, streamSettings, driveTimeout, driveMaxInflight)
			}),''', '''return newServiceClient(connCtx, h1Hosts, streamSettings, driveTimeout, driveMaxInflight)
			}, ownerContext),'''),
        (base+'s3.go', 'func newS3Storage(streamSettings *internet.MemoryStreamConfig, c *Config) (*s3Storage, error) {',
         'func newS3Storage(streamSettings *internet.MemoryStreamConfig, c *Config, lifetime ...context.Context) (*s3Storage, error) {\n\townerContext := nativeLifetimeContext(lifetime)'),
        (base+'s3.go', 'newConnPool(c.Xmux, newClient)', 'newConnPool(c.Xmux, newClient, ownerContext)'),
        (base+'s3.go', 'newClient(context.Background())', 'newClient(ownerContext)'),
        (base+'s3.go', 'type s3Shared struct {', 'type s3Shared struct {\n\tnativeContext context.Context'),
        (base+'s3.go', 's3Shared: &s3Shared{', 's3Shared: &s3Shared{\n\t\t\tnativeContext: ownerContext,'),
        (base+'s3.go', 'func (s *s3Storage) do(ctx context.Context, method, key string, query url.Values, body []byte) (int, []byte, error) {',
         'func (s *s3Storage) do(ctx context.Context, method, key string, query url.Values, body []byte) (int, []byte, error) {\n\tctx, release := nativeOperationContext(ctx, s.nativeContext); defer release()\n\tif err := ctx.Err(); err != nil { return 0, nil, err }'),
        (base+'client.go', 'type serviceTransport struct {', 'type serviceTransport struct {\n\towner context.Context'),
        (base+'client.go', '\tctx, cancel := context.WithCancelCause(r.Context())', '''	if t.owner != nil && t.owner.Err() != nil { return nil, t.owner.Err() }
	ctx, cancel := context.WithCancelCause(r.Context())
	stopOwner := func() bool { return false }
	if t.owner != nil { stopOwner = context.AfterFunc(t.owner, func() { cancel(context.Cause(t.owner)) }) }'''),
        (base+'client.go', '\tend := func() {\n\t\ttimer.Stop()', '\tend := func() {\n\t\tstopOwner()\n\t\ttimer.Stop()'),
        (base+'client.go', '\t\tTransport: &serviceTransport{', '\t\tTransport: &serviceTransport{\n\t\t\towner: connCtx,'),
        (base+'client.go', 'func newConnPool(config *splithttp.XmuxConfig, newClient func(connCtx context.Context) *http.Client) *connPool {',
         'func newConnPool(config *splithttp.XmuxConfig, newClient func(connCtx context.Context) *http.Client, lifetime ...context.Context) *connPool {'),
        (base+'client.go', 'ctx, cancel := context.WithCancel(context.Background())', 'ctx, cancel := context.WithCancel(nativeLifetimeContext(lifetime))'),
        (base+'client.go', '''				qconn, err := tr.Dial(ctx, udpAddr, gotlsConfig, cfg)
				if err != nil {
					tr.Close()
					pktConn.Close()
					return nil, err
				}
				stop := context.AfterFunc(connCtx, func() { qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
				context.AfterFunc(qconn.Context(), func() { stop(); tr.Close(); pktConn.Close() })''', '''				closeOwnedTransport := sync.OnceFunc(func() {
					// Close the supplied read source before joining QUIC's listener.
					_ = pktConn.Close()
					_ = tr.Close()
				})
				qconn, err := tr.Dial(ctx, udpAddr, gotlsConfig, cfg)
				if err != nil { closeOwnedTransport(); return nil, err }
				stop := context.AfterFunc(connCtx, func() { qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
				context.AfterFunc(qconn.Context(), func() { stop(); closeOwnedTransport() })'''),
    ]


def apply(root, replace):
    edits = replacements()
    for item in edits:
        path, before, _ = item[:3]
        expected = item[3] if len(item) == 4 else 1
        candidate = root / path
        if candidate.is_symlink() or candidate.read_text().count(before) != expected:
            raise ValueError('Pinned XDRIVE lifetime boundary changed: ' + path)
    for item in edits:
        path, before, after = item[:3]
        if len(item) == 4:
            # Both production call sites are intentionally one atomic edit.
            candidate = root / path
            source = candidate.read_text()
            replace(path, source, source.replace(before, after))
        else:
            replace(path, before, after)
