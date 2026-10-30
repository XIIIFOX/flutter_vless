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


UPSTREAM_SHA256 = {'core/xray.go': '66edf1a9ed6b9683b4f668612e6c6e876830cffb07521517f03a21e630f7ef15', 'transport/internet/xdrive/xdrive.go': '5eaaeff1aadf31f7bc391efc078d14d3d87ea284b126a6dfdb5cb4003f58ee3b', 'transport/internet/xdrive/client.go': 'ef4fddfeb400e80c96c739dbaf74825766d349ffe8581e5bc108a2572db3abb1', 'transport/internet/xdrive/drive.go': '6c5ee8bef724e85ee9a022d6d085a2e6ba02d61cba645eeb70a70758196254c1', 'transport/internet/xdrive/s3.go': '607e95246f885f784e172551ef70c8645ec775e0d00840f3daac2b852a1f1a18', 'transport/internet/xdrive/storage.go': 'd412258786f154d3e81fb3f5ca3c913d92011806fc6fbff5b68804865db19c33'}


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
        (base+'xdrive.go', '\tstorage, err := newStorage(streamSettings)', '\tstorage, err := newNativeStorage(ctx, streamSettings)', 2),
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
