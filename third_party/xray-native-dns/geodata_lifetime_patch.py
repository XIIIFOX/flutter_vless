"""Cancel only the pinned GeoDAT instance's downloader before joining cron.

The producer applies this to its disposable Core copy. All source hashes and
replacement boundaries are checked before the first write. No subprocesses,
network requests, module-cache access or global transport/context edits occur.
"""
import hashlib

UPSTREAM_SHA256 = {
    'app/geodata/geodata.go': '61b6b4eb9382294ea944393dc7e58a9220c0dc2c3565d6a993ac80aef896125b',
    'app/geodata/download.go': '38f04dc2d612bc332db5e8068b12fe685f90edcbdaa60ece58417691dbbd76aa',
}
PATHS = tuple(UPSTREAM_SHA256)


def replacements():
    return [
        ('app/geodata/geodata.go', '\ttasker     *cron.Cron\n',
         '\ttasker     *cron.Cron\n\tcancelDownload context.CancelFunc\n'),
        ('app/geodata/geodata.go', '\tif len(g.assets) > 0 {\n\t\tvar dispatcher routing.Dispatcher',
         '\tif len(g.assets) > 0 {\n\t\tdownloadCtx, cancel := context.WithCancel(ctx)\n\t\tg.cancelDownload = cancel\n\t\tvar dispatcher routing.Dispatcher'),
        ('app/geodata/geodata.go', '\t\t\treturn nil, errors.New("failed to get dispatcher for geodata downloader").Base(err)',
         '\t\t\tcancel()\n\t\t\treturn nil, errors.New("failed to get dispatcher for geodata downloader").Base(err)'),
        ('app/geodata/geodata.go', '\t\tg.downloader = newDownloader(ctx, dispatcher, config.Outbound)',
         '\t\tg.downloader = newDownloader(downloadCtx, dispatcher, config.Outbound)'),
        ('app/geodata/geodata.go', '''func (g *Instance) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {''', '''func (g *Instance) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Cancel the owned request/body before cron waits for active jobs. A
	// non-idle peer can otherwise keep a scheduled download alive indefinitely.
	if g.cancelDownload != nil { g.cancelDownload() }
	g.downloader.closeIdleConnections()

	if !g.running {'''),
        ('app/geodata/geodata.go', '\t\t<-g.tasker.Stop().Done()\n\t}\n\n\tg.running = false',
         '\t\t<-g.tasker.Stop().Done()\n\t}\n\t// A cancelled active HTTP/2 stream may enter the pool after the first close.\n\tg.downloader.closeIdleConnections()\n\n\tg.running = false'),
        ('app/geodata/download.go', 'func (d *downloader) download(assets []*Asset) ([]stage, error) {',
         '''// This client/transport belongs exclusively to one GeoDAT instance.
func (d *downloader) closeIdleConnections() {
	if d != nil && d.httpsClient != nil { d.httpsClient.CloseIdleConnections() }
}

func (d *downloader) download(assets []*Asset) ([]stage, error) {'''),
        ('app/geodata/geodata.go', 'func init() {',
         '''// NativeLifetimeCapability exists only with this guarded ownership patch.
func NativeLifetimeCapability() int64 { return 1 }

func init() {'''),
    ]


def apply(root, replace):
    edits = replacements()
    for name, expected in UPSTREAM_SHA256.items():
        source = root / name
        if source.is_symlink() or not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError('Pinned GeoDAT source mismatch: ' + name)
    for name, before, _ in edits:
        if (root / name).read_text().count(before) != 1:
            raise ValueError('Pinned GeoDAT lifetime boundary changed: ' + name)
    for name, before, after in edits:
        replace(name, before, after)
