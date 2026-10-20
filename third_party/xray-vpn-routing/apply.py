#!/usr/bin/env python3
"""Apply routing and shared lifetime fixes to a new disposable pinned Core copy."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / 'pin-manifest.json').read_text())
CLASSIC = HERE.parent / 'xray-native-dns'
H3_PATH = 'transport/internet/splithttp/dialer.go'


def classic_input_paths():
    return [CLASSIC / 'classic_lifetime_patch.py', CLASSIC / 'pin-manifest.json',
            CLASSIC / 'overlay/app/dns/native_classic_lifetime.go',
            CLASSIC / 'overlay/app/dns/native_classic_lifetime_test.go']


def lifetime_input_paths():
    return [*classic_input_paths(), CLASSIC / 'h3_lifetime_patch.py']


def apply_classic_lifetime(root):
    """Only the family-neutral Classic lifetime patch, never strict DNS policy."""
    inputs = classic_input_paths()
    if any(path.is_symlink() or not path.is_file() for path in inputs):
        raise ValueError('Classic lifetime inputs must be real files')
    manifest = json.loads((CLASSIC / 'pin-manifest.json').read_text())
    if any(manifest[key] != MANIFEST[key] for key in ('module', 'module_version', 'module_sum', 'core_commit')):
        raise ValueError('Classic lifetime and routing Core pins differ')
    allowed = {'app/dns/dns.go', 'app/dns/nameserver_udp.go', 'transport/internet/udp/dispatcher.go'}
    for name in allowed:
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != manifest['upstream_sha256'][name]:
            raise ValueError('Pinned Classic lifetime source mismatch: ' + name)
    def replace(name, before, after):
        if name not in allowed:
            raise ValueError('Classic lifetime attempted an unrelated edit')
        path = root / name
        source = path.read_text()
        if source.count(before) != 1:
            raise ValueError('Pinned Classic replacement mismatch: ' + name)
        path.write_text(source.replace(before, after))
    spec = importlib.util.spec_from_file_location('routing_classic_lifetime', CLASSIC / 'classic_lifetime_patch.py')
    patch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patch)
    patch.apply(root, replace)
    for helper in inputs[2:]:
        target = root / 'app/dns' / helper.name
        if target.exists() or target.is_symlink():
            raise ValueError('Classic lifetime helper collision')
        shutil.copyfile(helper, target)


def validate_h3_lifetime_source(root):
    """Read-only H3 pin preflight, before creating or changing a Core copy."""
    inputs = [CLASSIC / 'h3_lifetime_patch.py', CLASSIC / 'pin-manifest.json']
    if any(path.is_symlink() or not path.is_file() for path in inputs):
        raise ValueError('H3 lifetime inputs must be real files')
    manifest = json.loads(inputs[1].read_text())
    if any(manifest[key] != MANIFEST[key] for key in ('module', 'module_version', 'module_sum', 'core_commit')):
        raise ValueError('H3 lifetime and routing Core pins differ')
    path = root / H3_PATH
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != manifest['upstream_sha256'][H3_PATH]:
        raise ValueError('Pinned H3 lifetime source mismatch: ' + H3_PATH)
    return inputs[0]


def apply_h3_lifetime(root):
    """Only dial-owned H3 cleanup; no strict DNS or routing policy changes."""
    patch_path = validate_h3_lifetime_source(root)
    path = root / H3_PATH

    def replace(name, before, after):
        if name != H3_PATH:
            raise ValueError('H3 lifetime attempted an unrelated edit')
        source = path.read_text()
        if source.count(before) != 1:
            raise ValueError('Pinned H3 replacement mismatch: ' + name)
        path.write_text(source.replace(before, after))

    spec = importlib.util.spec_from_file_location('routing_h3_lifetime', patch_path)
    patch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patch)
    patch.apply(root, replace)


def copy_and_apply_classic(source, destination, *, go='go', caches=None):
    return copy_and_apply(source, destination, go=go, caches=caches, routing=False, h3=False)


def copy_and_apply_lifetimes(source, destination, *, go='go', caches=None, routing=False, h3=True):
    return copy_and_apply(source, destination, go=go, caches=caches, routing=routing, h3=h3)


def copy_and_apply(source, destination, *, go='go', caches=None, routing=True, h3=True):
    source, destination = Path(source).resolve(), Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('Destination must be new')
    if caches is None:
        caches = [Path(os.environ['GOMODCACHE'])] if os.environ.get('GOMODCACHE') else []
        result = subprocess.run([go, 'env', 'GOMODCACHE'], env=dict(os.environ, GOTOOLCHAIN='local'), capture_output=True, text=True, check=True, timeout=15)
        caches.append(Path(result.stdout.strip()))
    resolved = destination.resolve()
    if resolved == source or source in resolved.parents:
        raise ValueError('Destination must be outside source')
    if any(resolved == Path(cache).resolve() or Path(cache).resolve() in resolved.parents for cache in caches):
        raise ValueError('Destination must be outside module caches')
    if any(resolved.parts[i:i+2] == ('pkg', 'mod') for i in range(len(resolved.parts)-1)):
        raise ValueError('Destination must be outside module caches')
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('Source symlinks are not supported')
    for relative, expected in MANIFEST['upstream_sha256'].items():
        if hashlib.sha256((source / relative).read_bytes()).hexdigest() != expected:
            raise ValueError('Pinned source mismatch: ' + relative)
    if h3:
        validate_h3_lifetime_source(source)
    # Validate every replacement before copying; no source or cache mutation.
    replacements = patches() if routing else []
    for relative, before, _ in replacements:
        if (source / relative).read_text().count(before) != 1:
            raise ValueError('Pinned replacement mismatch: ' + relative)
    overlays = sorted((HERE / 'overlay').rglob('*.go')) if routing else []
    for overlay in overlays:
        if (source / overlay.relative_to(HERE / 'overlay')).exists():
            raise ValueError('Overlay path already exists')
    shutil.copytree(source, destination)
    for path in [destination, *destination.rglob('*')]:
        path.chmod(path.stat().st_mode | 0o200)
    for relative, before, after in replacements:
        path = destination / relative
        path.write_text(path.read_text().replace(before, after))
    for overlay in overlays:
        target = destination / overlay.relative_to(HERE / 'overlay')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(overlay, target)
    apply_classic_lifetime(destination)
    if h3:
        apply_h3_lifetime(destination)
    return destination


def patches():
    dispatcher = 'app/dispatcher/default.go'
    return [
        ('core/xray.go', '''func NewWithContext(ctx context.Context, config *Config) (*Instance, error) {
	server := &Instance{ctx: ctx}

	done, err := initInstanceWithConfig(config, server)
	if done {
		return nil, err
	}

	return server, nil
}''', '''func NewWithContext(ctx context.Context, config *Config) (*Instance, error) {
	server := &Instance{ctx: ctx}

	done, err := initInstanceWithConfig(config, server)
	if done {
		nativeRoutingConstructionFailed(ctx, server)
		return nil, err
	}

	return server, nil
}'''),
        (dispatcher, 'type DefaultDispatcher struct {\n', 'type DefaultDispatcher struct {\n\tnativeRouting *nativeRoutingDispatcher\n'),
        (dispatcher, '\t\td := new(DefaultDispatcher)\n', '\t\td := new(DefaultDispatcher)\n\t\tif err := d.bindNativeVPNRouting(ctx); err != nil { return nil, err }\n'),
        (dispatcher, 'func (*DefaultDispatcher) Start() error {\n\treturn nil\n}', 'func (d *DefaultDispatcher) Start() error {\n\treturn d.nativeStart()\n}'),
        (dispatcher, 'func (*DefaultDispatcher) Close() error { return nil }', 'func (d *DefaultDispatcher) Close() error { return d.nativeClose() }'),
        (dispatcher, 'func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {', '''func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	routed, release, nativeErr := d.nativeBeginRoute(ctx, link)
	if nativeErr != nil { interruptNativeRouting(link); return }
	defer release()
	ctx = routed'''),
        (dispatcher, '\tif forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {', '''	if route, kind, handled, err := d.nativePickRoute(ctx, routingLink); handled {
		if err != nil { interruptNativeRouting(link); return }
		ctx = consumeNativeForcedOutbound(ctx)
		isPickRoute = kind
		if route != nil {
			handler = d.ohm.GetHandler(route.GetOutboundTag())
			if handler == nil { interruptNativeRouting(link); return }
		}
	} else if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {'''),
        (dispatcher, '\thandler.Dispatch(ctx, link)\n}', '''	if d.nativeRouting != nil {
		if _, _, err := d.nativeDecision(ctx); err != nil || ctx.Err() != nil { interruptNativeRouting(link); return }
	}
	handler.Dispatch(ctx, link)
}'''),
        ('app/proxyman/inbound/inbound.go', '\treturn NewAlwaysOnInboundHandler(ctx, tag, receiverSettings, proxySettings)', '''	h, err := NewAlwaysOnInboundHandler(ctx, tag, receiverSettings, proxySettings)
	if err != nil { return nil, err }
	if err := bindNativeRoutingInput(ctx, config, h); err != nil { _ = h.Close(); return nil, err }
	return h, nil'''),
        ('common/mux/client.go', '"github.com/xtls/xray-core/proxy"', '"github.com/xtls/xray-core/proxy"\n\t"github.com/xtls/xray-core/features/routing"'),
        ('common/mux/client.go', '\ts := sm.Allocate(&m.strategy, link.Reader, link.Writer)\n\tif s == nil {\n\t\treturn false\n\t}', '''	release, err := routing.RetainNativeRoutingRoute(ctx)
	if err != nil { return false }
	s := sm.Allocate(&m.strategy, link.Reader, link.Writer, release)
	if s == nil {
		release()
		return false
	}'''),
        ('common/mux/session.go', 'func (m *SessionManager) Allocate(Strategy *ClientStrategy, input buf.Reader, output buf.Writer) *Session {', 'func (m *SessionManager) Allocate(Strategy *ClientStrategy, input buf.Reader, output buf.Writer, nativeRelease ...func()) *Session {'),
        ('common/mux/session.go', '\tm.sessions[s.ID] = s\n\treturn s', '\tif len(nativeRelease) == 1 { s.nativeRoutingRelease = nativeRelease[0] }\n\tm.sessions[s.ID] = s\n\treturn s'),
        ('common/mux/session.go', 'type Session struct {\n', 'type Session struct {\n\tnativeRoutingRelease func()\n'),
        ('common/mux/session.go', '\ts.closed = true\n\tif s.done != nil {', '\ts.closed = true\n\tif s.nativeRoutingRelease != nil { defer s.nativeRoutingRelease() }\n\tif s.done != nil {'),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    try:
        copy_and_apply(args.source, args.destination, go=args.go)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    main()
