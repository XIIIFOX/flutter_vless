#!/usr/bin/env python3
"""Unpublished strict capability: copy pinned Core, then apply only in that copy."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / 'pin-manifest.json').read_text())


def module_cache_paths(go='go'):
    paths = []
    if os.environ.get('GOMODCACHE'):
        paths.append(Path(os.environ['GOMODCACHE']).resolve())
    try:
        result = subprocess.run([go, 'env', 'GOMODCACHE'], env=dict(os.environ, GOTOOLCHAIN='local'), text=True, capture_output=True, check=True, timeout=10)
        if result.stdout.strip():
            paths.append(Path(result.stdout.strip()).resolve())
    except (OSError, subprocess.SubprocessError):
        pass
    return paths


def validate_destination(source, destination, caches):
    if destination.exists() or destination.is_symlink():
        raise ValueError('Destination must be a new disposable directory')
    resolved, source = destination.resolve(), source.resolve()
    for cache in caches:
        cache = cache.resolve()
        if resolved == cache or cache in resolved.parents:
            raise ValueError('Destination must not be inside a Go module cache')
    if resolved == source or source in resolved.parents:
        raise ValueError('Destination must be outside the source tree')
    parts = resolved.parts
    if any(parts[index:index+2] == ('pkg', 'mod') for index in range(len(parts)-1)):
        raise ValueError('Destination must not be inside a Go module cache')


def copy_and_apply(source, destination, *, go='go', caches=None):
    source, destination = source.resolve(), destination.absolute()
    validate_destination(source, destination, module_cache_paths(go) if caches is None else caches)
    for relative, expected in MANIFEST['upstream_sha256'].items():
        candidate = source / relative
        if candidate.is_symlink() or hashlib.sha256(candidate.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Pinned source mismatch in {relative}')
    # The runner additionally verifies module Version+Sum using go mod download.
    # Reject symlinks to avoid traversing or modifying shared source elsewhere.
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('Pinned source tree must not contain symlinks')
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    destination.chmod(destination.stat().st_mode | 0o200)
    for path in destination.rglob('*'):
        path.chmod(path.stat().st_mode | 0o200)
    apply_overlay(destination)
    (destination / '.flutter-vless-unpublished-capability.json').write_text(json.dumps({
        'capability': MANIFEST['capability'], 'core_commit': MANIFEST['core_commit'],
        'published': False,
        'lifetime_patches': ['classic-udp-lifetime', 'xhttp-h3-owned-transport'],
    }, indent=2)+'\n')
    return destination


def apply_overlay(root):
    # Private: callers must use copy_and_apply; never patch a shared checkout.
    here = HERE
    def replace(path, before, after):
        file = root / path
        source = file.read_text()
        if source.count(before) != 1:
            raise ValueError(f'Pinned source mismatch in {path}; do not apply automatically')
        file.write_text(source.replace(before, after))

    path = root / 'transport/internet/dialer.go'
    source = path.read_text()
    begin = source.index('func LookupForIP(domain string, strategy DomainStrategy, localAddr net.Address)')
    end = source.index('\nfunc redirect(', begin)
    source = source[:begin] + '''// Context-free callers are intentionally unavailable in this strict prototype.
// A lost/detached transport context must never fall through to process globals.
func LookupForIP(domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	return nil, ErrNativeDNSScope
}
''' + source[end:]
    path.write_text(source)
    replace('transport/internet/dialer.go',
        'func DialSystem(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {',
        '''func DialSystem(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	operation, release, err := NativeDNSOperationContext(ctx)
	if err != nil { return nil, err }
	defer release()
	ctx = operation
	plan, err := PrepareNativeDNSPhysical(ctx, dest, sockopt)
	if err != nil { return nil, err }
	dest = plan.Destination // local socket copy only; original TLS/Host target survives.''')
    replace('transport/internet/dialer.go',
        '''	if sockopt == nil {
		return effectiveSystemDialer.Dial(ctx, src, dest, sockopt)
	}

	if newDest, err := checkAddressPortStrategy(ctx, dest, sockopt); err == nil && newDest != nil {
		errors.LogInfo(ctx, "replace destination with "+newDest.String())
		dest = *newDest
	}''',
        '''	if sockopt == nil {
		if dest.Address.Family().IsDomain() { return nil, ErrNativeDNSUnsupported }
		if _, err := nativeDNSContextFrom(ctx); err != nil { return nil, err }
		return effectiveSystemDialer.Dial(ctx, src, dest, sockopt)
	}''')
    replace('transport/internet/dialer.go',
        'LookupForIP(dest.Address.Domain(), finalStrategy, src)',
        'LookupForIPContext(ctx, dest.Address.Domain(), finalStrategy, src)')
    replace('transport/internet/dialer.go',
        '''	if len(sockopt.DialerProxy) > 0 {
		if obm == nil {
			return nil, errors.New("there is no outbound manager for dialerProxy")
		}
		h := obm.GetHandler(sockopt.DialerProxy)
		if h == nil {
			return nil, errors.New("there is no outbound handler for dialerProxy")
		}
		return redirect(ctx, dest, sockopt.DialerProxy, h), nil
	}

	return effectiveSystemDialer.Dial(ctx, src, dest, sockopt)''',
        '''	if plan.ChainTag != "" {
		handler, err := NativeDNSChainHandler(ctx, plan.ChainTag)
		if err != nil { return nil, err }
		return redirect(ctx, dest, plan.ChainTag, handler), nil
	}
	if dest.Address.Family().IsDomain() { return nil, ErrNativeDNSUnsupported }
	if _, err := nativeDNSContextFrom(ctx); err != nil { return nil, err }
	return effectiveSystemDialer.Dial(ctx, src, dest, sockopt)''')

    replace('app/proxyman/outbound/handler.go',
        '"github.com/xtls/xray-core/features/outbound"',
        '"github.com/xtls/xray-core/features/outbound"\n\t"github.com/xtls/xray-core/features/dns"')
    replace('app/proxyman/outbound/handler.go',
        'type Handler struct {\n\ttag',
        'type Handler struct {\n\tnativeDNS *internet.NativeDNSHandler\n\ttag')
    replace('app/proxyman/outbound/handler.go',
        '\tproxyConfig, err := config.ProxySettings.GetInstance()',
        '''	if config.ProxySettings == nil { return nil, internet.ErrNativeDNSIdentity }
	client, clientOK := v.GetFeature(dns.ClientType()).(dns.Client)
	manager, managerOK := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !clientOK || !managerOK { return nil, internet.ErrNativeDNSScope }
	scope, err := internet.BindNativeDNSHandler(ctx, v, config, config.Tag, config.ProxySettings.Type, client, manager)
	if err != nil { return nil, err }
	if err := scope.ValidateTransport(h.streamSettings); err != nil { return nil, err }
	h.nativeDNS = scope
	proxyConfig, err := config.ProxySettings.GetInstance()''')
    replace('app/proxyman/outbound/handler.go',
        'func (h *Handler) Dispatch(ctx context.Context, link *transport.Link) {',
        '''func (h *Handler) Dispatch(ctx context.Context, link *transport.Link) {
	owned, nativeErr := h.nativeDNS.Context(ctx, false)
	if nativeErr != nil { common.Interrupt(link.Reader); common.Interrupt(link.Writer); return }
	ctx = owned''')
    replace('app/proxyman/outbound/handler.go',
        '\th.proxy = proxyHandler\n\treturn h, nil',
        '''\th.proxy = proxyHandler
	if err := h.nativeDNS.RegisterRuntime(h); err != nil { _ = h.Close(); return nil, err }
	return h, nil''')
    replace('app/proxyman/outbound/outbound.go',
        'type Manager struct {\n\taccess',
        'type Manager struct {\n\tnativeDNSSealed bool\n\taccess')
    for signature in [
        'func (m *Manager) AddHandler(ctx context.Context, handler outbound.Handler) error {',
        'func (m *Manager) RemoveHandler(ctx context.Context, tag string) error {',
    ]:
        path = root / 'app/proxyman/outbound/outbound.go'
        text = path.read_text()
        start = text.index(signature)
        guard = '\tm.access.Lock()\n\tdefer m.access.Unlock()'
        position = text.index(guard, start) + len(guard)
        text = text[:position] + '\n\tif m.nativeDNSSealed { return errors.New("native DNS runtime is sealed") }' + text[position:]
        path.write_text(text)
    replace('app/proxyman/outbound/handler.go',
        'internet.LookupForIP(ob.Target.Address.Domain(), strategy, nil)',
        'internet.LookupForIPContext(ctx, ob.Target.Address.Domain(), strategy, nil)')
    replace('app/proxyman/outbound/handler.go',
        'func (h *Handler) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {',
        '''func (h *Handler) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	owned, err := h.nativeDNS.Context(ctx, true)
	if err != nil { return nil, err }
	operation, release, err := internet.NativeDNSOperationContext(owned)
	if err != nil { return nil, err }
	defer release()
	ctx = operation // Covers the transport's TLS/upgrade work until Dial returns.''')

    replace('proxy/freedom/freedom.go',
        'internet.LookupForIP(destination.Address.Domain(), strategy, outGateway)',
        'internet.LookupForIPContext(ctx, destination.Address.Domain(), strategy, outGateway)')
    replace('proxy/freedom/freedom.go',
        '\tvar conn stat.Connection\n\tvar blockedDest',
        '''	// AsIs final-rule inspection in upstream Core uses a separate system
	// resolver before DialSystem. This strict capability does not authorize it.
	if destination.Address.Family().IsDomain() && (defaultRule != nil || len(h.finalRules) > 0) && !h.resolveStrategy.HasStrategy() {
		return internet.ErrNativeDNSUnsupported
	}
	var conn stat.Connection
	var blockedDest''')
    replace('proxy/freedom/freedom.go',
        '''				} else {
					addrs, err := net.DefaultResolver.LookupIPAddr(ctx, destination.Address.Domain())
					if err != nil { // dialer may retry DNS
						errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", destination.Address.Domain())
					}
					for _, addr := range addrs {
						if ipAddr := net.IPAddress(addr.IP); ipAddr != nil {
							if rule := h.matchFinalRule(destination.Network, ipAddr, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
								blockedDest = &destination
								blockedDest.Address = ipAddr
								blockedRule = rule
								return nil
							}
						}
					}
				}''',
        '''				} else {
					return internet.ErrNativeDNSUnsupported
				}''')
    replace('proxy/freedom/freedom.go',
        'NewPacketWriter(conn, h, defaultRule, UDPOverride, destination, outGateway)',
        'NewPacketWriter(conn, h, defaultRule, UDPOverride, destination, outGateway, internet.NativeDNSHandlerFromContext(ctx))')
    replace('proxy/freedom/freedom.go',
        'func NewPacketWriter(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination, outGateway net.Address) buf.Writer {',
        'func NewPacketWriter(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination, outGateway net.Address, nativeScopes ...*internet.NativeDNSHandler) buf.Writer {\n\tvar nativeDNS *internet.NativeDNSHandler\n\tif len(nativeScopes) == 1 { nativeDNS = nativeScopes[0] }')
    replace('proxy/freedom/freedom.go',
        '\t\treturn &PacketWriter{\n\t\t\tPacketConnWrapper:',
        '\t\treturn &PacketWriter{\n\t\t\tNativeDNS: nativeDNS,\n\t\t\tPacketConnWrapper:')
    replace('proxy/freedom/freedom.go',
        'type PacketWriter struct {\n\t*net.PacketConnWrapper',
        'type PacketWriter struct {\n\tNativeDNS *internet.NativeDNSHandler\n\t*net.PacketConnWrapper')
    replace('proxy/freedom/freedom.go',
        'func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {',
        '''func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if _, err := w.NativeDNS.Context(context.Background(), false); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}''')
    replace('proxy/freedom/freedom.go',
        '\t\t\t\t\tif strategy := w.Handler.resolveStrategy; strategy.HasStrategy() {\n\t\t\t\t\t\tips, err := internet.LookupForIP(b.UDP.Address.Domain(), strategy, w.OutGateway)',
        '''					owned, scopeErr := w.NativeDNS.Context(context.Background(), false)
					if scopeErr != nil { b.Release(); continue }
					if strategy := w.Handler.resolveStrategy; strategy.HasStrategy() {
						ips, err := internet.LookupForIPContext(owned, b.UDP.Address.Domain(), strategy, w.OutGateway)''')
    replace('proxy/freedom/freedom.go',
        '''					if shouldUseSystemResolver {
						udpAddr, err := net.ResolveUDPAddr("udp", b.UDP.NetAddr())
						if err != nil {
							b.Release()
							continue
						} else {
							ip = net.IPAddress(udpAddr.IP)
						}
					}''',
        '''					if shouldUseSystemResolver {
						// Unresolved UDP packet names must not escape to the OS.
						ips, err := internet.LookupForIPContext(owned, b.UDP.Address.Domain(), internet.DomainStrategy_USE_IP, w.OutGateway)
						if err != nil || len(ips) == 0 { b.Release(); continue }
						ip = net.IPAddress(ips[0])
					}''')

    local_patch = here / 'local_resolver_patch.py'
    spec = importlib.util.spec_from_file_location('native_dns_local_resolver_patch', local_patch)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.apply(root, replace)

    input_patch = here / 'managed_input_patch.py'
    spec = importlib.util.spec_from_file_location('native_dns_input_patch', input_patch)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.apply(root, replace)

    classic_patch = here / 'classic_lifetime_patch.py'
    spec = importlib.util.spec_from_file_location('native_dns_classic_lifetime_patch', classic_patch)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # managed_input_patch already owns the same dispatcher payload-release
    # correction. Classic accepts only that exact state or ordinary pinned Core.
    module.apply(root, replace)

    h3_patch = here / 'h3_lifetime_patch.py'
    spec = importlib.util.spec_from_file_location('native_dns_h3_lifetime_patch', h3_patch)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.apply(root, replace)

    for source in sorted((here / 'overlay').rglob('*.go')):
        target = root / source.relative_to(here / 'overlay')
        if target.exists():
            raise ValueError('New overlay path already exists: '+str(target.relative_to(root)))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--go', default='go')
    arguments = parser.parse_args()
    try:
        copy_and_apply(arguments.source, arguments.destination, go=arguments.go)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error)+'\n')
    print('Created disposable unpublished native DNS capability source')


if __name__ == '__main__':
    main()
