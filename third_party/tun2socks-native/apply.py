"""Separate pinned Android-only forwarder copy. Never patch a module cache."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / 'pin-manifest.json').read_text())


def copy_and_apply(source, destination, go='go'):
    spec = importlib.util.spec_from_file_location('forwarder_destination_guard', HERE.parent / 'xray-native-dns/apply.py')
    guards = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guards)
    guards.validate_destination(source, destination, guards.module_cache_paths(go))
    for relative, expected in MANIFEST['upstream_sha256'].items():
        path = source / relative
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Pinned forwarder source differs')
    if any(p.is_symlink() for p in source.rglob('*')):
        raise ValueError('Pinned forwarder contains a symlink')
    shutil.copytree(source, destination)
    for path in [destination, *destination.rglob('*')]:
        path.chmod(path.stat().st_mode | 0o200)
    # A private API avoids upstream log.Fatalf and never invokes TUN hooks,
    # interface binding, REST API or route changes. The child owns one engine.
    for path in (HERE / 'overlay').rglob('*.go'):
        target = destination / path.relative_to(HERE / 'overlay')
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise ValueError('Forwarder overlay must be additive')
        shutil.copyfile(path, target)
    path = destination / 'proxy/socks5.go'
    text = path.read_text()
    start = text.index('func (ss *Socks5) DialUDP(')
    end = text.index('\ntype socksPacketConn struct', start)
    text = text[:start] + '''func (ss *Socks5) DialUDP(_ *M.Metadata) (net.PacketConn, error) {
        return nativeBoundUDP(ss)
    }
''' + text[end:]
    # Exact response source is verified before decoding any SOCKS datagram.
    before = '''\tn, _, err := pc.PacketConn.ReadFrom(b)
\tif err != nil {
\t\treturn 0, nil, err
\t}'''
    if text.count(before) != 1:
        raise ValueError('Pinned forwarder UDP reader differs')
    text = text.replace(before, '''    var n int
    for {
        size, source, err := pc.PacketConn.ReadFrom(b)
        if err != nil { return 0, nil, err }
        if !nativeSameUDPSource(source, pc.rAddr) { continue }
        n = size
        break
    }''')
    # io is now owned by the additive, bounded private UDP adapter.
    text = text.replace('\n\t"io"', '').replace('\n\t"errors"', '')
    path.write_text(text)
    path = destination / 'transport/socks5/socks5.go'
    text = path.read_text()
    edits = [
        ('\tif buf[0] != Version {', '\tif buf[0] != Version || buf[1] != method {'),
        ('\t\tif buf[1] != 0x00 /* STATUS of SUCCESS */ {', '\t\tif buf[0] != 0x01 || buf[1] != 0x00 /* STATUS of SUCCESS */ {'),
        ('\tif rep := Reply(buf[1]); rep != 0x00 /* SUCCEEDED */ {',
         '\tif buf[0] != Version || buf[2] != 0 { return nil, errors.New("private SOCKS reply refused") }\n\tif rep := Reply(buf[1]); rep != 0x00 /* SUCCEEDED */ {'),
    ]
    for before, after in edits:
        if text.count(before) != 1:
            raise ValueError('Pinned SOCKS handshake differs')
        text = text.replace(before, after)
    path.write_text(text)
    return destination
