"""Release the pinned XHTTP TCP listener when server h2Params parsing fails.

Applied only to disposable producer/acceptance source copies. Listener.Close
also closes the underlying socket after TLS/REALITY wrapping. The success path,
HTTP/2 settings, public capability values and caller configuration are unchanged.
"""
import hashlib
from pathlib import Path

PATH = 'transport/internet/splithttp/hub.go'
UPSTREAM_SHA256 = {
    PATH: 'a651b04643dde70653955a55501f4607d7ed6bb647ea3d39596fb63f7d734aaa',
}
PATHS = tuple(UPSTREAM_SHA256)

BEFORE = '''\t\t\tif err := json.Unmarshal(l.config.H2Params, http2Config); err != nil {
\t\t\t\treturn nil, errors.New("failed to parse HTTP2Config").Base(err)
\t\t\t}'''

AFTER = '''\t\t\tif err := json.Unmarshal(l.config.H2Params, http2Config); err != nil {
\t\t\t\t_ = l.listener.Close()
\t\t\t\treturn nil, errors.New("failed to parse HTTP2Config").Base(err)
\t\t\t}'''


def replacements():
    return [(PATH, BEFORE, AFTER)]


def _regular_source(root):
    path = root / PATH
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError('XHTTP listener source must be a real file without symlink parents')
        if candidate == root:
            break
    if not path.is_file():
        raise ValueError('XHTTP listener source must be a real file')
    return path


def apply(root, replace):
    root = Path(root)
    path = _regular_source(root)
    if hashlib.sha256(path.read_bytes()).hexdigest() != UPSTREAM_SHA256[PATH]:
        raise ValueError('Pinned XHTTP listener source mismatch: ' + PATH)
    source = path.read_text(encoding='utf-8')
    if source.count(BEFORE) != 1:
        raise ValueError('Pinned XHTTP listener replacement boundary changed')
    expected = source.replace(BEFORE, AFTER)
    replace(PATH, BEFORE, AFTER)
    # Guard the producer callback too: a no-op must not yield an "applied"
    # receipt. Universal-newline reads allow the producer's Windows text copy.
    if _regular_source(root).read_text(encoding='utf-8') != expected:
        raise ValueError('XHTTP listener callback did not apply the exact owned edit')
