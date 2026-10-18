# Private Android forwarder preview

This is a separate, unpublished development artifact for the scoped Core DNS
input. It does not replace any packaged tun2socks binary or enable a public API.
The baseline module/commit/checksum are fixed in `pin-manifest.json`; the copier
refuses changed patch targets and Go module-cache destinations.

The private entry accepts only `-sock-path <absolute-private-dir>/tun-fd` and
`-config <absolute-0600-file>`. The bounded YAML contains exactly `proxy`, `mtu`
and `loglevel`: an authenticated numeric IPv4 loopback SOCKS endpoint, 1500, and
`error`. The engine suppresses raw logs. It exposes no REST API, TUN hooks,
interface binding, route or DNS changes. Parent EOF/signals stop the child.

The Unix socket requires a same-UID peer, exactly one SCM_RIGHTS descriptor with
byte `0x20`, and sender write EOF. Only a TUN/no-PI descriptor passing the Linux
ioctl check enters the engine. The child owns its duplicate; rejected descriptors
and temporary socket paths are closed. Failed engine construction reports
whether it adopted the descriptor so the caller cannot double-close it.

UDP binds `127.0.0.1:nonzero` before its password handshake and declares that
tuple to Core. Method downgrade, malformed version/reserved replies, nonloopback
relay endpoints and packets from a different relay are refused. Handshakes are
bounded; control EOF closes the bound UDP socket. This is an Android-only
development path, with no per-datagram authentication or adversarial UID/reuse
isolation claim. Ordinary UDP forwarding and full DNS/IPv6 semantics still depend
on the pending Core consumer work.

`tool/test_native_tun_preview.py` runs synthetic SOCKS loopback fixtures and pure
policy tests. On Linux it also tests SCM_RIGHTS ownership using a non-TUN file;
it never starts the engine or opens a TUN. Other hosts compile the Linux tests.
The Android builder emits a separate PIE `libtun2socks_preview.so` with 16 KiB
LOAD alignment. The verifier requires its exact current source snapshot,
capability, module pin, checksum and one verified JNI payload.

Actual TUN, system DNS, browser and handover acceptance is a separate gate after
the scoped Core UDP controls pass remotely. The Android harness accepts this
build through `--native-tun-preview BUILD_DIRECTORY` together with
`--native-dns-preview BUILD_DIRECTORY`. It matches both packaged JNI payloads to
fresh build verification reports before installation. Ordinary OS-policy tests
use a Core-only APK; a second APK adds the development VPN service immediately
before its five TUN scenarios, preserving Android's app-wide Always-on semantics.
CI depends on all three scoped Core jobs and the Linux descriptor fixtures;
their success does not substitute for the separate Android runtime result.
The workflow keeps the TUN option disabled until ordinary Android acceptance
succeeds; compiling or verifying these payloads does not open that gate.
The existing dirty/opaque packaged
forwarder is not claimed to be reproduced by this new pinned development copy.
