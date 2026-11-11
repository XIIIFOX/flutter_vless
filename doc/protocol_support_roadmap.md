# Protocol and transport support

The native previews in this repository target Xray-core **26.11.9**. Generated configurations must
match the actual loaded runtime and remote server. See [compatibility](compatibility.md)
for platform protection, DNS and real-network limits.

## Client profiles

| Core outbound | Import paths |
| --- | --- |
| `vless`, `vmess`, `trojan` | Share links, Clash YAML, sing-box JSON and raw Xray JSON |
| `shadowsocks` | `ss://`, Clash YAML, sing-box JSON and raw Xray JSON |
| `socks` | `socks://`, Clash YAML, sing-box JSON and raw Xray JSON |
| `wireguard` | Clash YAML, sing-box JSON and raw Xray JSON; no `wireguard://` parser |
| `hysteria` version 2 | `hysteria2://` / `hy2://`, Clash YAML, sing-box JSON and raw Xray JSON |
| `http` | Clash YAML, sing-box JSON and raw Xray JSON; arbitrary browser URLs are not proxy profiles |
| `masque` | Raw Xray JSON with native endpoint preparation and header preservation |

`freedom`, `blackhole`, `dns` and `loopback` are routing/runtime composition
features, available through raw JSON rather than remote-server share links.
Hysteria2 imports use Core's `hysteria` protocol and transport with version 2.

## Transports

These transports are used where the selected protocol supports them:

| Transport | Behavior |
| --- | --- |
| `raw` / `tcp` | `type=raw` emits `rawSettings`; legacy `type=tcp` remains supported |
| `xhttp` | VLESS and subscription imports; caller headers, uplink method and independent download settings are preserved |
| `grpc` | Supported import path |
| `websocket` / `ws` | Supported import path |
| `mkcp` / `kcp` | Both aliases are normalized during subscription import |
| `httpupgrade` | Share links, Clash YAML and sing-box JSON; non-Host headers are preserved |
| `hysteria` | Used by Hysteria2 import paths |
| `masque` | Raw Core transport; complete TLS/QUIC and device acceptance depends on the target deployment |
| `quic` | Legacy transport removed by the pinned Core; HTTP/3 uses XHTTP with TLS/ALPN `h3` |
| `xdrive` | Raw S3/Google Drive profiles with protected cloud endpoint preparation and required managed-service lifetime capabilities |

TLS, Reality, `FinalMask` and `sockopt` settings remain part of the relevant
configuration. Typed helpers do not replace full JSON for fields they do not
model. XDRIVE `local` and `template` services are not admitted; see
[XDRIVE examples](../example/xdrive/README.md).

## Inbounds and VPN context

The plugin generates an authenticated local SOCKS adapter for its VPN path.
Imported `socks`, `mixed`, `http`, `dokodemo-door` and other Core inbounds remain
raw configuration. Retaining an imported inbound does not turn a client app
into a qualified server deployment or copy all of its routing rules onto the
private VPN adapter. Use [per-session routing](../example/README.md#per-session-vpn-routing)
when that source context is required.

## References

- [Pinned Core protocol inventory](https://github.com/XTLS/Xray-core/blob/676eaf66f8f05d4d558ee7a74b4736623d3feeb9/infra/conf/xray.go)
- [Pinned Core transport builder](https://github.com/XTLS/Xray-core/blob/676eaf66f8f05d4d558ee7a74b4736623d3feeb9/infra/conf/transport_internet.go)
- [Configuration guide](configuration.md)
