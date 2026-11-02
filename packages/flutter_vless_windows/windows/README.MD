# Windows backend architecture

```text
Flutter app -> FlutterVlessPlugin -> V2rayManager
  proxy-only -> ProxyService -> owned Xray + system proxy preferences
  VPN        -> VpnService -> Wintun -> tun2socks
                        -> authenticated managed SOCKS -> Xray routing
```

The current VPN captures IPv4/IPv6 payload, delegates managed A/AAAA queries to
caller Core DNS, preserves imported listeners/API/services and applies owned
Windows Filtering Platform protection. Intentional direct routes remain caller
policy; physical IPv6 is limited to separately admitted endpoint/interface scopes.

There is no fixed public listener/API port and no required blanket DNS bypass.
Private ports/tags avoid caller definitions. Failed candidates preserve the
accepted session; failed workers retain the VPN's protection while recovery runs.
Explicit Stop removes the session's owned filters/routes and joins its workers.

See [runtime setup](XRAY_SETUP.md) and the
[current Windows platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/windows.md)
for capabilities, runtime pins, privilege requirements and integration steps.
