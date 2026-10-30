# Freedom masks in Xray 26.10.29

These are outbound configuration examples, not VPN server profiles. Merge the
chosen outbound into a complete configuration. They contain no credentials and
do not connect anywhere by themselves.

Compare [legacy-freedom.json](legacy-freedom.json) with
[finalmask.json](finalmask.json). The old Freedom fields are still accepted by
Xray 26.10.29, but emit a deprecation warning. The new configuration puts a
`fragment` mask in `streamSettings.finalmask.tcp` and a `noise` mask in
`streamSettings.finalmask.udp`.

| Legacy field | New field in this example |
| --- | --- |
| `settings.fragment.packets` | `finalmask.tcp[0].settings.packets` |
| `settings.fragment.length` | `finalmask.tcp[0].settings.length` |
| `settings.fragment.interval` | `finalmask.tcp[0].settings.delay` |
| `settings.noises[].packet` with `type: rand` | `finalmask.udp[0].settings.noise[].rand` |
| `settings.noises[].delay` | `finalmask.udp[0].settings.noise[].delay` |

The UDP example uses `reset: 0` and applies to both address families. It does
not translate a legacy `applyTo: ipv4` or `ipv6` restriction. Keep such policies
explicit when migrating; do not silently discard them. Mask ordering, reset
timing, scripts and transport placement can also change behavior. The plugin
preserves the chosen JSON instead of automatically rewriting legacy settings.

Actual pinned-Core configuration tests compare the compiled fragment/noise
ranges for this pair, including `interval` to `delay`, on the remote Linux,
Windows and macOS runners. These checks do not promise identical network
fingerprints or demonstrate a masking benefit on a particular network.

Sources: [upstream deprecation change](https://github.com/XTLS/Xray-core/commit/613d8147bb2b3bcfb0600a525c33260a9a2ca5f6),
[pinned mask schema](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_finalmask.go).
