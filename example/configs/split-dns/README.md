# Per-domain DNS and data routing

[profile.json](profile.json) demonstrates an explicit split: `api.ipify.org`
uses DIRECT for both its DNS requests and website traffic; `tfox.dev/ip` and
other traffic use the first outbound, PROXY. Replace the entire `proxy` outbound
with your working server configuration, retaining its `proxy` tag and first
position. The SOCKS server `proxy.example.invalid:1080` is a placeholder and
cannot provide a connection. The file contains no server credentials.

Import this JSON in the example app, enable VPN routing, leave `Use routing from
input` set to `VPN input`, and choose `proxy` as the default outbound. The inbound
is loopback-only; use a free port if 10808 is occupied. Preserve the three
outbound tags when adapting the recipe.

The first DNS server handles only `full:api.ipify.org`. Its numeric HTTPS
endpoint avoids a separate hostname bootstrap lookup. `skipFallback` excludes
that server from unrelated fallback queries; `finalQuery` prevents fallback for
that domain after an empty answer or a resolver error. The `case-api-direct-dns` tag sends this resolver's
requests through DIRECT, while the following domain rule sends the website
through DIRECT. `localhost` retains the other DNS path; the plugin prepares
that path for its tunnel environment. The plugin does not automatically rewrite
DNS to match arbitrary domain routing rules.

Align DNS egress with the intended data path deliberately. In this example the
network and the chosen resolver can observe DIRECT DNS connections, and the
resolver receives the queried domain. HTTPS encrypts the query in transit; it
does not make DIRECT resolution anonymous. Adjust this choice for your privacy
and resolver requirements rather than copying it as a universal default.

The first UDP/443 block is an **optional experiment** to prevent QUIC attempts;
it affects every domain. It remains in this file because it was present in the
physically qualified recipe. The successful DNS variant was **not tested without
the UDP rule**; do not infer that this block is required for split DNS or that
DNS alone caused the result. Removing it changes the tested configuration.

On a physical iPhone with Core 26.10.29-r3, the original implicit-DNS case did
not complete the DIRECT API request. Adding only the UDP block also did not
resolve it. Starting from that failed UDP-block control, adding the per-domain
DNS server and its DIRECT routing rule produced HTTP 200 and the ordinary IP
on the API site, while the other site showed the proxy IP in the same session.
The reverse split also passed. Actual resolver answer addresses were not
captured, so a GeoDNS cause was not established. These observations validate
that scoped configuration on that network, not every resolver or platform.

The root adapter tests read this file, parse it, and verify that Android, iOS,
macOS and Windows start/delay calls retain its DNS and routing objects. Those
mock-channel checks establish the Dart forwarding contract, not native DNS or
network correctness. Repeat real two-domain checks after replacing the proxy
outbound or changing the resolver, rules, network or native SDK.
