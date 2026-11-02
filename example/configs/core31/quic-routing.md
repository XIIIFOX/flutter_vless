# QUIC Initial SNI routing

These two JSON examples retain the original numeric UDP destination with
`routeOnly: true` while a recovered QUIC ClientHello SNI selects the domain rule.
They are loopback fixtures, with a separate UDP-capable SOCKS server expected at
`127.0.0.1:10809`; that server is not included in either client configuration.
Replace `quic-route.invalid` with the intended server name for a real setup.

* `quic-direct-default.json`: other destinations use DIRECT; the matching SNI
  uses the SOCKS proxy.
* `quic-proxy-default.json`: other destinations use the SOCKS proxy; the matching
  SNI uses DIRECT.

The first outbound is the ordinary Core default. The plugin's generated private
inbound/default-outbound policy is separate; select the corresponding default in
example rather than relying on the original inbound's port being retained.
Use these examples only in an isolated test environment; the loopback inbound
is intentionally unauthenticated and must not be exposed to other machines.

The focused CI fixture generates encrypted QUIC v1 Initials from a genuine
`crypto/tls` ClientHello. It verifies the production QUIC decoder and actual
authenticated SOCKS UDP/native routing to independent direct/proxy origins:

* A whole Initial and out-of-order CRYPTO frames.
* Fragmentation across coalesced Initials and separate UDP datagrams.
* A hole in SNI followed by its repair, and an unrepaired hole.
* A hole in the hostname-length field, a zero-length hostname and a wrong SNI.
* A truncated packet and an authentication failure.
* Both default directions, with sniffing enabled and disabled.

Every origin receipt includes the SHA-256 of the exact encrypted datagram;
wrong-destination, duplicate and altered payloads fail. DNS is forbidden by a
resolver trap, exchanges have deadlines and owned Core/listener lifetimes drain.
The fixture is gated by `flutter_vless_core31_followups` and executes only in
remote CI. It does not qualify a complete QUIC/HTTP3 handshake, every QUIC
version, a real NAT64 network, or UDP through the Mac's TCP-only emulator relay.

The Core31 [nonempty SNI change](https://github.com/XTLS/Xray-core/commit/9b8190f52c970861c938dcd8c8c6eb696a77a900)
and [RFC 9001 Initial protection](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2)
describe the relevant protocol boundaries. No new Flutter option is needed for
these existing sniffing/routing configuration fields.
