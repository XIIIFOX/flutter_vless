# Core31 XHTTP and HTTP inbound examples

These loopback examples use a fixed public test UUID, not an account credential.
Use the matching client/server pair with a locally generated certificate whose
DNS name is `core31-xhttp.invalid`. Place its PEM certificate and private key at
the relative paths shown in the server JSON; the client receives only the
certificate. Keep the private key outside Git. The client verifies this local
authority and negotiates HTTP/2; it does not disable certificate verification.
Certificate paths are resolved relative to the Core process working directory.

`xhttp-options-client.json` chooses `uplinkHTTPMethod: "OPTIONS"` in `extra`.
The ordinary uplink carries tunnel bytes and does **not** set
`Access-Control-Request-Method`. A real CORS preflight sets that header and asks
permission; it receives a CORS response without opening a tunnel stream.
Do not add preflight headers to the data uplink.

`xhttp-h2params-server.json` configures the **server's** HTTP/2 stack. Its
non-default concurrency limit and maximum frame size are observable in the
server's initial HTTP/2 SETTINGS frame. They are not client Flutter options.
If using `extra`, place the extended fields inside it: Core treats that object
as the extended settings, while keeping the outer host/path/mode.

`http-inbound-continue.json` is a local HTTP proxy for upload tests. A client
sends headers with `Expect: 100-continue`, waits for the origin's interim 100
response through Core, then sends the body and checks the final response.
This inbound is independent of the plugin's managed SOCKS inbound. Do not use
a SOCKS request or HTTPS CONNECT in place of the plain HTTP upload case: those
would exercise different code paths.

The tagged CI fixtures test actual Core XHTTP TLS/H2 round trips for POST and
OPTIONS in packet-up, stream-up and stream-one; real H2 SETTINGS, preflight and
wrong-path controls; malformed h2Params admission/cleanup; and actual HTTP
inbound uploads with short/fragmented 100 responses, 417 rejection, truncated
interim responses and cancellation. Each owns and closes its loopback sockets,
workers and Core instances, with fixed deadlines. Results are qualified by the
focused follow-up runner, rather than inferred from these JSON examples.

Sources: [OPTIONS versus preflight](https://github.com/XTLS/Xray-core/commit/e7a69fa85a18146e83e008b6ec0a72e996dc6cf9),
[server h2Params](https://github.com/XTLS/Xray-core/commit/316e07a53822aa23661cb3f8b30e1132911c5b36),
[short 100 response forwarding](https://github.com/XTLS/Xray-core/commit/bc7c895278a895a87881953e1ec522fcdb0f885b).
