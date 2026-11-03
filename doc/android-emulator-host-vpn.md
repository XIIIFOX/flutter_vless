# Android emulator with the Mac VPN left connected

Validated on 2026-11-02 with Android Emulator 36.6.11, the signed example
1.1.7+117 and public Maven Core 26.10.31-protect1. No plugin was published.
No Mac VPN profile, system route, DNS configuration or system proxy was changed.

The follow-up on 2026-11-03 uses the published `26.10.31-protect2` runtime
and the Android wrapper source `1.1.7+1`. A normal socket timeout closes only
its relay tunnel, retaining the listener for subsequent connections. The new
regression exercises that timeout, another real CONNECT exchange and complete
worker/socket cleanup; all 20 helper tests pass locally. The original dated
acceptance below remains the record for its earlier 19-test workflow run.

## Working transport

Two independent controls exposed the network restrictions:

* Ordinary Mac sockets to the supplied VPN peers established TCP but stalled
  during TLS. Selecting the physical interface on **only those peer sockets**
  completed TLS in about 0.3 seconds. The same stock Android Core then obtained
  both public IP API responses.
* The application's protected DNS lookups used emulator DNS alias 10.0.2.3,
  with unanswered peer-name requests and no outbound peer TCP. Public UDP DNS
  endpoints did not answer from this Mac; its currently configured DNS did.
  Passing that responsive DNS server to the emulator restored bootstrap lookup.

The final launch combines the current working Mac DNS, an emulator-level TCP
proxy and exact peer-only interface selection. The original VLESS hostname,
Reality identity and caller DNS/configuration are retained. Changing MSS alone
and reverting WiFiPacketStream alone did not establish a healthy reference.
The legacy Wi-Fi flag is retained in the tested launch, not claimed as the cause.

The proxy tunnels encrypted bytes without TLS interception. Connections to
explicitly selected public IPv4 VPN peers on port 443 use the specified physical
interface, outside the existing Mac VPN. Other relay connections use ordinary
Mac routing, including its active VPN. Thus **DIRECT in this test means the
emulator's ordinary egress under the unchanged Mac VPN**, not an ISP-bypass claim.

## Reproduce

Use a separate test AVD and a private directory (`umask 077`). Inspect
`scutil --dns` and test the selected current DNS before launch; do not assume
that public DNS on UDP/53 is reachable. Identify the physical interface without
changing the Mac network settings. Resolve the supplied VPN endpoint to its
current public IPv4 addresses through that DNS.

Create an owned regular 0600 allowlist JSON with pre-resolved destinations:

```json
{"destinations":[{"host":"YOUR_VPN_HOSTNAME","ports":[443],"addresses":["YOUR_PUBLIC_VPN_IPV4"]}]}
```

Create a separate owned regular 0600 peer-policy JSON:

```json
{"peers":[{"address":"YOUR_PUBLIC_VPN_IPV4","port":443,"interface":"en0"}]}
```

Replace the placeholders and interface for the actual machine. Keep profile
credentials outside Git and command arguments. Start the bounded relay in a
separate terminal; the ready file records its PID, source hash and localhost port:

```sh
python3 tool/android_emulator_tcp_relay.py \
  --allowlist "$test_dir/destinations.json" \
  --emulator-public-tcp \
  --peer-policy "$test_dir/peers.json" \
  --ready "$test_dir/ready.json" \
  --result "$test_dir/result.json" \
  --stop-file "$test_dir/stop" \
  --server-seconds 1200
```

`test_dir` is the operator's private directory. In another terminal use the
returned port, the responsive DNS server and the owned test AVD:

```sh
emulator -avd "$test_avd" \
  -feature -WiFiPacketStream \
  -dns-server "$test_dns" \
  -http-proxy "http://127.0.0.1:$relay_port" \
  -no-snapshot -netdelay none -netspeed full
```

This is the **emulator proxy**, not Android's system HTTP proxy. It handles TCP;
UDP is not redirected. Peer binding requires Darwin and fails closed if the
interface disappears or cannot be applied. It never retries the selected peer
through the ordinary socket path. IPv4-mapped IPv6 cannot bypass the policy.
The explicit public mode admits numeric public destinations on ports 80/443;
private/loopback destinations and arbitrary hostname resolution are not enabled.

After testing, disconnect in example, verify ordinary browsing, stop the owned
AVD, create the relay stop file, and wait for its process. Require `closed=true`,
zero active workers/sockets and no unexpected worker exceptions. Stop only the
ADB/forwards/drivers created by the test; preserve unrelated work.

## Live result

Fresh Chrome DevTools requests disabled cache/service workers, matched HTTP 200
bodies to complete DOM text, checked the visible Chrome page and saved private
screenshots. A fresh OFF baseline and an all-proxy reference preceded the splits.

| Example policy | api.ipify.org | checkip.amazonaws.com |
| --- | --- | --- |
| All proxy reference | VPN egress | VPN egress |
| Default DIRECT, IPify PROXY rule | VPN egress | Ordinary Mac-VPN egress |
| Default PROXY, IPify bypass | Ordinary Mac-VPN egress | VPN egress |

Both split directions pass on the same published runtime and imported P1
profile. The original endpoint remains a hostname; no caller DNS section was
injected. Sessions stop in 18.50, 17.55 and 17.78 seconds respectively, with
normal UI disconnect, native fullStop acknowledgement and VPN/Core OFF. Each
post-Stop pair returns the original ordinary address. Temporary processes,
relay sockets, emulator, private ADB and forwards are closed; four Mac network
configuration snapshots remain identical.

The current tfox.dev DNS failure was recorded separately; this acceptance uses
two responsive independent IP APIs. No result for tfox or 2ip is inferred.
These checks qualify the specified TCP setup, not arbitrary UDP/IPv6 transports.
The relay's 19 focused tests pass locally and on macOS/Linux in the
[three-OS helper workflow](https://github.com/XIIIFOX/flutter_vless/actions/runs/41435222473).
Windows passes the 17 applicable tests and skips two POSIX file-permission
checks. That workflow tests the helper; it is not a new native VPN acceptance.

Official references: [emulator proxy behavior](https://developer.android.com/studio/run/emulator-networking-proxy),
[legacy network flag](https://developer.android.com/studio/run/emulator-networking-interconnect),
[DNS/startup options](https://developer.android.com/studio/run/emulator-commandline).
