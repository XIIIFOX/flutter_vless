# Windows Core TUN leak rules

`windows-core-tun-leaks.json` documents **standalone Core TUN** configuration.
It is not a switch for the Flutter plugin's existing VPN/WFP implementation,
and must not be enabled alongside that implementation. This example changes
Windows routes and expects a separately configured resolver at `198.18.31.2`;
replace the example topology before using it on a disposable Windows machine.
It does not provide that resolver or a proxy server.

`tcp/<port>` and `udp/<port>` select the protocol independently. `dns` expands
to UDP/TCP 53, Windows DNS Client restrictions, TCP 853 and UDP 853. Entries are
case-insensitive, normalized and deduplicated. Ports must be 1 through 65535.
Core requires `autoSystemRoutingTable`; DNS blocking additionally requires
the TUN's DNS configuration. The DNS server must be reachable through the TUN.

The new acceptance invokes the **actual Core filter installer** in elevated
Windows Actions, with loopback standing in for the TUN interface. It creates no
TUN adapter and changes no routes/DNS. Exact TCP/UDP payloads first work from a
separate executable. A real, distinct nonloopback interface LUID then stands
in for a nonmatching TUN and blocks that client on two
random ports and TCP/UDP 853, while Core's own executable stays permitted.
TCP blocking must report the kernel's access-denied error. Windows may silently
drop UDP after a successful send, so a UDP timeout alone never counts as proof:
the owned origin must receive zero copies of that phase's fresh nonce. Exact
nonce receipts are checked per endpoint in every phase and again after the
origin readers stop, so delayed packets cannot turn a drop into a false pass.
Opposite protocols on the two custom ports and two unlisted endpoints must
continue to exchange exact bytes while those filters are active; widening a
port rule into a protocol-wide block therefore fails the test.
The real WFP inventory must contain each typed protocol/remote-port block and
matching interface permit on all four ALE layers, including the selected LUID;
the test does not infer installed conditions from filter names or timeouts.
Selecting the real loopback interface as the TUN must permit the independent
client again. Closing each dynamic WFP session must restore the exact filter
ID baseline and ordinary payload exchange. Permission errors and missing
prerequisites fail the acceptance rather than silently skip it.

This qualifies the port-filter mechanism, application exemption, interface
conditions and owned-filter deletion. It does not claim a complete Wintun
adapter, system DNS resolver, physical IPv6 or production Windows network test.

Source: [Core31 TUN changes](https://github.com/XTLS/Xray-core/commit/6cdd323ad82fe21bb9c1d06e6a5c5f909de2ffaf).
