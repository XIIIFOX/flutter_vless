# Android security emulator acceptance

Run `tool/test_android_security_emulator.sh` with a booted, dedicated Android
emulator. Set `ANDROID_SERIAL=emulator-5554` (using the actual serial) when more
than one emulator is connected. The harness rejects physical devices and checks
that the selected emulator has finished booting.
It enables the emulator's Wi-Fi and connects to its standard `AndroidWifi`
virtual access point before building. Host Wi-Fi is unaffected.

Keep the computer's VPN enabled. The script does not modify host routes, DNS,
interfaces, or VPN settings. Its fixture listeners bind only to `127.0.0.1`,
reached from the emulator as `10.0.2.2`. Reserved test names and control requests
remain in those fixtures. Ordinary readiness checks use existing host networking.

Prerequisites are Flutter, Python 3, Android SDK (`ANDROID_HOME` or
`ANDROID_SDK_ROOT`), and JDK 17 or newer. On macOS, existing standard Android SDK
and Android Studio JBR locations are recognized if the corresponding environment
variables are absent. The script runs `flutter pub get`, then builds and installs
the plugin's AndroidTest APK using the committed official runtime checksums and
strict Gradle dependency verification. Development runtime overrides are refused.

The default run covers native local authorization, encrypted authorized-profile
storage, worker and service recovery, invalid replacement, explicit stop, rapid
START/STOP ordering and final-session ownership, host
TCP/UDP capture, explicit exclusion and proxy-only behavior, rejected socket
protection, controlled direct/proxy domain routing before and after worker
recovery, local-secret rotation, STOP followed by an invalid START, delay IPC,
and HTTP/SOCKS/VLESS system DNS with recovery and failure checks. It also covers
Android always-on/lockdown behavior, missing Keystore keys, and actual VPN
permission revocation through Android Settings. Private supplied profiles are
excluded from this harness.
An emulator physical-interface packet capture additionally requires positive
observations through all three proxies and no reserved test names in direct
UDP/TCP port 53 traffic. These assertions concern the controlled system-DNS
queries; they do not claim to classify arbitrary application DoH traffic.
For DNS capture, the harness temporarily disables only the emulator's Wi-Fi so
the traffic uses the cellular Ethernet backend covered by the emulator console
capture. It restores `AndroidWifi` afterward, including on failure. The separate
handover test covers both emulator transports.

DNS traffic assertions begin after the new session emits `CONNECTED` and a real
request reaches the fixture through the TUN. Acceptance of a start command, or
Android announcing a VPN network, does not establish readiness. Local packet
capture detected an explicit test DNS query escaping during the first cold-start
`CONNECTING` transition, before TUN descriptor delivery to tun2socks and `CONNECTED`.
The readiness test now observes the new session's state transition, and the
capture verifier still inspects every captured packet without timing exclusions.
Android always-on/lockdown behavior across that initial transition is a separate
OS-level acceptance case.

The harness also runs Wi-Fi → cellular → Wi-Fi recovery and the existing
physical-network resolver control. The latter requires a functioning upstream
emulator resolver for `example.com`. The handover case alone may report an
assumption skip if a required emulator transport is absent; the summary records
that skip distinctly. Every other selected test must pass without skips.

`--no-capture` omits physical packet capture for a narrower local check. It does
not establish the absence of duplicate plaintext DNS leaks. CI should use the
default capture mode.

The physical resolver control also checks the emulator's baseline DNS setup.
If it cannot resolve before any VPN is active, restart only the dedicated AVD
with `-dns-server` set to a resolver reachable through the computer's existing
network. Do not disable the host VPN. On the local macOS validation machine,
`/etc/resolv.conf` contained no resolver entries, while the system resolver shown
by `scutil --dns` answered directly. Passing that reachable address explicitly to
the emulator restored the baseline control; public UDP resolvers were unreachable.
Choose the address for the current environment rather than copying a private
resolver address from another computer.

Each run creates `build/android-security-emulator.<unique>/` with build logs,
individual instrumentation logs, fixture logs/events, the packet capture and its
sanitized verification counts, and `summary.json`. Build and test commands have
bounded execution times. ADB's exit status alone is insufficient: the harness
checks the status and expected count of completed tests. Failures, crashes,
unexpected skips, fixture startup failures, capture errors, and timeouts cause a
nonzero script exit. Only the explicitly reported handover transport-prerequisite
skip is permitted.

On exit the script stops only its own fixture processes and force-stops the test
package (`com.github.tfox.flutter_vless.test`) to remove its VPN service and
suppress sticky restart. It resets that package's VPN permission to its default
state. It does not stop the emulator or change another application's VPN.

The OS policy suite requires no existing always-on VPN on the dedicated emulator.
The harness installs a disposable adversary APK using the standalone builder's
`--install-only` mode, and uninstalls it only after that invocation confirms a
successful installation. The suite changes policy through Android Settings and
restores it afterward. If a crash or timeout leaves the harness test package as
the always-on VPN owner, cleanup removes only that test package so Android also
clears its live lockdown state, and the harness remains failed. Merely rewriting
secure settings would not reliably clear Android's active VPN manager policy.

The local run on 2026-09-12 recorded **15/15 instrumentation tests passing with
zero skips** in `build/android-security-emulator.0ZnfX1CE/summary.json`. Its
unfiltered physical capture contained 1,380 packets: zero controlled direct DNS
queries, zero incomplete direct DNS TCP streams, and positive proxy observations
for HTTP (5), SOCKS (7), and VLESS (5). The rapid START/STOP regression also passed
separately (1/1) before being added to the default harness. These are completed
observations; subsequent acceptance cases are verified in their own runs.

The final expanded run on the same date passed **21/21 instrumentation tests,
zero skips**, including all OS policy, replacement, and delay cases. Evidence is
in `build/android-security-emulator.Dc18RVQb/`: `summary.json`, individual test
logs, and `dns-capture-verification.json`. Its complete capture contained 1,479
packets, zero controlled direct DNS queries, zero incomplete direct DNS TCP
streams, and HTTP/SOCKS/VLESS proxy observations of 5/7/5. A separate readback in
`cleanup-audit.json` confirmed no always-on owner, lockdown disabled, the
disposable adversary removed, and the test VPN service stopped. The test APK was
retained for the subsequent separate-UID CI step. The computer's VPN settings
were unchanged.
