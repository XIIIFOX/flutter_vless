# Native Core 26.10.31 qualification

Flutter packages remain **1.1.7**; no plugin package or `v1.1.7` release is
published. The owner's Mac VPN stays on. Live macOS VPN acceptance is excluded.

## Published native bytes

All four native releases use upstream commit
`a4a3dff5b20c2faae567b742c172c7b95e75c083` and producer
`13c47ed2caabd70b082449ed4917ce65574df91e`.

| Runtime | Public identity | Canonical archive SHA-256 |
| --- | --- | --- |
| Android | [Maven/GitHub 26.10.31-protect1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.10.31-protect1) | AAR `4c7080a48106e1b0369d7aba68a4969382de22a21ecf7c89f3e86685adb8d704` |
| iOS | [26.10.31-r1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-ios-v26.10.31-r1) | `22813f46cd978341a2f6aa61f8d346fb57393c53a9f271d5f42b6b1a3371b9cc` |
| macOS | [26.10.31-r1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-macos-v26.10.31-r1) | `15de3fed0dc69604ba0a76172ff0d1550f2d64ebc1c173109e2308ef657cb07c` |
| Windows AMD64 | [26.10.31-r1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-windows-v26.10.31-r1) | `19268b7f9f5ddedbcf9c3cb294175f28f1c6a4d495327e790f8e519e8073aa48` |

Public payloads match their qualified producer artifacts. Android was published
from the same USER_MANAGED Central deployment after review, without rebuilding
or uploading another bundle; all public Maven payloads and signatures match.
Apple consumers include exact public vendored SDK trees as well as updated
SwiftPM/CocoaPods pins. Merely changing URLs would leave existing vendored
frameworks selected, so both trees were replaced and checked member by member.

The shared MPTCP default-off method is identical to official Core in all five
protected/ordinary/routing source compositions. It belongs to the shared
listener reached by the in-process SDK, not just a CLI initializer. Explicit
caller socket policy is retained. Go 1.27.3, Root CA filtering and Apple H2BUF
128 KiB remain qualified.

## Completed checks

* [Core31 CI on Linux/macOS/Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41350987225)
  at `d9316e9356b27720d13b081d06d7fc931ebcdb03`: 340 supervised phases, 790
  exact source bindings, numeric SOCKS/TLS-SNI routing in both directions,
  IPv6/DNS/NAT64 address carriage, S3 encrypted relay and Google OAuth/API
  contracts, nine typed ECH cases and 21 strict H3 certificate rejection cases.
  Thirteen S3 HTTP/thread controls per OS pass with no hidden thread exceptions.
  The producer and validation heads have identical native-producing sources.
* [Apple native producer](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349615824):
  both SDKs execute version/capability/custom-root checks in Actions; all five
  architecture slices pass 16 strong C-export checks each. Source/tree/ZIP
  receipts and fresh anonymous public downloads agree.
* [Windows producer](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349615668):
  all six Windows 2022/2025 jobs pass. Each OS verifies 189 VPN, 21 proxy and
  21 portable cases plus numeric IPv6/WFP controls. The two Core executables
  are byte-identical and match the compiled 1.1.7.117 example bundles.
* Fourteen consumer-pin contracts pass: all platform defaults, Apple tags and
  checksum agreement, Android strict Maven checksums/preview commit, and all
  unchanged Flutter package versions. The legacy stock17 Android test-input
  fixture remains explicitly historical; its old bodies are not relabelled.

## Post-publication acceptance in progress

The public-byte Windows workflow mode installs the fixed released ZIP and
manifest, checks hashes and executes version/capabilities before the full
existing native/example/VPN matrix; it skips rebuilding and packaging Core.
The corresponding fresh Actions run and public Apple runtime checks are
pending the consumer commit.

Physical iPhone and VPN-compatible local Android emulator checks on the new
published runtimes are pending. Earlier 26.10.29 device passes are not inherited
as 26.10.31 passes. Both split directions need current OFF/reference controls;
external 2ip Loading and unhealthy peer references must remain explicit limits.

Final device results, cleanup and the concrete remaining plugin-release work
will be added after these checks. Full accounts, physical IPv6-only/NAT64 and
handover conditions are separate from controlled fixtures. No native Core/SDK
is executed on the owner's Mac for this stage.
