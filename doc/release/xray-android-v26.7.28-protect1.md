# XRay Android v26.7.28-protect1

Runtime revision of Xray-core v26.7.28, packaged as:

```
dev.tfox.fluttervless:xray-android:26.7.28-protect1
```

* Added transport socket protection through the plugin's authenticated native descriptor broker. Failed required protection rejects startup or socket use.
* Added physical-Network DNS integration, including Android Private DNS support, through the matching plugin broker.
* Included armeabi-v7a, arm64-v8a, x86, and x86_64 runtimes, tun2socks, and geo assets.
* Preserved standalone proxy-only operation.

VPN mode requires the corresponding socket-broker implementation in `flutter_vless_android`; do not pair this revision with an older plugin that excludes its entire host UID. Explicit application bypass rules retain their meaning. The release assets include the same AAR served by Maven Central and its SHA-256 checksum.
