# XRay iOS v26.7.28-r3

Runtime revision of Xray-core v26.7.28 for iOS 15 and newer.

* Added the `XRayStartPrivate` bridge and structured native diagnostics without imported log destinations or credentials.
* Disabled raw access/error output, REALITY debug printing, TLS key files, and corresponding nested XHTTP/finalmask debug output.
* Preserved dynamic geo asset loading and the 128 KiB HTTP/2 upload scratch-buffer cap.
* Included arm64 device and arm64/x86_64 simulator slices.

Download `XRay.xcframework.zip` and verify SHA-256:

```
3792dc3ae6ffa42922c4604827812e48e29307d381d5db40a2c3932e0b779a60
```

The core version remains 26.7.28; r3 identifies the mobile wrapper revision. iOS VPN routing and recovery are implemented by the plugin and Packet Tunnel provider, which must be updated separately when integrating the current example.
