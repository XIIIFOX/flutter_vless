# Android separate-UID authorization regression

`tool/test_android_separate_uid.py` builds a disposable Java APK with the Android SDK tools, installs it with a different application UID, runs its probes, and removes it. The host's plugin instrumentation APK must already include `SeparateUidAuthorizationHostTest`. Neither the test nor the runner reads a live VPN configuration, changes the computer's VPN, or uses an active session's credentials.

Run after building and installing the library instrumentation APK, while no other instrumentation or VPN test is running:

```sh
python3 tool/test_android_separate_uid.py --serial emulator-5554
```

Use `--sdk`, `--java`, and `--output` to select local SDK/JDK paths and the result file. `--build-only` validates the standalone APK build without touching a device. The runner uses SDK `javac`, `d8`, `aapt2`, `zipalign`, and `apksigner`; it does not invoke Gradle.

The host test launches the actual packaged Xray executable using the production managed-inbound normalizer. Both SOCKS and HTTP use fixed, public test credentials from these fixtures. The adversary verifies that missing or incorrect credentials are rejected and that correct credentials transfer controlled HTTP bytes. The origin receives exactly the two authorized requests and no `Proxy-Authorization` header.

For the socket broker, the host first sends a real descriptor with a same-UID handshake and receives a positive acknowledgement. The adversary attempts the same abstract socket from its separate UID, with `H`, `P`, and `D`. Android can block the connection in SELinux before the broker receives it; the report identifies that layer explicitly. The runner additionally attempts a shell-UID probe. Where Android permits that connection, it transfers actual descriptors for `H` and `P` and verifies rejection by the broker. If SELinux blocks this UID too, `peer_uid_guard_exercised` is false: effective denial is verified, but execution of the foreign-UID guard remains untested on that image. The host checks that its protection callback was invoked only once, for the same-UID control. The test never disables SELinux or treats a missing listener or timeout as successful protection.

The JSON result contains only UIDs, booleans, and a scope statement. Ports and the ephemeral broker name cross the test bridge; the broker name is not an authentication credential. There is no claim that separate apps cannot reach loopback: the test demonstrates that reaching these listeners does not bypass authorization. This fixture does not test Android's OS lockdown policy or reuse a production VPN session.

For a coordinated OS-lockdown check, `--install-only` leaves the disposable APK installed. Its bounded `httpProbe` mode requests only the controlled fixture at `10.0.2.2:18083` and reports whether it receives the `flutter-vless-direct-bypass` marker, without dumping response bytes:

```sh
adb -s emulator-5554 shell am instrument -w -e mode httpProbe -e url http://10.0.2.2:18083/ -e timeout 1500 com.github.tfox.flutter_vless.adversary/com.github.tfox.flutter_vless.adversary.Probe
adb -s emulator-5554 uninstall com.github.tfox.flutter_vless.adversary
```

The lockdown test must establish a successful baseline with blocking disabled, then verify blocking from this separate UID. Android treats the VPN-provider UID differently, so a provider's own request cannot substitute for the adversary probe. The caller owns lockdown setting changes and restoration.
