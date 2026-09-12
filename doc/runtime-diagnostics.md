# Runtime Diagnostics

`FlutterVless.getProviderDebugSnapshot()` exposes a bounded text snapshot for
support and integration testing. The wire method remains
`getProviderDebugSnapshot` on every native platform for compatibility with the
older iOS/macOS diagnostic hook.

The snapshot covers VPN and proxy-only connection sessions. Stateless Xray
processes created by `getServerDelay()` are deliberately excluded so a delay
probe cannot replace failure evidence from the latest connection session.

## Lifecycle contract

- Before the first recorded session, the method returns an empty string.
- Android, Windows, and Apple proxy-only collectors reset when a new runtime
  starts. Persisted Apple Packet Tunnel tails can include earlier timestamped
  provider entries after extension restarts.
- Normal stop and startup failure preserve the latest snapshot.
- Reads never clear the snapshot.
- Output is bounded before it crosses Method Channel and uses UTF-8 text.
- The text is intentionally platform-specific and must not be parsed as a
  stable data format.

Android uses an internal bounded file because its VPN service runs in a
separate process from the Flutter plugin. Windows uses a generation-tagged,
thread-safe memory buffer so detached readers from an old child process cannot
pollute a newly started session. Apple Packet Tunnel diagnostics come from the
provider/App Group fallback; proxy-only Xray callbacks use a bounded app-process
buffer.

## Regression scenarios

1. Call diagnostics before startup and verify an empty result, not an error.
2. Start a valid session, wait for native output, and verify the snapshot is
   non-empty and identifies the native source.
3. Stop the session and verify the same failure evidence remains readable.
4. Start with an invalid or unavailable native runtime and verify startup logs
   remain readable after the failure.
5. Start a second Android, Windows, or Apple proxy-only session and verify old
   in-process markers are absent. For an Apple Packet Tunnel, verify the new
   timestamped session is distinguishable in the persisted bounded tail.
6. Generate more than 128 KiB of output and verify the returned snapshot stays
   below 64 KiB while retaining the newest messages.
7. Split output across arbitrary byte chunks, including UTF-8 text, and verify
   the returned Method Channel string remains valid.
8. On iOS/macOS, test both Packet Tunnel and proxy-only modes; on Android and
   Windows, exercise both Xray and tun2socks output paths.

## Privacy

Native logs may contain server addresses, requested destinations, route
details, App Group or filesystem paths, and Xray error context. Applications
should let users review the snapshot before copying, uploading, or attaching it
to a support request. Credentials and full configuration JSON must never be
added by the diagnostic collectors.
