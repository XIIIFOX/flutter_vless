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
- Output is bounded before it crosses Method Channel and uses valid UTF-8 text.
  Snapshot retention is controlled by `DiagnosticsOptions`; native backends can
  impose a smaller returned-snapshot limit.
- The text is intentionally platform-specific and must not be parsed as a
  stable data format.

Android uses an internal bounded file because its VPN service runs in a
separate process from the Flutter plugin. Windows uses a generation-tagged,
thread-safe memory buffer so detached readers from an old child process cannot
pollute a newly started session. Apple Packet Tunnel diagnostics come from the
provider/App Group fallback; proxy-only Xray callbacks use a bounded app-process
buffer.

## Usage

Read a snapshot after startup, failure or Stop when collecting a support report:

```dart
final snapshot = await flutterVless.getProviderDebugSnapshot();
```

`DiagnosticsOptions` controls collection and retention limits. Collection is
on by default. Disabling it clears the owned buffers; re-enable it before the
session you need to investigate. The returned text is for human inspection,
not connection-state detection. Use status events for connection state and
`getConnectedServerDelay()` for a permitted destination's reachability.

## Privacy

iOS and Android use fixed safe events instead of copying raw Xray/tun2socks
stdout, stderr, commands or exception strings. Android disables Xray file logs;
tun2socks runs at `error`, but even error text is drained rather than forwarded.
Snapshots contain lifecycle stages, retry counts, exit codes and numerical stats.
Only the owning session can rotate its versioned diagnostic file. Known legacy
Android logs and iOS `hev-socks5-tunnel.log` files are deleted without reading
or republishing their contents; other application files are untouched.

iOS HEV keeps a bounded error-only `hev-socks5-tunnel-error-v2.log`; snapshots
report only its size. A worker must be stopped before legacy HEV cleanup.
Current macOS collectors use the same typed scalar/fixed-message boundary and
map arbitrary Xray callback strings to a closed vocabulary. Windows records safe
native lifecycle/preparation events and drains raw child stdout/stderr.
`DiagnosticsOptions` limits existing collection; disabling it clears the owned
buffers. Backend snapshot shapes remain platform-specific, and older published
wrappers or application-owned logs may have a different contract. Applications
should let users review support attachments before sharing them.
