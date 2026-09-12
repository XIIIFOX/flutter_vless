#!/usr/bin/env bash
# Calls only the config parser from the pinned HEV macOS archive. No worker,
# NetworkExtension, TUN, routes, DNS or host VPN settings are touched.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/ios_hev_auth_probe"
HEV="$ROOT/ios/flutter_vless/.build/artifacts/tun2sockskit/HevSocks5Tunnel/HevSocks5Tunnel.xcframework/macos-arm64_x86_64/libhev-socks5-tunnel.a"
if [[ ! -f "$HEV" ]]; then
  echo 'Resolve ios/flutter_vless SwiftPM dependencies (Tun2SocksKit 5.15.0) first.' >&2
  exit 1
fi
mkdir -p "$OUT"
cat > "$OUT/main.swift" <<'SWIFT'
import Foundation
let credentials = try LocalProxyCredentials(username: "hev-session-user", password: "hev'quoted-password")
let config = TunnelHEVConfiguration.make(port: 18099, credentials: credentials, mtu: 1500,
    logURL: URL(fileURLWithPath: "/tmp/hev-socks5-tunnel-error-v2.log"))
try Data(config.utf8).write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
SWIFT
xcrun swiftc "$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy/LocalProxyAccessPolicy.swift" \
  "$ROOT/ios/flutter_vless/Sources/flutter_vless_tunnel_support/TunnelHEVLogPolicy.swift" "$OUT/main.swift" -o "$OUT/config"
"$OUT/config" "$OUT/config.yml"
cat > "$OUT/probe.c" <<'C'
#include <assert.h>
#include <stdio.h>
#include <string.h>
// Public source ABI: heiher/hev-socks5-tunnel tag 2.15.0 src/hev-config.h.
// Tun2SocksKit 5.15.0 ships this parser in its checksum-pinned archive.
typedef struct {
    const char *user, *pass;
    unsigned int mark;
    short udp_in_udp;
    unsigned short port;
    unsigned char pipeline, fastopen;
    char udp_addr[256], addr[256];
} HevConfigServer;
extern int hev_config_init_from_file(const char *);
extern HevConfigServer *hev_config_get_socks5_server(void);
extern unsigned int hev_config_get_tunnel_mtu(void);
extern const char *hev_config_get_misc_log_file(void);
int main(int argc, char **argv) {
    assert(argc == 2 && hev_config_init_from_file(argv[1]) == 0);
    HevConfigServer *server = hev_config_get_socks5_server();
    assert(server && server->user && server->pass);
    assert(strcmp(server->user, "hev-session-user") == 0);
    assert(strcmp(server->pass, "hev'quoted-password") == 0);
    assert(strcmp(server->addr, "127.0.0.1") == 0);
    assert(server->port == 18099 && server->pipeline == 0 && server->udp_in_udp == 1);
    assert(hev_config_get_tunnel_mtu() == 1500);
    assert(strcmp(hev_config_get_misc_log_file(), "/tmp/hev-socks5-tunnel-error-v2.log") == 0);
    puts("PASS: pinned HEV parser accepted runtime-generated auth YAML, loopback, UDP and log policy; no tunnel started");
}
C
xcrun clang "$OUT/probe.c" "$HEV" -lresolv -o "$OUT/probe"
"$OUT/probe" "$OUT/config.yml"
