package main

import (
	"strings"
	"testing"
)

func TestNativePrivateForwarderPolicy(t *testing.T) {
	good := "proxy: 'socks5://private-user:private-password@127.0.0.1:23456'\nmtu: 1500\nloglevel: error\n"
	if p, err := parsePolicy([]byte(good)); err != nil || p.MTU != 1500 {
		t.Fatal("valid private policy refused")
	}
	for name, bad := range map[string]string{
		"empty": "", "size": strings.Repeat("x", 8193), "utf8": string([]byte{255}),
		"extra": good + "device: tun://x\n", "duplicate": strings.Replace(good, "loglevel: error", "mtu: 1500", 1),
		"documents": good + "---\n{}\n", "mapping-tag": "!unsafe " + good,
		"mapping-anchor": "&unsafe " + good, "alias": strings.Replace(good, "1500", "*unsafe", 1),
		"quoted-mtu": strings.Replace(good, "1500", "'1500'", 1), "mtu-hex": strings.Replace(good, "1500", "0x5dc", 1),
		"logging": strings.Replace(good, "error", "debug", 1), "null": strings.Replace(good, "error", "null", 1),
		"hostname": strings.Replace(good, "127.0.0.1", "example.invalid", 1), "wildcard": strings.Replace(good, "127.0.0.1", "0.0.0.0", 1),
		"ipv6": strings.Replace(good, "127.0.0.1", "[::1]", 1), "zero-port": strings.Replace(good, "23456", "0", 1),
		"query": strings.Replace(good, "23456'", "23456?device=bad'", 1), "fragment": strings.Replace(good, "23456'", "23456#bad'", 1),
		"empty-password": strings.Replace(good, "private-password", "", 1), "invalid-password-utf8": strings.Replace(good, "private-password", "%ff", 1),
		"password-bytes": strings.Replace(good, "private-password", strings.Repeat("a", 256), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePolicy([]byte(bad)); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
