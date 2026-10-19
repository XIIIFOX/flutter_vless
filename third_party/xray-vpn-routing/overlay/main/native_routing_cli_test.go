//go:build flutter_vless_vpn_routing_cli

package main

import (
	"reflect"
	"testing"

	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/main/commands/base"
)

func TestNativeRoutingCLIStockLogger(t *testing.T) {
	for _, args := range [][]string{{"xray"}, {"xray", "version"}, {"xray", "run", "-test"}, {"xray", "help"}, {"xray", "native-routing", "check"}} {
		calls := 0
		restoreNativeRoutingStockLogger(args, func(handler xlog.Handler) {
			calls++
			if reflect.TypeOf(handler) != reflect.TypeOf(xlog.NewLogger(xlog.CreateStdoutLogWriter())) {
				t.Fatal("stock command did not receive upstream logger")
			}
		})
		want := 1
		if len(args) > 1 && args[1] == "native-routing" {
			want = 0
		}
		if calls != want {
			t.Fatal("private/stock log boundary changed", args, calls)
		}
	}
}

func TestNativeRoutingCLIRegisteredOnce(t *testing.T) {
	count := 0
	for _, command := range base.RootCommand.Commands {
		if command.Name() == "native-routing" {
			count++
			if !command.CustomFlags || !command.Runnable() {
				t.Fatal("native command must retain its closed argument parser")
			}
		}
	}
	if count != 1 {
		t.Fatal("native routing command registration missing or duplicated", count)
	}
}
