//go:build flutter_vless_vpn_routing_cli

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/EbrahimTahernejad/xray-mobile/nativecli"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/main/commands/base"
)

func restoreNativeRoutingStockLogger(args []string, register func(xlog.Handler)) {
	if len(args) > 1 && args[1] == "native-routing" {
		return
	}
	// Importing the mobile bridge installs its private preflight handler. Stock
	// commands keep upstream logging; only the private command retains that
	// handler until the factory installs its redacted runtime logger.
	register(xlog.NewLogger(xlog.CreateStdoutLogWriter()))
}

func init() {
	restoreNativeRoutingStockLogger(os.Args, xlog.RegisterHandler)
	base.RootCommand.Commands = append(base.RootCommand.Commands, &base.Command{
		UsageLine:   "{{.Exec}} native-routing [arguments]",
		Short:       "Use the private native VPN routing factory",
		Long:        "Private capability, preflight and lifecycle commands for native launchers.",
		CustomFlags: true,
		Run: func(_ *base.Command, args []string) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			base.SetExitStatus(nativecli.Run(ctx, args, os.Stdout, nativecli.MobileBackend{}))
		},
	})
}
