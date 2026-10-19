//go:build flutter_vless_vpn_routing_cli

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/EbrahimTahernejad/xray-mobile/nativecli"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/main/commands/base"
)

func runNativeRoutingCommand(ctx context.Context, args []string, output io.Writer, backend nativecli.Backend, parent io.ReadCloser) int {
	// Only native launchers explicitly selecting this mode own stdin. Stock
	// commands and ordinary foreground routing runs never read or close it.
	if len(args) != 6 || args[0] != "run" || args[1] != "--parent-stdin" || parent == nil {
		return nativecli.Run(ctx, args, output, backend)
	}
	owned, cancel := context.WithCancel(ctx)
	defer cancel()
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, parent)
		cancel() // EOF, parent death and pipe failure all revoke this owner.
		close(drained)
	}()
	arguments := append([]string{"run"}, args[2:]...)
	code := nativecli.Run(owned, arguments, output, backend)
	cancel()
	_ = parent.Close() // Also unblock the observer on Check/capability refusal.
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		if code == 0 {
			code = 4
		}
	}
	return code
}

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
			base.SetExitStatus(runNativeRoutingCommand(ctx, args, os.Stdout, nativecli.MobileBackend{}, os.Stdin))
		},
	})
}
