//go:build flutter_vless_balancer_diagnostics_cli

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/EbrahimTahernejad/xray-mobile/nativecli"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/main/commands/base"
)

// The mobile bridge has already removed Core messages with traffic data.
// Keep these events separate from the numeric snapshot protocol on stdout.
type balancerCoreLogger struct{}

func (balancerCoreLogger) LogInput(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
}

func init() {
	if len(os.Args) < 2 || (os.Args[1] != "native-balancer" && os.Args[1] != "native-routing") {
		// Building this additive command must not suppress stock CLI logs.
		xlog.RegisterHandler(xlog.NewLogger(xlog.CreateStdoutLogWriter()))
	}
	base.RootCommand.Commands = append(base.RootCommand.Commands, &base.Command{
		UsageLine:   "{{.Exec}} native-balancer [arguments]",
		Short:       "Use the private native balancer diagnostics bridge",
		CustomFlags: true,
		Run: func(_ *base.Command, args []string) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			backend := nativecli.MobileBalancerBackend{Logger: balancerCoreLogger{}}
			base.SetExitStatus(nativecli.RunBalancer(ctx, args, os.Stdout, os.Stdin, backend))
		},
	})
}
