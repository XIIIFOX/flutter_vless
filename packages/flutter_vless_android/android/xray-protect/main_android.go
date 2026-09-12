package main

import (
	"fmt"
	"github.com/xtls/xray-core/common/androidprotect"
	"os"
)

func init() {
	if name := os.Getenv(androidprotect.Environment); name != "" {
		if err := androidprotect.Configure("@" + name); err != nil {
			fmt.Fprintln(os.Stderr, "Protected Android runtime startup failed")
			os.Exit(1)
		}
	}
}
