//go:build android

package main

import (
	"errors"
	"os"

	"github.com/xtls/xray-core/common/androidprotect"
)

func prepareHost() error {
	name := os.Getenv(androidprotect.Environment)
	if name == "" {
		return errors.New("strict Android socket broker unavailable")
	}
	return androidprotect.ConfigureNumericOnly("@" + name)
}
