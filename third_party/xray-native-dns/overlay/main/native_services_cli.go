package main

import (
	"encoding/json"
	"os"

	"github.com/xtls/xray-core/app/geodata"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/transport/internet/xdrive"
)

// Fixed status only: no config, network, cloud credential or Core construction.
func init() {
	base.RootCommand.Commands = append(base.RootCommand.Commands, &base.Command{
		UsageLine:   "{{.Exec}} native-services capabilities",
		Short:       "Report managed native service ownership capabilities",
		Long:        "Private versioned capabilities for GeoDAT and XDRIVE native launchers.",
		CustomFlags: true,
		Run: func(_ *base.Command, args []string) {
			if len(args) != 1 || args[0] != "capabilities" {
				base.SetExitStatus(2)
				return
			}
			bits := 0
			if geodata.NativeLifetimeCapability() == 1 {
				bits |= 1
			}
			if xdrive.NativeLifetimeCapability() == 1 {
				bits |= 2
			}
			if err := json.NewEncoder(os.Stdout).Encode(struct {
				Stage        string `json:"stage"`
				Code         int    `json:"code"`
				Capabilities int    `json:"managed_service_lifetimes"`
			}{"capabilities", 0, bits}); err != nil {
				base.SetExitStatus(3)
			}
		},
	})
}
