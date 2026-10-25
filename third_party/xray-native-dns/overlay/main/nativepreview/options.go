package main

// This executable is an unpublished native-host entry point. Imported JSON
// cannot grant a capability: the parent supplies this separate policy after it
// has verified the exact binary and its own socket/underlay implementation.
import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"time"
)

const (
	launcherSchema     = 1
	launcherCapability = "native-instance-preview-1"
	coreCommit         = "1b1647cd9ddf0abc34b981d4611fc03bcac1ca74"
	maxDocumentBytes   = 4 << 20
)

type commandOptions struct {
	command     string
	path        string
	privatePath string
	epoch       string
	resolver    string
	sourceIndex int
	timeout     time.Duration
}

var errArguments = errors.New("native launcher arguments rejected")

func parseOptions(args []string) (commandOptions, error) {
	if len(args) == 1 && args[0] == "capabilities" {
		return commandOptions{command: args[0]}, nil
	}
	if len(args) < 1 || (args[0] != "check" && args[0] != "run") {
		return commandOptions{}, errArguments
	}
	values := make(map[string]string)
	for index := 1; index < len(args); index += 2 {
		if index+1 >= len(args) {
			return commandOptions{}, errArguments
		}
		key := args[index]
		switch key {
		case "--config", "--resolver", "--egress-index", "--capability", "--timeout-ms", "--private-policy", "--policy-epoch":
		default:
			return commandOptions{}, errArguments
		}
		if _, exists := values[key]; exists {
			return commandOptions{}, errArguments
		}
		values[key] = args[index+1]
	}
	if values["--capability"] != launcherCapability || !filepath.IsAbs(values["--config"]) {
		return commandOptions{}, errArguments
	}
	privatePath, hasPrivate := values["--private-policy"]
	epoch, hasEpoch := values["--policy-epoch"]
	if hasPrivate != hasEpoch || hasPrivate && (!filepath.IsAbs(privatePath) || !lowerHex(epoch, 32)) {
		return commandOptions{}, errArguments
	}
	host, portText, err := net.SplitHostPort(values["--resolver"])
	if err != nil || net.ParseIP(host) == nil {
		return commandOptions{}, errArguments
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return commandOptions{}, errArguments
	}
	sourceIndex, err := strconv.Atoi(values["--egress-index"])
	if err != nil || sourceIndex < 0 {
		return commandOptions{}, errArguments
	}
	timeout := 4000
	if text, exists := values["--timeout-ms"]; exists {
		timeout, err = strconv.Atoi(text)
		if err != nil || timeout < 1 || timeout > 4000 {
			return commandOptions{}, errArguments
		}
	}
	return commandOptions{
		command: args[0], path: filepath.Clean(values["--config"]),
		privatePath: privatePath, epoch: epoch,
		resolver: net.JoinHostPort(host, strconv.Itoa(port)), sourceIndex: sourceIndex,
		timeout: time.Duration(timeout) * time.Millisecond,
	}, nil
}
