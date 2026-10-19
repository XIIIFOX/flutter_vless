// Package nativecli adapts the private routing factory to an additive command.
// The executable owns signal handling; this package neither exits the process
// nor reads stdin. File arguments and backend error text never enter output.
package nativecli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Backend interface {
	Capability() int64
	Check(config, spec []byte) int64
	Start(config, spec []byte) error
	Stop()
}

type command struct{ name, config, spec string }

func parse(args []string) (command, bool) {
	if len(args) == 1 && args[0] == "capabilities" {
		return command{name: args[0]}, true
	}
	if len(args) != 5 || (args[0] != "check" && args[0] != "run") {
		return command{}, false
	}
	c := command{name: args[0]}
	for i := 1; i < len(args); i += 2 {
		if !filepath.IsAbs(args[i+1]) {
			return command{}, false
		}
		switch args[i] {
		case "--config":
			if c.config != "" {
				return command{}, false
			}
			c.config = args[i+1]
		case "--spec":
			if c.spec != "" {
				return command{}, false
			}
			c.spec = args[i+1]
		default:
			return command{}, false
		}
	}
	return c, c.config != "" && c.spec != ""
}

func emit(out io.Writer, stage string, code int, capability *int) bool {
	if out == nil {
		return false
	}
	data, _ := json.Marshal(struct {
		Stage      string `json:"stage"`
		Code       int    `json:"code"`
		Capability *int   `json:"capability,omitempty"`
	}{stage, code, capability})
	data = append(data, '\n')
	n, err := out.Write(data)
	return err == nil && n == len(data)
}

func result(out io.Writer, stage string, code int, capability *int) int {
	if !emit(out, stage, code, capability) {
		return 4
	}
	return code
}

func checkCode(code int64) int {
	// Keep the native ABI's closed codes; unexpected backend values never
	// become an arbitrary status or process exit value.
	switch code {
	case 0, 1, 2, 3, 4, 5, 16, 17, 18, 19, 20, 21, 32:
		return int(code)
	default:
		return 4
	}
}

// Run reads each member of the candidate pair once. Both Check and Start get
// those same bytes, even if the paths change afterwards. Capability refusal
// precedes file access. A successful Start transfers ownership until Stop;
// a failed Start retains its factory-owned failure cleanup.
func Run(ctx context.Context, args []string, out io.Writer, backend Backend) int {
	return run(ctx, args, out, backend, os.ReadFile)
}

func run(ctx context.Context, args []string, out io.Writer, backend Backend, read func(string) ([]byte, error)) int {
	c, valid := parse(args)
	if !valid || ctx == nil || backend == nil {
		return result(out, "arguments", 2, nil)
	}
	if ctx.Err() != nil {
		return result(out, "canceled", 130, nil)
	}
	capability := 0
	if backend.Capability() != 1 {
		return result(out, "capabilities", 32, &capability)
	}
	if c.name == "capabilities" {
		capability = 1
		return result(out, "capabilities", 0, &capability)
	}
	config, err := read(c.config)
	if err != nil {
		return result(out, "input", 1, nil)
	}
	spec, err := read(c.spec)
	if err != nil {
		return result(out, "input", 1, nil)
	}
	if ctx.Err() != nil {
		return result(out, "canceled", 130, nil)
	}
	code := checkCode(backend.Check(config, spec))
	if code != 0 || c.name == "check" {
		return result(out, "check", code, nil)
	}
	if ctx.Err() != nil {
		return result(out, "canceled", 130, nil)
	}
	if backend.Start(config, spec) != nil {
		return result(out, "start", 4, nil)
	}
	stop := sync.OnceFunc(backend.Stop)
	defer stop()
	if ctx.Err() == nil {
		if !emit(out, "started", 0, nil) {
			return 4
		}
		<-ctx.Done()
	}
	stop()
	return result(out, "stopped", 0, nil)
}
