package nativecli

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type BalancerBackend interface {
	Capability() int64
	CheckRouting(config, spec []byte) int64
	Start(config, spec []byte, inbound string, capacity int64) error
	Snapshot() string
	Disable()
	Stop()
}

type balancerLaunch struct {
	config, spec, inbound string
	capacity              int64
}

func parseBalancerLaunch(args []string) (balancerLaunch, bool) {
	var launch balancerLaunch
	if (len(args) != 7 && len(args) != 9) || args[0] != "run" {
		return launch, false
	}
	seen := make(map[string]bool, 4)
	for i := 1; i < len(args); i += 2 {
		flag, value := args[i], args[i+1]
		if seen[flag] || value == "" {
			return launch, false
		}
		seen[flag] = true
		switch flag {
		case "--config", "--spec":
			if !filepath.IsAbs(value) {
				return launch, false
			}
			if flag == "--config" {
				launch.config = value
			} else {
				launch.spec = value
			}
		case "--managed-inbound":
			launch.inbound = value
		case "--max-lines":
			value, err := strconv.ParseInt(value, 10, 64)
			if err != nil || value < 1 || value > 300 {
				return launch, false
			}
			launch.capacity = value
		default:
			return launch, false
		}
	}
	return launch, launch.config != "" && launch.inbound != "" && launch.capacity != 0
}

// RunBalancer uses inherited pipes without a listener or history file.
// Every successful start belongs to this parent until its stdin closes.
func RunBalancer(ctx context.Context, args []string, out io.Writer, parent io.ReadCloser, backend BalancerBackend) int {
	capability := 0
	if backend != nil && backend.Capability() == 1 {
		capability = 1
	}
	if len(args) == 1 && args[0] == "capabilities" {
		if capability == 0 {
			return result(out, "capabilities", 32, &capability)
		}
		return result(out, "capabilities", 0, &capability)
	}
	launch, valid := parseBalancerLaunch(args)
	if !valid || ctx == nil || parent == nil || out == nil {
		return result(out, "arguments", 2, nil)
	}
	if capability == 0 {
		return result(out, "capabilities", 32, &capability)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer parent.Close()
	// One in-flight snapshot and one live opt-out can be pending together.
	requests := make(chan bool, 2)
	go observeBalancerRequests(ctx, parent, requests, cancel)
	config, err := os.ReadFile(launch.config)
	if err != nil {
		return result(out, "input", 1, nil)
	}
	var spec []byte
	if launch.spec != "" {
		spec, err = os.ReadFile(launch.spec)
		if err != nil || len(spec) == 0 {
			return result(out, "input", 1, nil)
		}
		if code := checkCode(backend.CheckRouting(config, spec)); code != 0 {
			return result(out, "check", code, nil)
		}
	}
	if ctx.Err() != nil {
		return 130
	}
	if backend.Start(config, spec, launch.inbound, launch.capacity) != nil {
		return result(out, "start", 4, nil)
	}
	defer backend.Stop()
	if ctx.Err() != nil {
		return 0
	}
	if !emit(out, "started", 0, nil) {
		return 4
	}
	for {
		select {
		case <-ctx.Done():
			return 0
		case disable := <-requests:
			if ctx.Err() != nil {
				return 0
			}
			if disable {
				backend.Disable()
			}
			rows := strings.TrimSuffix(backend.Snapshot(), "\n")
			frame, _ := json.Marshal(struct {
				Stage string `json:"stage"`
				Code  int    `json:"code"`
				Rows  string `json:"rows"`
			}{"selections", 0, rows})
			frame = append(frame, '\n')
			n, err := out.Write(frame)
			if err != nil || n != len(frame) {
				return 4
			}
		}
	}
}

func observeBalancerRequests(ctx context.Context, parent io.Reader, requests chan<- bool, cancel context.CancelFunc) {
	defer cancel()
	reader := bufio.NewReaderSize(parent, 16)
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return
		}
		request := string(line)
		if request != "snapshot\n" && request != "disable\n" {
			return
		}
		select {
		case requests <- request == "disable\n":
		case <-ctx.Done():
			return
		default:
			// The launcher must finish reading before requesting another
			// snapshot. Keep the queue and parent pipe work bounded.
			return
		}
	}
}
