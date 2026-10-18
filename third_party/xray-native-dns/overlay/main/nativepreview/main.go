// nativepreview is a separate development executable, not the stock Xray CLI.
// It never changes routes, system DNS, proxies, or the host VPN. Its capability
// is intentionally unpublished and does not certify any platform packet path.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/nativeinstance"
	xnet "github.com/xtls/xray-core/common/net"
	_ "github.com/xtls/xray-core/main/distro/all"
)

type response struct {
	Schema                 int    `json:"schema"`
	Capability             string `json:"capability"`
	CoreCommit             string `json:"core_commit"`
	Status                 string `json:"status"`
	Stage                  string `json:"stage,omitempty"`
	SourceDigest           string `json:"source_digest,omitempty"`
	PolicyEpoch            string `json:"policy_epoch,omitempty"`
	HostQualified          bool   `json:"host_qualified"`
	SystemResolverAttempts int64  `json:"system_resolver_attempts"`
}

var systemResolverAttempts atomic.Int64

func refuseSystemResolution() {
	refuse := func(context.Context, string, string) (net.Conn, error) {
		systemResolverAttempts.Add(1)
		return nil, errors.New("system resolver unavailable in scoped native entry")
	}
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = refuse
	xnet.DefaultResolver.PreferGo = true
	xnet.DefaultResolver.Dial = refuse
}

func emit(output io.Writer, status, stage, digest, epoch string) error {
	return json.NewEncoder(output).Encode(response{
		Schema: launcherSchema, Capability: launcherCapability, CoreCommit: coreCommit,
		Status: status, Stage: stage, SourceDigest: digest, HostQualified: false,
		PolicyEpoch:            epoch,
		SystemResolverAttempts: systemResolverAttempts.Load(),
	})
}

func document(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errArguments
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() > maxDocumentBytes {
		return nil, errArguments
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDocumentBytes+1))
	if err != nil || len(data) > maxDocumentBytes {
		return nil, errArguments
	}
	return data, nil
}

// EOF is also an explicit parent-lifetime end. The private control channel
// accepts one bounded, exact command; config/policy/queries cannot be injected.
func stopCommand(input io.Reader) bool {
	reader := bufio.NewReaderSize(input, 64)
	line, err := reader.ReadSlice('\n')
	if err == io.EOF && len(line) == 0 {
		return true
	}
	return err == nil && string(line) == "stop\n"
}

func execute(ctx context.Context, args []string, input io.Reader, output io.Writer) int {
	fail := func(stage string) int { _ = emit(output, "failed", stage, "", ""); return 1 }
	options, err := parseOptions(args)
	if err != nil {
		return fail("arguments")
	}
	capability := nativeinstance.Capabilities()
	if capability.ID != launcherCapability || capability.Schema != launcherSchema || capability.CoreCommit != coreCommit {
		return fail("capability")
	}
	if options.command == "capabilities" {
		if emit(output, "available", "", "", "") != nil {
			return 1
		}
		return 0
	}
	data, err := document(options.path)
	if err != nil {
		return fail("read")
	}
	resolver, err := netip.ParseAddrPort(options.resolver)
	if err != nil {
		return fail("policy")
	}
	policy := nativeinstance.Policy{
		RequiredCapability: launcherCapability, Resolver: resolver,
		DefaultOutboundIndex: options.sourceIndex, LookupTimeout: options.timeout,
	}
	if options.privatePath != "" {
		private, err := readPrivatePolicy(options.privatePath, data, options.epoch)
		if err != nil {
			return fail("private-policy")
		}
		policy.SystemDNSBridge, policy.ManagedInput = private.bridge, private.input
	}
	refuseSystemResolution()
	prepared, err := nativeinstance.PrepareJSON(data, policy)
	if err != nil {
		return fail("prepare")
	}
	if systemResolverAttempts.Load() != 0 {
		return fail("prepare-system-resolver")
	}
	if options.command == "check" {
		if emit(output, "prepared", "", prepared.SourceDigest(), options.epoch) != nil {
			return 1
		}
		return 0
	}
	// Android requires the separate strict FD broker; old binaries/brokers fail
	// here. Check/capabilities never register controllers or contact the broker.
	if err := prepareHost(); err != nil {
		return fail("host")
	}
	refuseSystemResolution()
	runtime, err := prepared.Start(ctx)
	if err != nil {
		return fail("start")
	}
	closeRuntime := func() error {
		deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return runtime.Close(deadline)
	}
	if emit(output, "started", "", prepared.SourceDigest(), options.epoch) != nil {
		_ = closeRuntime()
		return 1
	}
	control := make(chan bool, 1)
	go func() { control <- stopCommand(input) }()
	valid := true
	select {
	case valid = <-control:
	case <-ctx.Done():
	}
	if err := closeRuntime(); err != nil {
		return fail("close")
	}
	if !valid {
		return fail("control")
	}
	if systemResolverAttempts.Load() != 0 {
		return fail("system-resolver")
	}
	if emit(output, "stopped", "", prepared.SourceDigest(), options.epoch) != nil {
		return 1
	}
	return 0
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdin, os.Stdout)
	cancel()
	os.Exit(code)
}
