//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"golang.org/x/sys/unix"
)

func readPolicy(path string) (privatePolicy, error) {
	var empty privatePolicy
	if !filepath.IsAbs(path) {
		return empty, errPrivate
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, errPrivate
	}
	file := os.NewFile(uintptr(fd), "private-forwarder-policy")
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Size() < 1 || before.Size() > 8192 {
		return empty, errPrivate
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return empty, errPrivate
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	after, afterErr := file.Stat()
	named, namedErr := os.Lstat(path)
	if err != nil || afterErr != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(after, named) || after.Mode() != before.Mode() || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return empty, errPrivate
	}
	return parsePolicy(data)
}

func receiveTUN(ctx context.Context, path string) (int, error) {
	return receivePrivateFD(ctx, path, validateTUN)
}

func validateTUN(fd int) error {
	request, err := unix.NewIfreq("")
	if err != nil || unix.IoctlIfreq(fd, unix.TUNGETIFF, request) != nil || request.Uint16()&(unix.IFF_TUN|unix.IFF_NO_PI) != (unix.IFF_TUN|unix.IFF_NO_PI) {
		return errPrivate
	}
	return unix.SetNonblock(fd, true)
}

// The validator is fixed to validateTUN in the only executable callsite. The
// internal seam permits FD-ownership tests without opening any TUN or engine.
func receivePrivateFD(ctx context.Context, path string, validate func(int) error) (int, error) {
	if validate == nil {
		return -1, errPrivate
	}
	if !filepath.IsAbs(path) || len(path) > 100 || filepath.Base(path) != "tun-fd" {
		return -1, errPrivate
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return -1, errPrivate
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return -1, errPrivate
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return -1, errPrivate
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return -1, errPrivate
	}
	defer listener.Close()
	if os.Chmod(path, 0600) != nil {
		return -1, errPrivate
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	conn, err := listener.AcceptUnix()
	if err != nil {
		return -1, errPrivate
	}
	defer conn.Close()
	stopConnection := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopConnection()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, errPrivate
	}
	var credential *unix.Ucred
	var credentialErr error
	if raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}) != nil || credentialErr != nil || credential == nil || credential.Uid != uint32(os.Geteuid()) {
		return -1, errPrivate
	}
	var data [2]byte
	oob := make([]byte, unix.CmsgSpace(4*16))
	n, count, flags, _, readErr := conn.ReadMsgUnix(data[:], oob)
	var descriptors []int
	messages, parseErr := unix.ParseSocketControlMessage(oob[:count])
	valid := true
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			valid = false
			continue
		}
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			valid = false
			continue
		}
		for _, fd := range rights {
			unix.CloseOnExec(fd)
			descriptors = append(descriptors, fd)
		}
	}
	accepted := false
	defer func() {
		if !accepted {
			for _, fd := range descriptors {
				_ = unix.Close(fd)
			}
		}
	}()
	if readErr != nil || parseErr != nil || !valid || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || n != 1 || data[0] != 0x20 || len(descriptors) != 1 || ctx.Err() != nil {
		return -1, errPrivate
	}
	// Refuse extra stream bytes/control messages; sender must finish its half.
	more, oobn, _, _, tailErr := conn.ReadMsgUnix(data[:], oob)
	if oobn > 0 {
		if extra, e := unix.ParseSocketControlMessage(oob[:oobn]); e == nil {
			for _, m := range extra {
				if fds, e := unix.ParseUnixRights(&m); e == nil {
					for _, fd := range fds {
						_ = unix.Close(fd)
					}
				}
			}
		}
	}
	if more != 0 || oobn != 0 || tailErr != io.EOF {
		return -1, errPrivate
	}
	fd := descriptors[0]
	if validate(fd) != nil || ctx.Err() != nil {
		return -1, errPrivate
	}
	accepted = true
	return fd, nil
}

func execute() int {
	flags := flag.NewFlagSet("private-forwarder", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("sock-path", "", "")
	config := flags.String("config", "", "")
	if len(os.Args) != 5 || os.Args[1] == os.Args[3] ||
		(os.Args[1] != "-sock-path" && os.Args[1] != "-config") ||
		(os.Args[3] != "-sock-path" && os.Args[3] != "-config") || flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	policy, err := readPolicy(*config)
	if err != nil {
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, io.LimitReader(os.Stdin, 64)); cancel() }()
	fd, err := receiveTUN(ctx, *path)
	if err != nil {
		return 2
	}
	// fd ownership moves to the engine only on successful construction; its
	// private error API closes partial engine state on failure.
	key := &engine.Key{Device: fmt.Sprintf("fd://%d", fd), Proxy: policy.Proxy, MTU: policy.MTU, LogLevel: "silent", UDPTimeout: 15 * time.Second}
	if adopted, startErr := engine.StartNativePreview(key); startErr != nil {
		if !adopted {
			_ = unix.Close(fd)
		}
		return 2
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "capability": "native-tun-forwarder-preview-1", "status": "started", "host_qualified": false})
	<-ctx.Done()
	if engine.StopNativePreview() != nil {
		return 2
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "capability": "native-tun-forwarder-preview-1", "status": "stopped", "host_qualified": false})
	return 0
}

func main() { os.Exit(execute()) }
