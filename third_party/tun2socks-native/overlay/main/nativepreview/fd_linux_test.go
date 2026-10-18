//go:build linux

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func matchingPrivateFDs(t *testing.T, file *os.File) int {
	t.Helper()
	var original unix.Stat_t
	if unix.Fstat(int(file.Fd()), &original) != nil {
		t.Fatal("sender descriptor unavailable")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("descriptor inventory unavailable", err)
	}
	count := 0
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		var current unix.Stat_t
		if unix.Fstat(fd, &current) == nil && current.Dev == original.Dev && current.Ino == original.Ino {
			count++
		}
	}
	return count
}

func TestNativePrivateFDHandoffOwnershipWithoutTUN(t *testing.T) {
	for _, kind := range []string{"valid", "marker", "two-fds", "tail", "validator"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if os.Chmod(dir, 0700) != nil {
				t.Fatal("private directory")
			}
			path := filepath.Join(dir, "tun-fd")
			file, err := os.CreateTemp(dir, "source")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			type result struct {
				fd  int
				err error
			}
			done := make(chan result, 1)
			var received int = -1
			go func() {
				fd, e := receivePrivateFD(ctx, path, func(fd int) error {
					received = fd
					if kind == "validator" {
						return errPrivate
					}
					return nil
				})
				done <- result{fd, e}
			}()
			var conn *net.UnixConn
			until := time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(until) {
				conn, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
				if err == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if conn == nil {
				cancel()
				<-done
				t.Fatal("private listener not ready", err)
			}
			defer conn.Close()
			marker := []byte{0x20}
			if kind == "marker" {
				marker = []byte{0x21}
			}
			rights := unix.UnixRights(int(file.Fd()))
			if kind == "two-fds" {
				rights = unix.UnixRights(int(file.Fd()), int(file.Fd()))
			}
			if _, _, err := conn.WriteMsgUnix(marker, rights, nil); err != nil {
				t.Fatal(err)
			}
			if kind == "tail" {
				_, _ = conn.Write([]byte{1})
			}
			_ = conn.CloseWrite()
			out := <-done
			if out.fd >= 0 {
				defer unix.Close(out.fd)
			}
			if kind == "valid" {
				if out.err != nil || out.fd < 0 {
					t.Fatal("valid private descriptor refused", out.err)
				}
				var a, b unix.Stat_t
				if unix.Fstat(out.fd, &a) != nil || unix.Fstat(int(file.Fd()), &b) != nil || a.Ino != b.Ino || a.Dev != b.Dev {
					t.Fatal("handoff did not retain exact descriptor")
				}
			} else {
				if out.err == nil || out.fd != -1 {
					t.Fatal("invalid descriptor handoff accepted")
				}
				if received >= 0 {
					var stat unix.Stat_t
					if unix.Fstat(received, &stat) == nil {
						t.Fatal("rejected received descriptor leaked")
					}
				}
			}
			expected := 1
			if kind == "valid" {
				expected = 2
			}
			if count := matchingPrivateFDs(t, file); count != expected {
				t.Fatalf("descriptor ownership count=%d, expected=%d", count, expected)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("owned Unix listener path survived")
			}
			if _, err := file.Stat(); err != nil {
				t.Fatal("receiver closed sender descriptor")
			}
		})
	}
}

func TestNativePrivateFDCancelAcceptedReadBeforePeerEOF(t *testing.T) {
	dir, err := os.MkdirTemp("", "native-fd-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	file, err := os.CreateTemp(dir, "source")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	path := filepath.Join(dir, "tun-fd")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		fd, err := receivePrivateFD(ctx, path, func(int) error { return nil })
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		done <- err
	}()
	var conn *net.UnixConn
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		conn, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if conn == nil {
		cancel()
		<-done
		t.Fatal("private listener not ready", err)
	}
	defer conn.Close()
	if _, _, err := conn.WriteMsgUnix([]byte{0x20}, unix.UnixRights(int(file.Fd())), nil); err != nil {
		cancel()
		_ = conn.Close()
		<-done
		t.Fatal(err)
	}
	// The second file descriptor appears only after ReadMsgUnix consumes the
	// rights. This proves cancellation interrupts an accepted read awaiting EOF.
	until = time.Now().Add(time.Second)
	for matchingPrivateFDs(t, file) != 2 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if matchingPrivateFDs(t, file) != 2 {
		cancel()
		_ = conn.Close()
		<-done
		t.Fatal("receiver never consumed rights")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handoff accepted descriptor")
		}
	case <-time.After(500 * time.Millisecond):
		_ = conn.Close()
		<-done
		t.Fatal("cancel did not unblock accepted stream")
	}
	if matchingPrivateFDs(t, file) != 1 {
		t.Fatal("cancelled accepted handoff leaked received descriptor")
	}
}

func TestNativePrivateFDRejectsRealNonTUNWithoutEngine(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-tun")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if validateTUN(int(file.Fd())) == nil {
		t.Fatal("regular file passed TUN ioctl qualification")
	}
}
