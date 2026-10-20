package dispatcher_test

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"syscall"
	"testing"
)

const nativeRuntimeOriginCandidates = 8

func nativeRuntimeOriginCandidateError(err error, platform string) bool {
	// Go's portable Windows EADDRINUSE is distinct from Winsock's WSAEADDRINUSE.
	return errors.Is(err, syscall.EADDRINUSE) || platform == "windows" &&
		(errors.Is(err, syscall.Errno(10013)) || errors.Is(err, syscall.Errno(10048)))
}

// A TCP ephemeral port is not necessarily bindable by UDP on Windows. Keep the
// fixture's TCP-first choice, but publish a port only while both binds are held.
// These are allocation candidates, never retries of Core or a traffic case.
// The closer types let the exact allocation/cleanup algorithm use inert binders.
func nativeRuntimeReserveOriginPair[T io.Closer, U io.Closer](
	bindTCP func() (T, int, error), bindUDP func(int) (U, error), platform string,
) (T, U, error) {
	var noTCP T
	var noUDP U
	var last error
	for range nativeRuntimeOriginCandidates {
		tcp, port, err := bindTCP()
		if err != nil {
			if !nativeRuntimeOriginCandidateError(err, platform) {
				return noTCP, noUDP, err
			}
			last = err
			continue
		}
		udp, err := bindUDP(port)
		if err == nil {
			return tcp, udp, nil
		}
		// Do not allocate another candidate until its partial TCP listener is
		// retired. A close error is uncertain ownership and must fail closed.
		if closeError := tcp.Close(); closeError != nil {
			return noTCP, noUDP, fmt.Errorf("origin candidate cleanup: %w", closeError)
		}
		if !nativeRuntimeOriginCandidateError(err, platform) {
			return noTCP, noUDP, err
		}
		last = err
	}
	return noTCP, noUDP, fmt.Errorf("origin TCP/UDP pair unavailable after %d candidates: %w", nativeRuntimeOriginCandidates, last)
}

type nativeRuntimePairResource struct {
	closed     int
	closeError error
}

func (r *nativeRuntimePairResource) Close() error { r.closed++; return r.closeError }

type nativeRuntimePairFake struct {
	t                  *testing.T
	tcpCalls, udpCalls int
	resources          []*nativeRuntimePairResource
	udpResource        *nativeRuntimePairResource
	rejected           error
	alwaysReject       bool
	tcpError           error
	closeError         error
}

func (f *nativeRuntimePairFake) tcp() (*nativeRuntimePairResource, int, error) {
	f.tcpCalls++
	if f.tcpError != nil {
		return nil, 0, f.tcpError
	}
	if len(f.resources) > 0 && f.resources[len(f.resources)-1].closed != 1 {
		f.t.Fatal("next candidate allocated before partial TCP close")
	}
	r := &nativeRuntimePairResource{closeError: f.closeError}
	f.resources = append(f.resources, r)
	return r, 18000 + f.tcpCalls, nil
}

func (f *nativeRuntimePairFake) udp(port int) (*nativeRuntimePairResource, error) {
	f.udpCalls++
	if port != 18000+f.tcpCalls {
		f.t.Fatal("UDP bind did not use exact current TCP port")
	}
	if f.alwaysReject || f.udpCalls == 1 && f.rejected != nil {
		return nil, f.rejected
	}
	f.udpResource = new(nativeRuntimePairResource)
	return f.udpResource, nil
}

// Literal single-candidate algorithm from the pre-repair origin. Its explicit
// negative control below must reject the same TCP-valid/UDP-rejected scenario
// for which the actual allocation helper subsequently acquires a complete pair.
func nativeRuntimeOldSingleOriginPair(f *nativeRuntimePairFake) error {
	tcp, port, err := f.tcp()
	if err != nil {
		return err
	}
	_, err = f.udp(port)
	if err != nil {
		_ = tcp.Close()
	}
	return err
}

// Automatically selected as a pure routing test; no listener, Core or resolver.
func TestNativeVPNRoutingOriginPairAllocation(t *testing.T) {
	for _, tc := range []struct {
		name, platform string
		rejected       error
	}{
		{"address-in-use", runtime.GOOS, fmt.Errorf("bind: %w", syscall.EADDRINUSE)},
		{"windows-udp-address-in-use", "windows", fmt.Errorf("bind: %w", syscall.Errno(10048))},
		{"windows-udp-access-denied", "windows", fmt.Errorf("bind: %w", syscall.Errno(10013))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := &nativeRuntimePairFake{t: t, rejected: tc.rejected}
			if err := nativeRuntimeOldSingleOriginPair(old); !errors.Is(err, tc.rejected) || old.tcpCalls != 1 || old.udpCalls != 1 || old.resources[0].closed != 1 {
				t.Fatal("old single-candidate negative control did not reject and retire partial bind")
			}
			current := &nativeRuntimePairFake{t: t, rejected: tc.rejected}
			tcp, udp, err := nativeRuntimeReserveOriginPair(current.tcp, current.udp, tc.platform)
			if err != nil || current.tcpCalls != 2 || current.udpCalls != 2 || current.resources[0].closed != 1 ||
				tcp != current.resources[1] || udp != current.udpResource || tcp.closed != 0 || udp.closed != 0 {
				t.Fatal("complete second pair was not retained after rejected UDP candidate", err)
			}
			_ = tcp.Close()
			_ = udp.Close()
			if tcp.closed != 1 || udp.closed != 1 {
				t.Fatal("successful pair cleanup ownership changed")
			}
		})
	}
	t.Run("candidate-exhaustion", func(t *testing.T) {
		f := &nativeRuntimePairFake{t: t, rejected: syscall.EADDRINUSE, alwaysReject: true}
		tcp, udp, err := nativeRuntimeReserveOriginPair(f.tcp, f.udp, runtime.GOOS)
		if !errors.Is(err, syscall.EADDRINUSE) || tcp != nil || udp != nil || f.tcpCalls != nativeRuntimeOriginCandidates || f.udpCalls != nativeRuntimeOriginCandidates {
			t.Fatal("pair candidate bound was not enforced", err)
		}
		for _, r := range f.resources {
			if r.closed != 1 {
				t.Fatal("exhausted partial listener leaked or closed twice")
			}
		}
	})
	t.Run("tcp-candidate-exhaustion", func(t *testing.T) {
		f := &nativeRuntimePairFake{t: t, tcpError: syscall.EADDRINUSE}
		tcp, udp, err := nativeRuntimeReserveOriginPair(f.tcp, f.udp, runtime.GOOS)
		if !errors.Is(err, syscall.EADDRINUSE) || tcp != nil || udp != nil ||
			f.tcpCalls != nativeRuntimeOriginCandidates || f.udpCalls != 0 || len(f.resources) != 0 {
			t.Fatal("TCP candidate exhaustion exceeded its bound or attempted UDP", err)
		}
	})
	t.Run("unexpected-udp-error", func(t *testing.T) {
		failure := errors.New("synthetic unexpected UDP error")
		f := &nativeRuntimePairFake{t: t, rejected: failure}
		_, _, err := nativeRuntimeReserveOriginPair(f.tcp, f.udp, runtime.GOOS)
		if err != failure || f.tcpCalls != 1 || f.udpCalls != 1 || f.resources[0].closed != 1 {
			t.Fatal("unexpected UDP error retried or leaked", err)
		}
	})
	t.Run("unexpected-tcp-error", func(t *testing.T) {
		failure := errors.New("synthetic unexpected TCP error")
		f := &nativeRuntimePairFake{t: t, tcpError: failure}
		_, _, err := nativeRuntimeReserveOriginPair(f.tcp, f.udp, runtime.GOOS)
		if err != failure || f.tcpCalls != 1 || f.udpCalls != 0 {
			t.Fatal("unexpected TCP error retried or reached UDP", err)
		}
	})
	t.Run("partial-close-error", func(t *testing.T) {
		failure := errors.New("synthetic close failure")
		f := &nativeRuntimePairFake{t: t, rejected: syscall.EADDRINUSE, closeError: failure}
		_, _, err := nativeRuntimeReserveOriginPair(f.tcp, f.udp, runtime.GOOS)
		if !errors.Is(err, failure) || f.tcpCalls != 1 || f.udpCalls != 1 || f.resources[0].closed != 1 {
			t.Fatal("uncertain cleanup admitted another candidate", err)
		}
	})
}

func TestNativeVPNRoutingOriginPairCandidateErrors(t *testing.T) {
	for _, tc := range []struct {
		name, platform string
		err            error
		retry          bool
	}{
		{"portable-address-in-use", "linux", fmt.Errorf("wrapped: %w", syscall.EADDRINUSE), true},
		{"windows-address-in-use", "windows", fmt.Errorf("wrapped: %w", syscall.EADDRINUSE), true},
		{"windows-native-address-in-use", "windows", fmt.Errorf("wrapped: %w", syscall.Errno(10048)), true},
		{"windows-access-denied", "windows", fmt.Errorf("wrapped: %w", syscall.Errno(10013)), true},
		{"foreign-access-code", "linux", syscall.Errno(10013), false},
		{"foreign-address-code", "linux", syscall.Errno(10048), false},
		{"ordinary-permission-denied", "windows", syscall.EACCES, false},
		{"unexpected", "windows", errors.New("synthetic bind failure"), false},
		{"nil", "windows", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if nativeRuntimeOriginCandidateError(tc.err, tc.platform) != tc.retry {
				t.Fatal("candidate error classification changed")
			}
		})
	}
}
