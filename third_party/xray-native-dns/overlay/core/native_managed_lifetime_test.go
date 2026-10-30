package core

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet/xdrive"
)

// CI runtime fixture, deliberately outside the pure TestNative selection.
func TestAcceptanceManagedCoreCloseAndFailedConstruction(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstContext, firstOwner := xdrive.ContextWithNativeLifetime(parent)
	secondContext, secondOwner := xdrive.ContextWithNativeLifetime(parent)
	first := &Instance{ctx: firstContext, nativeXdriveLifetime: firstOwner}
	second := &Instance{ctx: secondContext, nativeXdriveLifetime: secondOwner}
	defer first.Close()
	defer second.Close()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.nativeXdriveLifetime.Done():
	default:
		t.Fatal("Core.Close did not cancel its service lifetime")
	}
	select {
	case <-second.nativeXdriveLifetime.Done():
		t.Fatal("another Core was cancelled")
	default:
	}
	if parent.Err() != nil {
		t.Fatal("caller context was cancelled")
	}
	failed := &Instance{ctx: parent}
	done, err := initInstanceWithConfig(&Config{App: []*serial.TypedMessage{{Type: "unregistered.synthetic.app"}}}, failed)
	if !done || err == nil || failed.nativeXdriveLifetime == nil {
		t.Fatal("invalid construction did not exercise owner admission")
	}
	select {
	case <-failed.nativeXdriveLifetime.Done():
	default:
		t.Fatal("failed construction retained its service lifetime")
	}
}
