package XRay

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
)

type routingAdmissionLogger struct{ calls int }

func (l *routingAdmissionLogger) LogInput(string) { l.calls++; _ = QueryStats("") }

func TestNativeRoutingActiveSessionAdmission(t *testing.T) {
	// The placeholder is identity-only. No Core constructor/Start/Close runs.
	coreState.Lock()
	before, oldOwner := coreInstance, coreRoutingOwner
	existing := new(core.Instance)
	coreInstance, coreRoutingOwner = existing, nil
	coreState.Unlock()
	defer func() { coreState.Lock(); coreInstance, coreRoutingOwner = before, oldOwner; coreState.Unlock() }()
	logger := new(routingAdmissionLogger)
	if err := StartPrivate([]byte("invalid candidate"), logger); err == nil || !strings.Contains(err.Error(), "active session") {
		t.Fatal("working session was not admitted before candidate processing", err)
	}
	coreState.RLock()
	unchanged := coreInstance == existing && coreRoutingOwner == nil
	coreState.RUnlock()
	if !unchanged || logger.calls != 1 {
		t.Fatal("rejected replacement changed published state or logger callback was blocked")
	}
}
