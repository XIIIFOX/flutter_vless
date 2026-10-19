package XRay

import (
	"errors"
	"reflect"
	"testing"
)

type routingLifecycleOwner struct{ events *[]string }

func (o routingLifecycleOwner) Close() error {
	*o.events = append(*o.events, "revoke")
	return errors.New("cleanup owner error")
}

type routingLifecycleRuntime struct {
	events     *[]string
	startError error
}

func (r *routingLifecycleRuntime) Start() error {
	*r.events = append(*r.events, "start")
	return r.startError
}
func (r *routingLifecycleRuntime) Close() error {
	*r.events = append(*r.events, "close")
	return errors.New("cleanup runtime error")
}

func TestNativeRoutingCandidateLifecycle(t *testing.T) {
	for _, failure := range []string{"construct", "seal", "start", "publish", "none"} {
		t.Run(failure, func(t *testing.T) {
			var events []string
			primary := errors.New("synthetic primary failure")
			runtime := &routingLifecycleRuntime{events: &events}
			if failure == "start" {
				runtime.startError = primary
			}
			old := &routingLifecycleRuntime{}
			published := routingRuntime(old)
			stage, err := activateNativeRoutingCandidate(routingLifecycleOwner{&events}, func() (routingRuntime, error) {
				events = append(events, "construct")
				if failure == "construct" {
					return nil, primary
				}
				return runtime, nil
			}, func(actual routingRuntime) error {
				if actual != runtime {
					t.Fatal("candidate identity changed")
				}
				events = append(events, "seal")
				if failure == "seal" {
					return primary
				}
				return nil
			}, func(actual routingRuntime) error {
				events = append(events, "publish")
				if failure == "publish" {
					return primary
				}
				published = actual
				return nil
			})
			if failure == "none" {
				if err != nil || stage != "" || published != runtime || !reflect.DeepEqual(events, []string{"construct", "seal", "start", "publish"}) {
					t.Fatal("successful candidate not published once", stage, err, events)
				}
				return
			}
			if err != primary || stage != failure || published != old {
				t.Fatal("failure changed the primary error or published runtime", stage, err)
			}
			want := map[string][]string{
				"construct": {"construct", "revoke"},
				"seal":      {"construct", "seal", "revoke", "close"},
				"start":     {"construct", "seal", "start", "revoke", "close"},
				"publish":   {"construct", "seal", "start", "publish", "revoke", "close"},
			}[failure]
			if !reflect.DeepEqual(events, want) {
				t.Fatal("cleanup order or stage admission changed", events, want)
			}
		})
	}
}

func TestNativeRoutingCandidateMissingRuntime(t *testing.T) {
	var events []string
	stage, err := activateNativeRoutingCandidate(routingLifecycleOwner{&events}, func() (routingRuntime, error) { return nil, nil }, func(routingRuntime) error { t.Fatal("nil candidate sealed"); return nil }, func(routingRuntime) error { t.Fatal("nil candidate published"); return nil })
	if err == nil || stage != "construct" || !reflect.DeepEqual(events, []string{"revoke"}) {
		t.Fatal("nil runtime accepted", stage, err, events)
	}
}
