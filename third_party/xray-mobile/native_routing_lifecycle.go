package XRay

import "errors"

type routingRuntime interface {
	Start() error
	Close() error
}

type routingRevoker interface{ Close() error }

// Candidate ownership stays local until all stages succeed. The constructor
// owns partial-construction cleanup; a returned full instance belongs here.
// Cleanup failures cannot hide the primary failure or publish a failed runtime.
func activateNativeRoutingCandidate(owner routingRevoker, construct func() (routingRuntime, error), seal func(routingRuntime) error, publish func(routingRuntime) error) (stage string, failure error) {
	var candidate routingRuntime
	accepted := false
	defer func() {
		if accepted {
			return
		}
		_ = owner.Close()
		if candidate != nil {
			_ = candidate.Close()
		}
	}()
	var err error
	candidate, err = construct()
	if err != nil {
		return "construct", err
	}
	if candidate == nil {
		return "construct", errors.New("native routing constructor returned no instance")
	}
	if err = seal(candidate); err != nil {
		return "seal", err
	}
	if err = candidate.Start(); err != nil {
		return "start", err
	}
	if err = publish(candidate); err != nil {
		return "publish", err
	}
	accepted = true
	return "", nil
}
