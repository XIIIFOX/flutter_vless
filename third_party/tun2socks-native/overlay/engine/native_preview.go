package engine

// The private entry constructs a restricted Key from its validated policy.
// Errors stay with its closed protocol, never an upstream fatal/raw error.
func StartNativePreview(key *Key) (bool, error) {
	Insert(key)
	if err := start(); err != nil {
		_engineMu.Lock()
		adopted := _defaultDevice != nil
		_engineMu.Unlock()
		_ = stop()
		return adopted, err
	}
	return true, nil
}
func StopNativePreview() error { return stop() }
