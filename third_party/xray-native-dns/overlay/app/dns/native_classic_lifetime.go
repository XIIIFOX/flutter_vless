package dns

import "sync"

// The request-map lock cannot span Periodic.Start: its first Execute acquires
// that same lock. This gate makes registration/Start atomic with final Close.
type nativeClassicLifetime struct {
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
}

func (s *ClassicNameServer) closeNativeClassicLifetime() {
	s.nativeLifetime.closeOnce.Do(func() {
		s.nativeLifetime.mu.Lock()
		s.nativeLifetime.closed = true
		if s.requestsCleanup != nil {
			_ = s.requestsCleanup.Close()
		}
		s.Lock()
		s.requests = make(map[uint16]*udpDnsRequest)
		s.Unlock()
		s.nativeLifetime.mu.Unlock()

		// Never hold the admission or request lock over Dispatch/WriteMultiBuffer
		// or its interruption. RemoveRay closes the final new-ray gate and
		// interrupts the existing ray; it does not promise a worker join.
		if s.udpServer != nil {
			s.udpServer.RemoveRay()
		}
	})
}

func closeNativeClassicServers(clients []*Client) {
	for _, client := range clients {
		if classic, ok := client.server.(*ClassicNameServer); ok && classic != nil {
			classic.closeNativeClassicLifetime()
		}
	}
}
