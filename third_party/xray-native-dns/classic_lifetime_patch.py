"""Guarded Classic DNS shutdown only; also usable without the full DNS overlay.

The caller supplies the checked replace(path, before, after) function and copies
only overlay/app/dns/native_classic_*.go into its disposable pinned Core tree.
"""


def apply(root, replace):
    replace('app/dns/nameserver_udp.go',
            'type ClassicNameServer struct {\n\tsync.RWMutex',
            'type ClassicNameServer struct {\n\tnativeLifetime nativeClassicLifetime\n\tsync.RWMutex')
    replace('app/dns/nameserver_udp.go',
            '''func (s *ClassicNameServer) addPendingRequest(req *udpDnsRequest) {
	s.Lock()
	id := req.msg.ID
	req.expire = time.Now().Add(time.Second * 8)
	s.requests[id] = req
	s.Unlock()
	common.Must(s.requestsCleanup.Start())
}''',
            '''func (s *ClassicNameServer) addPendingRequest(req *udpDnsRequest) bool {
	// Periodic.Start immediately calls RequestsCleanup. Use a distinct lifetime
	// mutex, never the request-map mutex, across admission plus Start.
	s.nativeLifetime.mu.Lock()
	defer s.nativeLifetime.mu.Unlock()
	if s.nativeLifetime.closed { return false }
	s.Lock()
	id := req.msg.ID
	req.expire = time.Now().Add(time.Second * 8)
	s.requests[id] = req
	s.Unlock()
	common.Must(s.requestsCleanup.Start())
	return true
}''')
    replace('app/dns/nameserver_udp.go',
            '\t\t\ts.addPendingRequest(&newReq)\n',
            '\t\t\tif !s.addPendingRequest(&newReq) { return }\n')
    replace('app/dns/nameserver_udp.go',
            '\t\ts.addPendingRequest(udpReq)\n',
            '''		if !s.addPendingRequest(udpReq) {
			if noResponseErrCh != nil { noResponseErrCh <- errors.New("DNS server closed") }
			continue
		}
''')
    # Works with ordinary Core or after local_resolver_patch's existing local
    # cleanup insertion; it does not replace either script/local cleanup.
    replace('app/dns/dns.go',
            'func (s *DNS) Close() error {',
            'func (s *DNS) Close() error {\n\tcloseNativeClassicServers(s.clients)')

    # managed_input_patch already fixes this exact terminal ownership branch.
    # Admit exactly its known patched state or the original pinned state.
    path = 'transport/internet/udp/dispatcher.go'
    before = '''conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		return
	}'''
    after = '''conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		payload.Release()
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		return
	}'''
    source = (root / path).read_text()
    if source.count(before) == 1 and source.count(after) == 0:
        replace(path, before, after)
    elif source.count(before) != 0 or source.count(after) != 1:
        raise ValueError('Pinned Classic DNS payload ownership branch mismatch')
