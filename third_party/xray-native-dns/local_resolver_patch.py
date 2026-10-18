"""Exact additive local/default DNS seams, only in the guarded disposable copy."""


def apply(root, replace):
    # Keep the legacy resolver constructor/body (including Android's protected
    # d.DialContext block) byte-identical for the existing protection overlay.
    replace('features/dns/localdns/client.go',
            'type Client struct {\n\td *net.Dialer',
            'type Client struct {\n\tnative *nativeLocalState\n\td *net.Dialer')
    replace('features/dns/localdns/client.go',
            'func (*Client) Close() error { return nil }',
            'func (c *Client) Close() error { return c.closeNativeLocal() }')
    replace('features/dns/localdns/client.go',
            'func (c *Client) LookupIP(host string, option dns.IPOption) ([]net.IP, uint32, error) {',
            '''func (c *Client) LookupIP(host string, option dns.IPOption) ([]net.IP, uint32, error) {
	if c.native != nil { return c.LookupIPContext(context.Background(), host, option) }''')
    replace('app/dns/nameserver_local.go',
            'ips, ttl, err = s.client.LookupIP(domain, option)',
            'ips, ttl, err = s.client.LookupIPContext(ctx, domain, option)')
    replace('app/dns/nameserver.go',
            'return NewLocalNameServer(), nil',
            'return NewLocalNameServerWithContext(ctx), nil')
    replace('app/dns/dns.go',
            'clients = append(clients, NewLocalDNSClient(ipOption))',
            'clients = append(clients, NewLocalDNSClientWithContext(ctx, ipOption))')
    replace('app/dns/dns.go',
            '''func (s *DNS) Close() error {
	if s.script != nil {''',
            '''func (s *DNS) Close() error {
	for _, client := range s.clients {
		if local, ok := client.server.(*LocalNameServer); ok { _ = local.closeNativeLocal() }
	}
	if s.script != nil {''')
    replace('core/xray.go',
            '{dns.ClientType(), localdns.New()},',
            '{dns.ClientType(), nativeLocalEssentialClient(server)},')
    replace('core/xray.go',
            '\t"github.com/xtls/xray-core/features/dns/localdns"\n',
            '')
    replace('core/xray.go',
            '''server := &Instance{ctx: ctx}

	done, err := initInstanceWithConfig(config, server)
	if done {
		return nil, err
	}''',
            '''server := &Instance{ctx: ctx}

	done, err := initInstanceWithConfig(config, server)
	if done {
		closeNativeDNSPartialInstance(server)
		return nil, err
	}''')
    for kind in ('inbound', 'outbound'):
        replace('core/xray.go',
                f'''if err := {kind}Manager.AddHandler(server.ctx, handler); err != nil {{
		return err
	}}''',
                f'''if err := {kind}Manager.AddHandler(server.ctx, handler); err != nil {{
		closeNativeDNSUnaddedHandler(server.ctx, handler)
		return err
	}}''')
