package dns

import (
	"context"

	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// Retain LocalNameServer's concrete type/name and root matcher semantics. Only
// the local lookup mechanism is scoped; no caller server, tag or hosts is changed.
func NewLocalNameServerWithContext(ctx context.Context) *LocalNameServer {
	return &LocalNameServer{client: localdns.NewWithContext(ctx)}
}

func NewLocalDNSClientWithContext(ctx context.Context, option dns.IPOption) *Client {
	if _, scoped := dns.NativeLocalResolverFromContext(ctx); !scoped {
		return NewLocalDNSClient(option)
	}
	// Legacy implicit clients have zero timeout. Honouring that context would
	// immediately cancel every scoped lookup, so provide the native hard bound.
	return &Client{id: "localhost", server: NewLocalNameServerWithContext(ctx),
		ipOption: &option, timeoutMs: dns.NativeLocalResolverTimeout}
}

func (s *LocalNameServer) closeNativeLocal() error { return s.client.Close() }
