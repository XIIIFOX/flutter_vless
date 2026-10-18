package internet

// UNPUBLISHED CAPABILITY. This internal pinned overlay is not an upstream API
// or a shipped runtime capability. No process-global hostname/owner registry.
import (
	"context"
	stderrors "errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	ErrNativeDNSScope       = stderrors.New("native DNS context unavailable")
	ErrNativeDNSClosed      = stderrors.New("native DNS owner closed")
	ErrNativeDNSIdentity    = stderrors.New("native DNS handler identity mismatch")
	ErrNativeDNSUnsupported = stderrors.New("native DNS path unavailable in prototype")
	ErrNativeDNSEndpoint    = stderrors.New("native transport endpoint is not owned")
)

type nativeDNSOwnerKey struct{}
type nativeDNSHandlerKey struct{}

// A native host binds Key to the exact compiled *core.OutboundHandlerConfig
// pointer at SourceIndex. Tag is verified, never used as the policy identity.
// The key/index/protobuf type is not supplied by caller JSON or MethodChannels.
type NativeDNSBinding struct {
	Key                any
	SourceIndex        int
	Tag, ProxyType     string
	TransportEndpoints bool
	Endpoints          []NativeDNSEndpoint
}

type NativeDNSEndpoint struct {
	Network   net.Network
	Host      string
	Port      net.Port
	Addresses []netip.Addr
}

type nativeDNSBinding struct {
	sourceIndex        int
	tag, proxyType     string
	transportEndpoints bool
	endpoints          map[string][]netip.Addr
}

type NativeDNSOwner struct {
	closed       atomic.Bool
	lifetime     context.Context
	cancel       context.CancelFunc
	bindings     map[any]nativeDNSBinding
	instanceLock sync.Mutex
	instanceKey  any
}

// NewNativeDNSOwner copies every map/slice. Native preparation and all policy
// validation happen before NewWithContext; candidate preflight never changes a
// live owner's state. Exactly one Core instance can bind this owner.
func NewNativeDNSOwner(bindings []NativeDNSBinding) (*NativeDNSOwner, error) {
	owner := &NativeDNSOwner{bindings: make(map[any]nativeDNSBinding, len(bindings))}
	owner.lifetime, owner.cancel = context.WithCancel(context.Background())
	indices := map[int]bool{}
	for _, binding := range bindings {
		key := reflect.ValueOf(binding.Key)
		if !key.IsValid() || key.Kind() != reflect.Pointer || key.IsNil() || binding.SourceIndex < 0 || indices[binding.SourceIndex] || binding.ProxyType == "" {
			return nil, ErrNativeDNSIdentity
		}
		if _, exists := owner.bindings[binding.Key]; exists {
			return nil, ErrNativeDNSIdentity
		}
		indices[binding.SourceIndex] = true
		compiled := nativeDNSBinding{sourceIndex: binding.SourceIndex, tag: binding.Tag, proxyType: binding.ProxyType,
			transportEndpoints: binding.TransportEndpoints, endpoints: map[string][]netip.Addr{}}
		if binding.TransportEndpoints {
			switch binding.ProxyType {
			case "xray.proxy.vless.outbound.Config", "xray.proxy.vmess.outbound.Config", "xray.proxy.trojan.ClientConfig",
				"xray.proxy.socks.ClientConfig", "xray.proxy.http.ClientConfig", "xray.proxy.shadowsocks.ClientConfig":
			default:
				return nil, ErrNativeDNSUnsupported
			}
			if len(binding.Endpoints) == 0 {
				return nil, ErrNativeDNSEndpoint
			}
		} else if len(binding.Endpoints) != 0 {
			return nil, ErrNativeDNSIdentity
		}
		for _, endpoint := range binding.Endpoints {
			name, err := nativeDNSName(endpoint.Host)
			if err != nil || endpoint.Port == 0 || (endpoint.Network != net.Network_TCP && endpoint.Network != net.Network_UDP) || len(endpoint.Addresses) == 0 {
				return nil, ErrNativeDNSEndpoint
			}
			key := nativeDNSEndpointKey(endpoint.Network, name, endpoint.Port)
			if _, exists := compiled.endpoints[key]; exists {
				return nil, ErrNativeDNSEndpoint
			}
			addresses := append([]netip.Addr(nil), endpoint.Addresses...)
			for index, address := range addresses {
				if !address.IsValid() || address.Zone() != "" {
					return nil, ErrNativeDNSEndpoint
				}
				addresses[index] = address.Unmap()
				if original, err := netip.ParseAddr(endpoint.Host); err == nil && original.Unmap() != addresses[index] {
					return nil, ErrNativeDNSEndpoint
				}
			}
			compiled.endpoints[key] = addresses
		}
		owner.bindings[binding.Key] = compiled
	}
	return owner, nil
}

func nativeDNSName(value string) (string, error) {
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		return address.Unmap().String(), nil
	}
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", ErrNativeDNSEndpoint
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrNativeDNSEndpoint
		}
		for _, value := range label {
			if !(value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-') {
				return "", ErrNativeDNSEndpoint
			}
		}
	}
	return name, nil
}

func nativeDNSEndpointKey(network net.Network, name string, port net.Port) string {
	return strconv.Itoa(int(network)) + "/" + name + "/" + strconv.Itoa(int(port))
}

func (owner *NativeDNSOwner) Close() error { owner.closed.Store(true); owner.cancel(); return nil }

func ContextWithNativeDNSOwner(ctx context.Context, owner *NativeDNSOwner) context.Context {
	return context.WithValue(ctx, nativeDNSOwnerKey{}, owner)
}

// NewHandler captures construction identity and actual features of its Core.
// The request context, tags and process-global InitSystemDialer values cannot
// substitute another owner, DNS feature or outbound manager.
func BindNativeDNSHandler(ctx context.Context, instance, key any, tag, proxyType string,
	client dns.Client, manager outbound.Manager) (*NativeDNSHandler, error) {
	owner, ok := ctx.Value(nativeDNSOwnerKey{}).(*NativeDNSOwner)
	if !ok || owner == nil {
		return nil, ErrNativeDNSScope
	}
	if owner.closed.Load() {
		return nil, ErrNativeDNSClosed
	}
	keyIdentity := reflect.ValueOf(key)
	if !keyIdentity.IsValid() || keyIdentity.Kind() != reflect.Pointer || keyIdentity.IsNil() {
		return nil, ErrNativeDNSIdentity
	}
	binding, ok := owner.bindings[key]
	identity := reflect.ValueOf(instance)
	if !ok || binding.tag != tag || binding.proxyType != proxyType || !identity.IsValid() || identity.Kind() != reflect.Pointer || identity.IsNil() || client == nil || manager == nil {
		return nil, ErrNativeDNSIdentity
	}
	owner.instanceLock.Lock()
	defer owner.instanceLock.Unlock()
	if owner.instanceKey == nil {
		owner.instanceKey = instance
	}
	if owner.instanceKey != instance {
		return nil, ErrNativeDNSIdentity
	}
	return &NativeDNSHandler{owner: owner, binding: binding, client: client, manager: manager}, nil
}

type NativeDNSHandler struct {
	owner   *NativeDNSOwner
	binding nativeDNSBinding
	client  dns.Client
	manager outbound.Manager
}

type nativeDNSContext struct {
	handler   *NativeDNSHandler
	transport bool
}

// Attach ownership only. Keep this operation's cancellation/deadline and never
// retain/copy a first request's mutable Outbounds, Content, or session ID.
func (handler *NativeDNSHandler) Context(ctx context.Context, transport bool) (context.Context, error) {
	if handler == nil || handler.owner == nil {
		return nil, ErrNativeDNSScope
	}
	if handler.owner.closed.Load() {
		return nil, ErrNativeDNSClosed
	}
	if previous, ok := ctx.Value(nativeDNSHandlerKey{}).(nativeDNSContext); ok {
		if previous.handler == nil || previous.handler.owner == nil {
			return nil, ErrNativeDNSScope
		}
		if previous.handler.owner != handler.owner {
			return nil, ErrNativeDNSIdentity
		}
	}
	if previous, ok := ctx.Value(nativeDNSOwnerKey{}).(*NativeDNSOwner); ok && previous != handler.owner {
		return nil, ErrNativeDNSIdentity
	}
	return context.WithValue(ctx, nativeDNSHandlerKey{}, nativeDNSContext{handler, transport}), nil
}

func nativeDNSContextFrom(ctx context.Context) (nativeDNSContext, error) {
	if err := ctx.Err(); err != nil {
		return nativeDNSContext{}, err
	}
	scope, ok := ctx.Value(nativeDNSHandlerKey{}).(nativeDNSContext)
	if !ok || scope.handler == nil || scope.handler.owner == nil {
		return nativeDNSContext{}, ErrNativeDNSScope
	}
	if scope.handler.owner.closed.Load() {
		return nativeDNSContext{}, ErrNativeDNSClosed
	}
	return scope, nil
}

func NativeDNSHandlerFromContext(ctx context.Context) *NativeDNSHandler {
	scope, err := nativeDNSContextFrom(ctx)
	if err != nil {
		return nil
	}
	return scope.handler
}

// Bind an individual physical dial to owner cancellation without capturing any
// first request in a cached object. The caller releases this link after Dial.
func NativeDNSOperationContext(ctx context.Context) (context.Context, func(), error) {
	scope, err := nativeDNSContextFrom(ctx)
	if err != nil {
		return nil, nil, err
	}
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(scope.handler.owner.lifetime, cancel)
	if scope.handler.owner.closed.Load() {
		stop()
		cancel()
		return nil, nil, ErrNativeDNSClosed
	}
	return operation, func() { stop(); cancel() }, nil
}

// Reject known independent resolver/cache paths in this deliberately narrow
// prototype. Runtime acceptance for these paths is still required separately.
func (handler *NativeDNSHandler) ValidateTransport(stream *MemoryStreamConfig) error {
	if stream == nil {
		return nil
	}
	switch stream.ProtocolName {
	case "tcp", "websocket", "httpupgrade", "udp":
	default:
		return ErrNativeDNSUnsupported
	}
	if stream.FinalMask != nil || stream.QuicParams != nil || stream.DownloadSettings != nil {
		return ErrNativeDNSUnsupported
	}
	for _, settings := range []any{stream.SecuritySettings, stream.ProtocolSettings} {
		if message, ok := settings.(proto.Message); ok && message != nil {
			unsupported := false
			message.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
				name := strings.ToLower(string(field.Name()))
				if strings.Contains(name, "ech") || strings.Contains(name, "browser") {
					unsupported = true
					return false
				}
				return true
			})
			if unsupported {
				return ErrNativeDNSUnsupported
			}
		}
	}
	return nil
}

type NativeDNSPhysicalPlan struct {
	Destination net.Destination
	ChainTag    string
}

// Pure planning boundary, used by DialSystem before any OS resolver/socket.
// A chained destination remains logical; only its leaf handler can bootstrap.
func PrepareNativeDNSPhysical(ctx context.Context, destination net.Destination, sockopt *SocketConfig) (NativeDNSPhysicalPlan, error) {
	scope, err := nativeDNSContextFrom(ctx)
	if err != nil {
		return NativeDNSPhysicalPlan{}, err
	}
	plan := NativeDNSPhysicalPlan{Destination: destination}
	if sockopt != nil {
		if sockopt.AddressPortStrategy != AddressPortStrategy_None {
			return plan, ErrNativeDNSUnsupported
		}
		if sockopt.DialerProxy != "" {
			plan.ChainTag = sockopt.DialerProxy
			return plan, nil
		}
	}
	if !scope.transport || !scope.handler.binding.transportEndpoints {
		return plan, nil
	}
	if destination.Address == nil {
		return plan, ErrNativeDNSEndpoint
	}
	addressName := destination.Address.String()
	if destination.Address.Family().IsIP() {
		addressName = destination.Address.IP().String()
	}
	name, err := nativeDNSName(addressName)
	if err != nil {
		return plan, err
	}
	addresses, ok := scope.handler.binding.endpoints[nativeDNSEndpointKey(destination.Network, name, destination.Port)]
	if !ok {
		return plan, ErrNativeDNSEndpoint
	}
	strategy := DomainStrategy_AS_IS
	if sockopt != nil {
		strategy = sockopt.DomainStrategy
	}
	var localAddr net.Address
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
		localAddr = outbounds[len(outbounds)-1].Gateway
	}
	allowed := func(address netip.Addr, fallback bool) bool {
		if !strategy.HasStrategy() {
			return localAddr == nil || address.Is4() && localAddr.Family().IsIPv4() || address.Is6() && localAddr.Family().IsIPv6()
		}
		v4, v6 := strategy.PreferIP4(), strategy.PreferIP6()
		if fallback {
			v4, v6 = strategy.FallbackIP4(), strategy.FallbackIP6()
		}
		return address.Is4() && v4 && (localAddr == nil || localAddr.Family().IsIPv4()) || address.Is6() && v6 && (localAddr == nil || localAddr.Family().IsIPv6())
	}
	for _, address := range addresses {
		if allowed(address, false) {
			plan.Destination.Address = net.IPAddress(address.AsSlice())
			return plan, nil
		}
	}
	for _, address := range addresses {
		if localAddr == nil && allowed(address, true) {
			plan.Destination.Address = net.IPAddress(address.AsSlice())
			return plan, nil
		}
	}
	return plan, ErrNativeDNSEndpoint
}

func NativeDNSChainHandler(ctx context.Context, tag string) (outbound.Handler, error) {
	scope, err := nativeDNSContextFrom(ctx)
	if err != nil {
		return nil, err
	}
	handler := scope.handler.manager.GetHandler(tag)
	if handler == nil {
		return nil, ErrNativeDNSIdentity
	}
	return handler, nil
}

// Ordinary caller lookup never reads endpoint pins, even for the same name.
func LookupForIPContext(ctx context.Context, domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	scope, err := nativeDNSContextFrom(ctx)
	if err != nil {
		return nil, err
	}
	client := scope.handler.client
	ips, _, err := client.LookupIP(domain, dns.IPOption{
		IPv4Enable: (localAddr == nil && strategy.PreferIP4()) || (localAddr != nil && localAddr.Family().IsIPv4() && (strategy.PreferIP4() || strategy.FallbackIP4())),
		IPv6Enable: (localAddr == nil && strategy.PreferIP6()) || (localAddr != nil && localAddr.Family().IsIPv6() && (strategy.PreferIP6() || strategy.FallbackIP6())),
	})
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if (len(ips) == 0 || err != nil) && strategy.HasFallback() && localAddr == nil {
		if scope.handler.owner.closed.Load() {
			return nil, ErrNativeDNSClosed
		}
		ips, _, err = client.LookupIP(domain, dns.IPOption{IPv4Enable: strategy.FallbackIP4(), IPv6Enable: strategy.FallbackIP6()})
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
	}
	if scope.handler.owner.closed.Load() {
		return nil, ErrNativeDNSClosed
	}
	if err == nil && len(ips) == 0 {
		return nil, dns.ErrEmptyResponse
	}
	return ips, err
}
