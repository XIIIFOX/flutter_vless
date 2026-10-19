package XRay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"google.golang.org/protobuf/proto"
)

// The native spec is a separate trusted argument, never a caller-config field.
// Required pointer fields distinguish a missing value from index/version zero.
type nativeRoutingSpec struct {
	Version             *int    `json:"version"`
	SourceSHA256        *string `json:"source_sha256"`
	ManagedInboundIndex *int    `json:"managed_inbound_index"`
	ManagedInboundTag   *string `json:"managed_inbound_tag"`
	AuthUser            *string `json:"auth_user"`
	SourceInboundIndex  *int    `json:"source_inbound_index"`
	DefaultOutboundTag  string  `json:"default_outbound_tag"`
	GuardRuleIndices    []int   `json:"guard_rule_indices"`
}

// Retained final compiled objects, not a rebuildable or public preparation API.
// The tagged factory must pass this exact key and config to NewWithContext.
type nativeRoutingPrepared struct {
	config                      *core.Config
	key                         *core.InboundHandlerConfig
	managedIndex                int
	managedTag, authUser, alias string
	defaultTag                  string
	aliasEnabled                bool
	guards                      []*router.RoutingRule
	level                       xlog.Severity
	diagnostics                 bool
}

func parseNativeRoutingSpec(encoded []byte) (*nativeRoutingSpec, bool) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	seen := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok {
			return nil, false
		}
		switch key {
		case "version", "source_sha256", "managed_inbound_index", "managed_inbound_tag", "auth_user", "source_inbound_index", "default_outbound_tag", "guard_rule_indices":
		default:
			return nil, false
		}
		if _, exists := seen[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		seen[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) != io.EOF {
		return nil, false
	}
	var spec nativeRoutingSpec
	if json.Unmarshal(encoded, &spec) != nil || spec.Version == nil || *spec.Version != 1 || spec.SourceSHA256 == nil ||
		spec.ManagedInboundIndex == nil || spec.ManagedInboundTag == nil || *spec.ManagedInboundTag == "" || spec.AuthUser == nil || *spec.AuthUser == "" {
		return nil, false
	}
	if raw, present := seen["default_outbound_tag"]; present && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, false
	}
	// encoding/json maps a null element of []int to zero. Only the whole
	// optional list may be null; an individual guard must be an integer index.
	if raw, present := seen["guard_rule_indices"]; present {
		var indices []*int
		if json.Unmarshal(raw, &indices) != nil {
			return nil, false
		}
		for _, index := range indices {
			if index == nil {
				return nil, false
			}
		}
	}
	return &spec, true
}

func nativeRoutingPrivateInput(key *core.InboundHandlerConfig, tag, user string) bool {
	if key == nil || key.Tag != tag || key.ReceiverSettings == nil || key.ProxySettings == nil {
		return false
	}
	rawReceiver, err := key.ReceiverSettings.GetInstance()
	if err != nil {
		return false
	}
	receiver, ok := rawReceiver.(*proxyman.ReceiverConfig)
	if !ok || receiver.Listen == nil || receiver.PortList == nil || len(receiver.PortList.Range) != 1 || receiver.ReceiveOriginalDestination {
		return false
	}
	listen := receiver.Listen.AsAddress()
	if listen == nil || !listen.Family().IsIP() || !listen.IP().IsLoopback() {
		return false
	}
	port := receiver.PortList.Range[0]
	if port == nil || port.From == 0 || port.From > 65535 || port.From != port.To {
		return false
	}
	if stream := receiver.StreamSettings; stream != nil {
		if (stream.ProtocolName != "" && stream.ProtocolName != "tcp") || stream.SecurityType != "" || len(stream.SecuritySettings) != 0 || len(stream.Tcpmasks) != 0 || len(stream.Udpmasks) != 0 {
			return false
		}
		if socket := stream.SocketSettings; socket != nil && (socket.Tproxy != internet.SocketConfig_Off || socket.AcceptProxyProtocol || socket.AddressPortStrategy != internet.AddressPortStrategy_None) {
			return false
		}
		for _, transport := range stream.TransportSettings {
			if transport == nil || transport.ProtocolName != "tcp" {
				continue
			}
			settings, err := transport.Settings.GetInstance()
			if err != nil {
				return false
			}
			plain, ok := settings.(*tcp.Config)
			if !ok || plain.AcceptProxyProtocol || (plain.HeaderSettings != nil && plain.HeaderSettings.Type != "xray.transport.internet.headers.noop.ConnectionConfig") {
				return false
			}
		}
	}
	rawProxy, err := key.ProxySettings.GetInstance()
	if err != nil {
		return false
	}
	proxy, ok := rawProxy.(*socks.ServerConfig)
	if !ok || proxy.AuthType != socks.AuthType_PASSWORD || len(proxy.Accounts) != 1 {
		return false
	}
	password, exists := proxy.Accounts[user]
	return exists && password != ""
}

func nativeRoutingGuardValid(rule *router.RoutingRule) (valid bool) {
	if rule == nil || rule.GetTag() == "" || rule.GetBalancingTag() != "" || rule.Webhook != nil || len(rule.InboundTag) == 0 {
		return false
	}
	for _, tag := range rule.InboundTag {
		if tag == "" {
			return false
		}
	}
	// Core's attribute-condition builder uses regexp.MustCompile. A malformed
	// selected guard must be a closed preflight refusal, not a native panic.
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	_, err := rule.BuildCondition()
	return err == nil
}

func prepareNativeRouting(config, specBytes []byte) (*nativeRoutingPrepared, int64) {
	spec, ok := parseNativeRoutingSpec(specBytes)
	if !ok {
		return nil, 16
	}
	digest, err := hex.DecodeString(*spec.SourceSHA256)
	want := sha256.Sum256(config)
	if err != nil || len(digest) != len(want) || !bytes.Equal(digest, want[:]) {
		return nil, 17
	}
	private, level, enabled, err := privateConfig(config)
	if err != nil {
		return nil, 1
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(private))
	if err != nil {
		return nil, 2
	}
	// Core Build applies root Env entries with os.Setenv. Deny them before the
	// single Build call; preflight must not change a running session's process.
	if len(decoded.Env) != 0 {
		return nil, 5
	}
	compiled, err := decoded.Build()
	if err != nil || compiled == nil {
		return nil, 3
	}
	index := *spec.ManagedInboundIndex
	if index < 0 || index >= len(compiled.Inbound) || !nativeRoutingPrivateInput(compiled.Inbound[index], *spec.ManagedInboundTag, *spec.AuthUser) {
		return nil, 18
	}
	count := 0
	for _, input := range compiled.Inbound {
		if input.GetTag() == *spec.ManagedInboundTag {
			count++
		}
	}
	if count != 1 {
		return nil, 18
	}
	prepared := &nativeRoutingPrepared{config: compiled, key: compiled.Inbound[index], managedIndex: index, managedTag: *spec.ManagedInboundTag,
		authUser: *spec.AuthUser, defaultTag: spec.DefaultOutboundTag, level: level, diagnostics: enabled}
	if source := spec.SourceInboundIndex; source != nil {
		if *source < 0 || *source >= len(compiled.Inbound) || *source == index || compiled.Inbound[*source] == nil {
			return nil, 19
		}
		prepared.aliasEnabled, prepared.alias = true, compiled.Inbound[*source].Tag
	}
	if spec.DefaultOutboundTag != "" {
		count := 0
		for _, outbound := range compiled.Outbound {
			if outbound.GetTag() == spec.DefaultOutboundTag {
				count++
			}
		}
		if count != 1 {
			return nil, 20
		}
	}
	if len(spec.GuardRuleIndices) != 0 {
		var caller *router.Config
		for _, app := range compiled.App {
			if app.Type != "xray.app.router.Config" {
				continue
			}
			value, err := app.GetInstance()
			if err != nil || caller != nil {
				return nil, 21
			}
			caller, ok = value.(*router.Config)
			if !ok {
				return nil, 21
			}
		}
		seen := make(map[int]bool)
		for _, index := range spec.GuardRuleIndices {
			if caller == nil || index < 0 || index >= len(caller.Rule) || seen[index] || !nativeRoutingGuardValid(caller.Rule[index]) {
				return nil, 21
			}
			seen[index] = true
			prepared.guards = append(prepared.guards, proto.Clone(caller.Rule[index]).(*router.RoutingRule))
		}
	}
	return prepared, 0
}
