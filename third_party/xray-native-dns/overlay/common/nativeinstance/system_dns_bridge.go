package nativeinstance

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
)

const maxSystemDNSQuery = 512
const maxSystemDNSReply = 4096
const maxSystemDNSAnswers = 256

// SystemDNSBridgePolicy grants an OPTIONAL wire-query primitive to trusted
// native code. It does not install a listener, route, proxy, CLI command, packet
// interceptor or OS/TUN/browser integration. A future consumer must authenticate
// its managed input and carry exact compiled-handler identity, not merely a tag.
// V1 is IPv4 only: A uses caller root DNS; AAAA returns deliberate NODATA.
type SystemDNSBridgePolicy struct{ VirtualIPv4 netip.Addr }

type systemDNSBinding struct {
	identity *core.Config // exact per-Start compiled clone; never exported
	owner    *internet.NativeDNSOwner
	virtual  netip.Addr
}

// SystemDNSBridge is an opaque capability minted by one Runtime. An empty or
// stale value cannot be used. Caller JSON and request metadata cannot grant it.
// It owns no socket; ExchangeUDP/TCP are wire-message framing APIs only.
type SystemDNSBridge struct {
	runtime *Runtime
	binding *systemDNSBinding
}

func (r *Runtime) SystemDNSBridge() (*SystemDNSBridge, error) {
	if r == nil {
		return nil, ErrClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.life.Err() != nil || r.core == nil {
		return nil, ErrClosed
	}
	if r.bridge == nil {
		return nil, ErrUnsupported
	}
	return &SystemDNSBridge{runtime: r, binding: r.bridge}, nil
}

// ExchangeUDP consumes one ordinary DNS message and returns one bounded wire
// response. No packet is sent to destination: it must equal trusted virtual:53.
func (b *SystemDNSBridge) ExchangeUDP(ctx context.Context, destination netip.AddrPort, query []byte) ([]byte, error) {
	return b.exchange(ctx, destination, query, false)
}

// ExchangeTCP consumes/returns exactly one complete two-byte-length-prefixed DNS
// message. It does not implement a TCP listener, stream reassembly or pipelining.
func (b *SystemDNSBridge) ExchangeTCP(ctx context.Context, destination netip.AddrPort, query []byte) ([]byte, error) {
	return b.exchange(ctx, destination, query, true)
}

func (b *SystemDNSBridge) validLocked(destination netip.AddrPort) bool {
	r := b.runtime
	return r != nil && b.binding != nil && r.bridge == b.binding && b.binding.identity != nil &&
		b.binding.owner == r.owner && !r.closed && r.life.Err() == nil && r.core != nil &&
		destination == netip.AddrPortFrom(b.binding.virtual, 53)
}

func (b *SystemDNSBridge) exchange(ctx context.Context, destination netip.AddrPort, query []byte, tcp bool) ([]byte, error) {
	if b == nil || b.runtime == nil || ctx == nil {
		return nil, ErrClosed
	}
	r := b.runtime
	operation, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	r.mu.Lock()
	valid := b.validLocked(destination)
	r.mu.Unlock()
	if !valid {
		return nil, ErrClosed
	}
	if err := operation.Err(); err != nil {
		return nil, err
	}
	if tcp {
		if len(query) < 2 || int(binary.BigEndian.Uint16(query[:2])) != len(query)-2 {
			return nil, ErrDNSQuery
		}
		query = query[2:]
	}
	if len(query) < 12 || len(query) > maxSystemDNSQuery {
		return nil, ErrDNSQuery
	}
	// Freeze the message before any wait. The caller may reuse its input buffer
	// after dispatch; no worker or cached reply retains a caller-owned slice.
	packet := append([]byte(nil), query...)
	header, question, refuse, err := parseSystemDNS(packet)
	if err != nil {
		return nil, ErrDNSQuery
	}
	answer := lookupResult{}
	rcode := dnsmessage.RCodeRefused
	if !refuse {
		switch question.Type {
		case dnsmessage.TypeA:
			answer, err = r.lookupRoot(operation, question.Name.String())
			if err != nil {
				return nil, err
			}
			rcode = systemDNSRCode(answer.err)
		case dnsmessage.TypeAAAA:
			// Explicit trusted IPv4-only policy, not a claim of IPv6 DNS preservation.
			rcode = dnsmessage.RCodeSuccess
		}
	}
	reply, err := buildSystemDNSReply(header, question, answer, rcode, tcp)
	if err != nil {
		return nil, ErrDNSQuery
	}
	if tcp {
		framed := make([]byte, len(reply)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(reply)))
		copy(framed[2:], reply)
		reply = framed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !b.validLocked(destination) {
		return nil, ErrClosed
	}
	if err := operation.Err(); err != nil {
		return nil, err
	}
	return append([]byte(nil), reply...), nil
}

// This first wire subset accepts one uncompressed question. It deliberately
// refuses EDNS/additional/answer sections and nonstandard query flags/opcodes.
// Unsupported well-framed queries receive REFUSED; malformed frames receive a
// fixed error and never reach root DNS. It does not advertise full DNS support.
func parseSystemDNS(packet []byte) (dnsmessage.Header, dnsmessage.Question, bool, error) {
	if len(packet) < 12 || len(packet) > maxSystemDNSQuery {
		return dnsmessage.Header{}, dnsmessage.Question{}, false, ErrDNSQuery
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil || header.Response || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return header, dnsmessage.Question{}, false, ErrDNSQuery
	}
	offset := 12
	for {
		if offset >= len(packet) {
			return header, dnsmessage.Question{}, false, ErrDNSQuery
		}
		size := int(packet[offset])
		offset++
		if size&0xc0 != 0 || size > 63 || offset+size > len(packet) {
			return header, dnsmessage.Question{}, false, ErrDNSQuery
		}
		if size == 0 {
			break
		}
		offset += size
	}
	if offset+4 > len(packet) {
		return header, dnsmessage.Question{}, false, ErrDNSQuery
	}
	offset += 4
	question, err := parser.Question()
	if err != nil {
		return header, question, false, ErrDNSQuery
	}
	sections := binary.BigEndian.Uint16(packet[6:8]) != 0 || binary.BigEndian.Uint16(packet[8:10]) != 0 || binary.BigEndian.Uint16(packet[10:12]) != 0
	if !sections && offset != len(packet) {
		return header, question, false, ErrDNSQuery
	}
	refuse := sections || packet[3]&0x40 != 0 || header.OpCode != 0 || header.Truncated || header.Authoritative || header.RecursionAvailable || header.CheckingDisabled || header.RCode != 0 ||
		question.Class != dnsmessage.ClassINET || !validLookupName(question.Name.String())
	return header, question, refuse, nil
}

// Only closed wire status escapes. Root errors are never returned/formatted.
func systemDNSRCode(err error) dnsmessage.RCode {
	if err == nil || errors.Is(err, featuredns.ErrEmptyResponse) {
		return dnsmessage.RCodeSuccess
	}
	code := featuredns.RCodeFromError(err)
	if code > 0 && code <= 15 {
		return dnsmessage.RCode(code)
	}
	return dnsmessage.RCodeServerFailure
}

func buildSystemDNSReply(query dnsmessage.Header, question dnsmessage.Question, answer lookupResult, rcode dnsmessage.RCode, tcp bool) ([]byte, error) {
	header := dnsmessage.Header{ID: query.ID, OpCode: query.OpCode, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true, RCode: rcode}
	// Root A answers are copied and family checked. A non-IPv4/invalid success
	// result cannot be represented as a successful IPv4-policy response.
	if rcode == dnsmessage.RCodeSuccess && question.Type == dnsmessage.TypeA {
		for _, ip := range answer.ips {
			if ip.To4() == nil {
				header.RCode = dnsmessage.RCodeServerFailure
				break
			}
		}
	}
	overLimit := len(answer.ips) > maxSystemDNSAnswers
	if overLimit && tcp {
		header.RCode = dnsmessage.RCodeServerFailure
	}
	if overLimit && !tcp {
		header.Truncated = true
	}
	build := func(includeAnswers bool) ([]byte, error) {
		builder := dnsmessage.NewBuilder(make([]byte, 0, maxSystemDNSReply), header)
		builder.EnableCompression()
		if builder.StartQuestions() != nil || builder.Question(question) != nil || builder.StartAnswers() != nil {
			return nil, ErrDNSQuery
		}
		if includeAnswers && header.RCode == dnsmessage.RCodeSuccess && question.Type == dnsmessage.TypeA && !header.Truncated {
			for _, ip := range answer.ips {
				var body dnsmessage.AResource
				copy(body.A[:], ip.To4())
				resource := dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: answer.ttl}
				if builder.AResource(resource, body) != nil {
					return nil, ErrDNSQuery
				}
			}
		}
		return builder.Finish()
	}
	reply, err := build(!overLimit)
	if err != nil {
		return nil, ErrDNSQuery
	}
	if len(reply) > maxSystemDNSReply {
		header.RCode = dnsmessage.RCodeServerFailure
		header.Truncated = false
		return build(false)
	}
	if !tcp && len(reply) > 512 {
		header.Truncated = true
		return build(false)
	}
	return reply, nil
}
