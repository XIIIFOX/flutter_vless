package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/dns/dnsmessage"
)

type routedDNSTestLink struct {
	request  *pipe.Reader
	response *pipe.Writer
	ctx      context.Context
}

type routedDNSTestDispatcher struct {
	routing.Dispatcher
	links chan routedDNSTestLink
}

func (d *routedDNSTestDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	request, toServer := pipe.New()
	toClient, response := pipe.New()
	d.links <- routedDNSTestLink{request: request, response: response, ctx: ctx}
	return &transport.Link{Reader: toClient, Writer: toServer}, nil
}

func routedDNSTestReceive[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case value := <-c:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("fixture deadline exceeded")
		var zero T
		return zero
	}
}

func (l routedDNSTestLink) query(t *testing.T) dnsmessage.Message {
	t.Helper()
	packet, err := l.request.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, packet.Len())
	packet, size := buf.SplitBytes(packet, frame)
	buf.ReleaseMulti(packet)
	var msg dnsmessage.Message
	if size < 2 || int(binary.BigEndian.Uint16(frame)) != size-2 ||
		msg.Unpack(frame[2:]) != nil || len(msg.Questions) != 1 {
		t.Fatal("expected a complete framed DNS question")
	}
	return msg
}

func (l routedDNSTestLink) answer(t *testing.T, query dnsmessage.Message, body dnsmessage.ResourceBody) {
	t.Helper()
	question := query.Questions[0]
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: question.Class, TTL: 60},
			Body:   body,
		}},
	}
	packet, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2, len(packet)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	frame = append(frame, packet...)
	if err := l.response.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame)}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRoutedTCPDNSLifetime(t *testing.T) {
	dispatcher := &routedDNSTestDispatcher{links: make(chan routedDNSTestLink, 1)}
	resolver, err := NewTCPNameServer(&url.URL{Scheme: "tcp", Host: "127.0.0.1:1053"},
		dispatcher, false, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	type dnsResult struct {
		ips []net.IP
		err error
	}
	query := func(ctx context.Context, domain string, options featuredns.IPOption) <-chan dnsResult {
		ch := make(chan dnsResult, 1)
		go func() {
			ips, _, err := resolver.QueryIP(ctx, domain, options)
			ch <- dnsResult{ips, err}
		}()
		return ch
	}
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	pending := query(ctx, "cancel.fixture.invalid", featuredns.IPOption{IPv4Enable: true})
	link := routedDNSTestReceive(t, dispatcher.links)
	t.Cleanup(link.response.Interrupt)
	_ = link.query(t)
	cancel()
	if result := routedDNSTestReceive(t, pending); result.err == nil || len(result.ips) != 0 {
		t.Fatal("canceled lookup still returned an address")
	}
	if frame, err := link.request.ReadMultiBufferTimeout(time.Second); !errors.Is(err, io.EOF) {
		buf.ReleaseMulti(frame)
		t.Fatalf("canceled lookup left its stream open: %v", err)
	}
	routedDNSTestReceive(t, link.ctx.Done())

	for _, test := range []struct {
		label   string
		options featuredns.IPOption
		body    dnsmessage.ResourceBody
		address string
	}{
		{"ipv4", featuredns.IPOption{IPv4Enable: true}, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 20}}, "192.0.2.20"},
		{"ipv6", featuredns.IPOption{IPv6Enable: true}, &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20}}, "2001:db8::14"},
	} {
		t.Run(test.label, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(base, time.Second)
			defer cancel()
			pending := query(ctx, "valid.fixture.invalid", test.options)
			link := routedDNSTestReceive(t, dispatcher.links)
			t.Cleanup(link.response.Interrupt)
			link.answer(t, link.query(t), test.body)
			result := routedDNSTestReceive(t, pending)
			if result.err != nil || len(result.ips) != 1 || result.ips[0].String() != test.address {
				t.Fatalf("ordinary lookup failed: %v", result)
			}
			routedDNSTestReceive(t, link.ctx.Done())
		})
	}
}
