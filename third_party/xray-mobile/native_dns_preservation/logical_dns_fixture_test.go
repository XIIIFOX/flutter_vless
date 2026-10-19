package native_dns_preservation_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"

	dns "github.com/miekg/dns"
)

type logicalDNSMemoryIO struct {
	input         *bytes.Reader
	output        bytes.Buffer
	terminalReads int
}

func (stream *logicalDNSMemoryIO) Read(data []byte) (int, error) {
	if stream.input.Len() == 0 {
		stream.terminalReads++
		return 0, errors.New("synthetic reset after owned DNS frame")
	}
	return stream.input.Read(data)
}
func (stream *logicalDNSMemoryIO) Write(data []byte) (int, error) { return stream.output.Write(data) }

func logicalDNSFrame(packet []byte) []byte {
	frame := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	copy(frame[2:], packet)
	return frame
}

// Pure in-memory I/O only. A valid exchange must not read a second packet;
// malformed/truncated input must fail before any answer bytes are written.
func testLogicalDNSFixtureIO(t *testing.T) {
	t.Run("logical_dns_exchange", func(t *testing.T) {
		question := new(dns.Msg)
		question.SetQuestion("logical-query.invalid.", dns.TypeA)
		question.Id = 0x7128
		packet, err := question.Pack()
		if err != nil {
			t.Fatal(err)
		}
		t.Run("one_frame_then_reset", func(t *testing.T) {
			stream := &logicalDNSMemoryIO{input: bytes.NewReader(logicalDNSFrame(packet))}
			observed := new(fixture)
			if err := logicalDNSExchange(stream, observed); err != nil {
				t.Fatal("finite DNS exchange read beyond its response", err)
			}
			if stream.terminalReads != 0 {
				t.Fatal("DNS exchange read beyond its owned query")
			}
			response := bytes.NewReader(stream.output.Bytes())
			var size uint16
			if err := binary.Read(response, binary.BigEndian, &size); err != nil {
				t.Fatal(err)
			}
			body := make([]byte, size)
			if _, err := io.ReadFull(response, body); err != nil || response.Len() != 0 {
				t.Fatal("wrong response framing", err)
			}
			answer := new(dns.Msg)
			if answer.Unpack(body) != nil || answer.Id != question.Id || !reflect.DeepEqual(answer.Question, question.Question) ||
				answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
				t.Fatal("finite DNS answer identity changed")
			}
			record, ok := answer.Answer[0].(*dns.A)
			if !ok || record.A.String() != "192.0.2.81" {
				t.Fatal("finite DNS payload changed")
			}
			queries, failures := observed.snapshot()
			if !reflect.DeepEqual(queries, []string{"logical-query.invalid./1"}) || len(failures) != 0 {
				t.Fatal("wrong owned query observations")
			}
		})
		for _, test := range []struct {
			name string
			data []byte
		}{
			{"missing_length", nil},
			{"zero_length", []byte{0, 0}},
			{"oversize", []byte{0x10, 0x01}},
			{"truncated_length", []byte{0}},
			{"truncated_query", append([]byte{0, 40}, packet[:5]...)},
			{"malformed_query", logicalDNSFrame([]byte{0})},
			{"missing_question", logicalDNSFrame(make([]byte, 12))},
		} {
			t.Run(test.name, func(t *testing.T) {
				stream := &logicalDNSMemoryIO{input: bytes.NewReader(test.data)}
				if err := logicalDNSExchange(stream, new(fixture)); err == nil {
					t.Fatal("invalid query succeeded")
				}
				if stream.output.Len() != 0 {
					t.Fatal("invalid query wrote answer bytes")
				}
			})
		}
	})
}
