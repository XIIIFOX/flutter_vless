// Prepared inert CI tests. No sockets, processes, Windows APIs or network calls.
#include "ipv6_tcp_challenge_peer.h"
#include <cassert>
#include <iostream>
#include <string>

namespace {
using flutter_vless::wireproof::Bytes;
using flutter_vless::wireproof::Error;
using flutter_vless::wireproof::Peer;
using flutter_vless::wireproof::Phase;
using flutter_vless::wireproof::Result;
const std::string nonce = "0123456789abcdef0123456789abcdef";
Bytes Text(const std::string& value) { return Bytes(value.begin(), value.end()); }
uint16_t Get16(const Bytes& p, size_t i) { return static_cast<uint16_t>(p[i] * 256u + p[i + 1]); }
uint32_t Get32(const Bytes& p, size_t i) {
  return static_cast<uint32_t>(p[i]) * 0x1000000u + static_cast<uint32_t>(p[i + 1]) * 0x10000u
      + static_cast<uint32_t>(p[i + 2]) * 0x100u + p[i + 3];
}
void Put16(Bytes& p, size_t i, uint16_t value) { p[i] = static_cast<uint8_t>(value / 256); p[i + 1] = static_cast<uint8_t>(value); }
void Put32(Bytes& p, size_t i, uint32_t value) {
  for (size_t j = 0; j < 4; ++j) p[i + j] = static_cast<uint8_t>(value >> (24 - 8 * j));
}
// Independent reference accumulation over an explicitly materialized pseudoheader.
uint16_t ReferenceChecksum(const Bytes& packet) {
  assert(packet.size() >= 60);
  Bytes bytes(packet.begin() + 8, packet.begin() + 40);
  const auto n = static_cast<uint32_t>(packet.size() - 40);
  bytes.insert(bytes.end(), {static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
      static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n), 0, 0, 0, 6});
  bytes.insert(bytes.end(), packet.begin() + 40, packet.end());
  if (bytes.size() % 2) bytes.push_back(0);
  uint64_t sum = 0;
  for (size_t i = 0; i < bytes.size(); i += 2) sum += bytes[i] * 256u + bytes[i + 1];
  while (sum > 65535) sum = (sum % 65536) + (sum / 65536);
  return static_cast<uint16_t>(65535 - sum);
}
void FixChecksum(Bytes& packet) { Put16(packet, 56, 0); Put16(packet, 56, ReferenceChecksum(packet)); }
Bytes ClientPacket(uint32_t sequence, uint32_t acknowledgement, uint8_t flags,
    const Bytes& payload = {}, const Bytes& options = {}, uint16_t source_port = 49152) {
  assert(options.size() <= 40 && options.size() % 4 == 0);
  Bytes packet(60 + options.size() + payload.size(), 0);
  packet[0] = 0x60; packet[6] = 6; packet[7] = 64;
  const Bytes source{0xfd,0,0,0x85,0,2,0,0,0,0,0,0,0,0,0,1};
  const Bytes target{0xfd,0,0,0x85,0,2,0,0,0,0,0,0,0,0,0,2};
  std::copy(source.begin(), source.end(), packet.begin() + 8);
  std::copy(target.begin(), target.end(), packet.begin() + 24);
  Put16(packet, 4, static_cast<uint16_t>(packet.size() - 40));
  Put16(packet, 40, source_port); Put16(packet, 42, 18443);
  Put32(packet, 44, sequence); Put32(packet, 48, acknowledgement);
  packet[52] = static_cast<uint8_t>((5 + options.size() / 4) << 4); packet[53] = flags;
  Put16(packet, 54, 8192);
  std::copy(options.begin(), options.end(), packet.begin() + 60);
  std::copy(payload.begin(), payload.end(), packet.begin() + 60 + options.size());
  FixChecksum(packet); return packet;
}
void RequireReply(const Result& result, uint32_t sequence, uint32_t acknowledgement,
    uint8_t flags, const Bytes& payload) {
  assert(result.accepted && !result.packet.empty() && result.error == Error::none);
  assert(result.packet.size() == 60 + payload.size());
  assert(Get16(result.packet, 4) == result.packet.size() - 40);
  assert(Get16(result.packet, 40) == 18443 && Get16(result.packet, 42) == 49152);
  assert(Get32(result.packet, 44) == sequence && Get32(result.packet, 48) == acknowledgement);
  assert(result.packet[53] == flags && ReferenceChecksum(result.packet) == 0);
  assert(Bytes(result.packet.begin() + 60, result.packet.end()) == payload);
  assert(std::equal(result.packet.begin() + 8, result.packet.begin() + 24,
      flutter_vless::wireproof::server_address.begin()));
}
struct Conversation {
  Peer peer{nonce};
  uint32_t sequence = 0xfffffff0u, acknowledgement = 0;
  uint64_t now = 100;
  Bytes last_client;
  Result Send(uint8_t flags, const Bytes& payload = {}) {
    last_client = ClientPacket(sequence, acknowledgement, flags, payload);
    auto result = peer.Receive(last_client.data(), last_client.size(), now++);
    sequence += static_cast<uint32_t>(payload.size()) + ((flags & 1) ? 1u : 0u);
    if (!result.packet.empty()) acknowledgement = Get32(result.packet, 44)
        + static_cast<uint32_t>(result.packet.size() - 60)
        + ((result.packet[53] & 3) ? 1u : 0u);
    return result;
  }
  void Handshake() {
    const auto syn = ClientPacket(sequence, 0, 2, {}, {2,4,5,0xa0,1,3,3,8,1,1,4,2});
    auto result = peer.Receive(syn.data(), syn.size(), now++);
    ++sequence;
    acknowledgement = Get32(result.packet, 44) + 1;
    RequireReply(result, acknowledgement - 1, sequence, 0x12, {});
    assert(Send(0x10).accepted);
    assert(peer.Inspect().phase == Phase::greeting);
  }
  void Greeting(bool split = false) {
    if (split) {
      auto partial = Send(0x18, {5});
      RequireReply(partial, acknowledgement, sequence, 0x10, {});
      auto result = Send(0x18, {1,2});
      RequireReply(result, acknowledgement - 2, sequence, 0x18, {5,2});
    } else {
      auto result = Send(0x18, {5,1,2});
      RequireReply(result, acknowledgement - 2, sequence, 0x18, {5,2});
    }
  }
  void Authenticate() {
    auto result = Send(0x18, {1,10,'s','c','o','p','e','-','u','s','e','r',14,
        's','c','o','p','e','-','p','a','s','s','w','o','r','d'});
    RequireReply(result, acknowledgement - 2, sequence, 0x18, {1,0});
  }
  void Connect() {
    auto result = Send(0x18, {5,1,0,1,198,18,0,77,0x46,0xa0});
    RequireReply(result, acknowledgement - 10, sequence, 0x18, {5,0,0,1,198,18,0,77,0x46,0xa0});
  }
  void Ready() { Handshake(); Greeting(); Authenticate(); Connect(); }
};
void HappyPath() {
  Conversation c; c.Handshake(); c.Greeting(true); c.Authenticate(); c.Connect();
  const auto payload = Text("numeric-ipv6-" + nonce + "\n");
  auto partial = c.Send(0x18, Bytes(payload.begin(), payload.begin() + 9));
  RequireReply(partial, c.acknowledgement, c.sequence, 0x10, {});
  auto reply = c.Send(0x18, Bytes(payload.begin() + 9, payload.end()));
  const auto expected = Text("accepted-numeric-ipv6-" + nonce + "\n");
  RequireReply(reply, c.acknowledgement - static_cast<uint32_t>(expected.size()) - 1, c.sequence, 0x19, expected);
  assert(!reply.complete && c.peer.Inspect().challenge_count == 1);
  assert(c.Send(0x10).accepted);
  auto closed = c.Send(0x11);
  RequireReply(closed, c.acknowledgement, c.sequence, 0x10, {});
  const auto snapshot = c.peer.Inspect();
  assert(closed.complete && snapshot.phase == Phase::closed && snapshot.error == Error::none);
  assert(snapshot.syn_count == 1 && snapshot.authentication_count == 1
      && snapshot.connect_count == 1 && snapshot.challenge_count == 1);
  auto fin_retry = c.peer.Receive(c.last_client.data(), c.last_client.size(), c.now++);
  assert(fin_retry.complete && fin_retry.packet == closed.packet);
  assert(c.peer.Poll(c.now + 20000).complete);
}
void HeaderRefusals() {
  const auto syn = ClientPacket(17, 0, 2);
  for (int variant = 0; variant < 17; ++variant) {
    Peer peer(nonce); auto packet = syn;
    switch (variant) {
      case 0: packet.resize(39); break;
      case 1: packet[0] = 0x40; break;
      case 2: packet[6] = 44; break; // fragmentation explicitly unsupported
      case 3: packet[6] = 0; break;  // extension chain explicitly unsupported
      case 4: packet[7] = 0; break;
      case 5: packet[5] += 1; break;
      case 6: packet[23] = 3; FixChecksum(packet); break;
      case 7: packet[39] = 1; FixChecksum(packet); break;
      case 8: Put16(packet, 42, 18444); FixChecksum(packet); break;
      case 9: Put16(packet, 40, 0); FixChecksum(packet); break;
      case 10: packet[52] = 0x40; FixChecksum(packet); break;
      case 11: packet[52] = 0xf0; FixChecksum(packet); break;
      case 12: packet[52] |= 1; FixChecksum(packet); break;
      case 13: packet[53] |= 0x20; FixChecksum(packet); break;
      case 14: Put16(packet, 58, 1); FixChecksum(packet); break;
      case 15: packet[56] ^= 1; break;
      case 16: packet.push_back(0); break;
    }
    const auto result = peer.Receive(packet.data(), packet.size(), 100);
    assert(!result.accepted && result.packet.empty() && !result.complete);
    assert(peer.Inspect().phase == Phase::listen && peer.Inspect().syn_count == 0);
  }
  for (const Bytes& options : {Bytes{2,1,0,0}, Bytes{2,5,0,0}, Bytes{0,1,0,0}}) {
    Peer peer(nonce); auto packet = ClientPacket(17, 0, 2, {}, options);
    assert(!peer.Receive(packet.data(), packet.size(), 100).accepted);
  }
}
void TupleAndAckDoNotRetireOutstanding() {
  Conversation c; c.Handshake(); c.Greeting();
  const auto state = c.peer.Inspect();
  auto wrong_port = ClientPacket(c.sequence, c.acknowledgement, 0x10, {}, {}, 49153);
  assert(!c.peer.Receive(wrong_port.data(), wrong_port.size(), c.now++).accepted);
  auto future = ClientPacket(c.sequence + 100, c.acknowledgement, 0x10);
  assert(!c.peer.Receive(future.data(), future.size(), c.now++).accepted);
  auto wrong_ack = ClientPacket(c.sequence, c.acknowledgement + 1, 0x10);
  assert(!c.peer.Receive(wrong_ack.data(), wrong_ack.size(), c.now++).accepted);
  const auto retry = c.peer.Poll(c.now + 300);
  assert(retry.accepted && !retry.packet.empty() && c.peer.Inspect().phase == state.phase);
  assert(c.peer.Inspect().authentication_count == 0);
}
void RetransmittedInputIsIdempotent() {
  Conversation c;
  auto syn = ClientPacket(c.sequence, 0, 2);
  auto first = c.peer.Receive(syn.data(), syn.size(), c.now++);
  auto duplicate = c.peer.Receive(syn.data(), syn.size(), c.now++);
  assert(first.packet == duplicate.packet && c.peer.Inspect().syn_count == 1);
  ++c.sequence; c.acknowledgement = Get32(first.packet, 44) + 1;
  c.Send(0x10); c.Greeting();
  const auto greeting = c.last_client;
  auto repeated = c.peer.Receive(greeting.data(), greeting.size(), c.now++);
  assert(repeated.accepted && repeated.packet[53] == 0x18);
  assert(c.peer.Inspect().phase == Phase::authentication && c.peer.Inspect().authentication_count == 0);
  c.Authenticate(); c.Connect();
  auto response = c.Send(0x18, Text("numeric-ipv6-" + nonce + "\n"));
  auto replay = c.peer.Receive(c.last_client.data(), c.last_client.size(), c.now++);
  assert(response.packet == replay.packet && c.peer.Inspect().challenge_count == 1);
  c.Send(0x10); auto fin = c.Send(0x11); assert(fin.complete);
  const auto forbidden = c.peer.Receive(syn.data(), syn.size(), c.now++);
  assert(!forbidden.accepted && forbidden.packet.empty() && c.peer.Inspect().syn_count == 1);
}
void BadProtocolFailsWithoutSuccess() {
  for (int variant = 0; variant < 12; ++variant) {
    Conversation c; c.Handshake();
    Bytes bytes{5,1,2};
    if (variant == 0) bytes = {5,1,0};
    else if (variant == 1) bytes = {5,2,2,0};
    else {
      c.Greeting(); bytes = {1,10,'s','c','o','p','e','-','u','s','e','r',14,
          's','c','o','p','e','-','p','a','s','s','w','o','r','d'};
      if (variant == 2) bytes.back() = 'X';
      else if (variant == 3) bytes[1] = 9;
      else {
        c.Authenticate(); bytes = {5,1,0,1,198,18,0,77,0x46,0xa0};
        if (variant == 4) bytes[1] = 3; // UDP association
        else if (variant == 5) bytes[2] = 1;
        else if (variant == 6) bytes[3] = 3; // domain differs from admitted IPv4 target
        else if (variant == 7) bytes[7] = 78;
        else if (variant == 8) bytes[9] += 1;
        else {
          c.Connect(); bytes = Text("numeric-ipv6-" + nonce + "\n");
          if (variant == 9) bytes[15] = 'f'; // wrong nonce
          else if (variant == 10) bytes.push_back('X');
          else bytes = Text("foreign-marker\n");
        }
      }
    }
    const auto result = c.Send(0x18, bytes);
    assert(!result.complete && result.packet.empty() && result.error == Error::protocol);
    assert(c.peer.Inspect().phase == Phase::failed && c.peer.Inspect().challenge_count == 0);
  }
}
void BoundsResetAndClose() {
  assert(Peer("UPPER").Inspect().error == Error::bad_nonce);
  Conversation timeout; timeout.Handshake();
  assert(timeout.peer.Poll(10100).error == Error::deadline);
  Conversation rollback; rollback.Handshake();
  assert(rollback.peer.Poll(1).error == Error::protocol);
  Conversation retries; retries.Handshake(); retries.Greeting();
  uint64_t tick = retries.now;
  for (int i = 0; i < 4; ++i) { tick += 300; assert(retries.peer.Poll(tick).accepted); }
  assert(retries.peer.Poll(tick + 300).error == Error::retransmission_limit);
  Conversation reset; reset.Handshake();
  auto bad_rst = ClientPacket(reset.sequence + 1, reset.acknowledgement, 0x14);
  assert(!reset.peer.Receive(bad_rst.data(), bad_rst.size(), reset.now++).accepted);
  assert(reset.peer.Inspect().error == Error::none);
  assert(reset.Send(0x14).error == Error::reset);
  Conversation early_fin; early_fin.Handshake();
  assert(early_fin.Send(0x11).error == Error::protocol);
  Conversation zero_window; zero_window.Handshake();
  auto packet = ClientPacket(zero_window.sequence, zero_window.acknowledgement, 0x18, {5,1,2});
  Put16(packet, 54, 1); FixChecksum(packet);
  assert(zero_window.peer.Receive(packet.data(), packet.size(), zero_window.now++).error == Error::resource_limit);
  Conversation flooded; flooded.Handshake();
  auto empty = ClientPacket(flooded.sequence, flooded.acknowledgement, 0x10);
  for (int i = 0; i < 255; ++i) flooded.peer.Receive(empty.data(), empty.size(), flooded.now++);
  assert(flooded.peer.Inspect().error == Error::resource_limit);
}
}  // namespace
int main() {
  HappyPath(); HeaderRefusals(); TupleAndAckDoNotRetireOutstanding();
  RetransmittedInputIsIdempotent(); BadProtocolFailsWithoutSuccess(); BoundsResetAndClose();
  std::cout << "WINDOWS_NUMERIC_IPV6_PEER_CODEC_PASS=1\n";
}
