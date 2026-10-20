#pragma once
// CI fixture only. One synthetic IPv6 TCP/SOCKS exchange; no sockets or OS calls.
// Receive owns no input bytes. The caller injects the returned packet into the
// same owned Wintun session. Remote ::2 must NEVER be assigned to the host.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace flutter_vless::wireproof {
using Bytes = std::vector<uint8_t>;
using Address = std::array<uint8_t, 16>;
inline constexpr Address client_address{0xfd,0,0,0x85,0,2,0,0,0,0,0,0,0,0,0,1};
inline constexpr Address server_address{0xfd,0,0,0x85,0,2,0,0,0,0,0,0,0,0,0,2};
inline constexpr uint16_t server_port = 18443;
enum class Error { none, bad_nonce, deadline, retransmission_limit, protocol, reset, resource_limit };
enum class Phase { listen, syn_received, greeting, authentication, connect, challenge, closing, closed, failed };
struct Result {
  Bytes packet;
  bool accepted = false;
  bool complete = false;
  Error error = Error::none;
};
struct Snapshot {
  Phase phase = Phase::listen;
  Error error = Error::none;
  unsigned accepted_packets = 0, dropped_packets = 0, retransmissions = 0;
  unsigned syn_count = 0, authentication_count = 0, connect_count = 0, challenge_count = 0;
  uint16_t client_port = 0;
};

namespace detail {
inline uint16_t Read16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
inline uint32_t Read32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
      | (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
inline void Put16(Bytes& p, size_t i, uint16_t v) {
  p[i] = static_cast<uint8_t>(v >> 8); p[i + 1] = static_cast<uint8_t>(v);
}
inline void Put32(Bytes& p, size_t i, uint32_t v) {
  p[i] = static_cast<uint8_t>(v >> 24); p[i + 1] = static_cast<uint8_t>(v >> 16);
  p[i + 2] = static_cast<uint8_t>(v >> 8); p[i + 3] = static_cast<uint8_t>(v);
}
inline uint32_t Sum(const uint8_t* p, size_t n) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < n; i += 2) sum += Read16(p + i);
  if (n & 1) sum += static_cast<uint32_t>(p[n - 1]) << 8;
  return sum;
}
inline uint16_t Checksum(const uint8_t* packet, size_t n) {
  // IPv6 pseudo-header: source, destination, 32-bit TCP length, next-header=6.
  uint32_t sum = Sum(packet + 8, 32) + static_cast<uint32_t>(n - 40) + 6;
  sum += Sum(packet + 40, n - 40);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}
inline bool Options(const uint8_t* p, size_t n) {
  size_t i = 0;
  while (i < n) {
    const auto kind = p[i];
    if (kind == 0) return std::all_of(p + i, p + n, [](uint8_t v) { return v == 0; });
    if (kind == 1) { ++i; continue; }
    if (i + 1 >= n || p[i + 1] < 2 || p[i + 1] > n - i) return false;
    i += p[i + 1];
  }
  return true;
}
struct Segment {
  uint16_t source = 0, window = 0;
  uint32_t sequence = 0, acknowledgement = 0;
  uint8_t flags = 0;
  Bytes payload;
};
inline bool Parse(const uint8_t* p, size_t n, Segment& s) {
  if (!p || n < 60 || n > 1200 || (p[0] >> 4) != 6 || p[6] != 6 || p[7] == 0
      || Read16(p + 4) != n - 40
      || !std::equal(client_address.begin(), client_address.end(), p + 8)
      || !std::equal(server_address.begin(), server_address.end(), p + 24)
      || Read16(p + 42) != server_port || !Read16(p + 40)) return false;
  const size_t header = static_cast<size_t>(p[52] >> 4) * 4;
  if (header < 20 || header > 60 || 40 + header > n || (p[52] & 15) != 0
      || (p[53] & 0x20) != 0 || Read16(p + 58) != 0
      || !Options(p + 60, header - 20) || Checksum(p, n) != 0) return false;
  s.source = Read16(p + 40); s.window = Read16(p + 54);
  s.sequence = Read32(p + 44); s.acknowledgement = Read32(p + 48); s.flags = p[53];
  s.payload.assign(p + 40 + header, p + n);
  return s.payload.size() <= 512;
}
}  // namespace detail

class Peer {
 public:
  explicit Peer(std::string nonce) : nonce_(std::move(nonce)) {
    if (nonce_.size() != 32 || nonce_.find_first_not_of("0123456789abcdef") != std::string::npos) {
      Fail(Error::bad_nonce); return;
    }
    uint32_t seed = 0;
    for (size_t i = 0; i < 8; ++i) {
      const auto c = nonce_[i];
      seed = (seed << 4) | static_cast<uint32_t>(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    server_initial_ = seed ^ 0x85020000u;
  }

  Result Receive(const uint8_t* packet, size_t size, uint64_t now_ms) {
    if (!Clock(now_ms)) return Finish();
    detail::Segment s;
    if (!detail::Parse(packet, size, s)) { ++snapshot_.dropped_packets; return Finish(); }
    if (++matching_packets_ > 256) { Fail(Error::resource_limit); return Finish(); }
    if (snapshot_.phase == Phase::failed) return Finish();
    if (snapshot_.phase == Phase::listen) {
      if ((s.flags & 0x3f) != 0x02 || !s.payload.empty() || s.acknowledgement != 0 || !s.window) return Drop();
      snapshot_.client_port = s.source; snapshot_.syn_count = 1;
      client_initial_ = s.sequence; client_next_ = s.sequence + 1;
      server_next_ = server_initial_ + 1; started_ms_ = now_ms; armed_ = true;
      snapshot_.phase = Phase::syn_received;
      return Emit(0x12, {}, server_initial_, true, now_ms);
    }
    if (s.source != snapshot_.client_port) return Drop();
    if ((s.flags & 0x3f) == 0x02) {
      if (snapshot_.phase == Phase::syn_received && s.sequence == client_initial_
          && s.acknowledgement == 0 && s.payload.empty()) return Retransmit(now_ms);
      return Drop();
    }
    if ((s.flags & 0xc0) != 0 || (s.flags & 0x02) != 0 || (s.flags & 0x10) == 0) return Drop();
    if (s.flags & 0x04) {
      if (s.sequence == client_next_ && s.acknowledgement == server_next_) Fail(Error::reset);
      return Drop();
    }
    if ((s.flags & static_cast<uint8_t>(~0x19)) != 0) return Drop();
    if (snapshot_.phase == Phase::closed) {
      // Only the final FIN retransmission is answered; no fresh connection or replay.
      if (s.flags == 0x11 && s.payload.empty() && s.sequence + 1 == client_next_
          && s.acknowledgement == server_next_) return Emit(0x10, {}, server_next_, false, now_ms);
      return Drop();
    }
    // An ACK with an unrelated sequence must not retire our retransmission.
    if (s.sequence != client_next_ && !Duplicate(s)) return Drop();
    if (s.acknowledgement == server_next_) {
      outstanding_.clear(); retries_ = 0;
    } else if (!outstanding_.empty() && s.acknowledgement == outstanding_sequence_) {
      // The client has not acknowledged our last response. It may retransmit
      // already consumed bytes, but cannot advance the application protocol.
      if (Duplicate(s)) return Retransmit(now_ms);
      return Drop();
    } else return Drop();
    if (snapshot_.phase == Phase::syn_received) {
      if (s.sequence != client_next_ || (s.flags & 1)) return Drop();
      snapshot_.phase = Phase::greeting; Expect(Bytes{5, 1, 2});
    }
    if (s.sequence != client_next_) {
      if (Duplicate(s)) return Emit(0x10, {}, server_next_, false, now_ms);
      return Drop();
    }
    if (s.flags & 1) {
      if (snapshot_.phase != Phase::closing || !s.payload.empty() || snapshot_.challenge_count != 1) {
        Fail(Error::protocol); return Finish();
      }
      ++client_next_; snapshot_.phase = Phase::closed;
      return Emit(0x10, {}, server_next_, false, now_ms);
    }
    if (s.payload.empty()) return Accept();
    if (snapshot_.phase == Phase::closing || s.payload.size() > expected_.size() - received_.size()
        || history_.size() + s.payload.size() > 512) { Fail(Error::protocol); return Finish(); }
    if (!std::equal(s.payload.begin(), s.payload.end(), expected_.begin() + received_.size())) {
      Fail(Error::protocol); return Finish();
    }
    history_.insert(history_.end(), s.payload.begin(), s.payload.end());
    received_.insert(received_.end(), s.payload.begin(), s.payload.end());
    client_next_ += static_cast<uint32_t>(s.payload.size());
    if (received_.size() != expected_.size()) return Emit(0x10, {}, server_next_, false, now_ms);
    Bytes reply;
    switch (snapshot_.phase) {
      case Phase::greeting:
        snapshot_.phase = Phase::authentication;
        Expect(Bytes{1, 10, 's','c','o','p','e','-','u','s','e','r', 14,
            's','c','o','p','e','-','p','a','s','s','w','o','r','d'});
        reply = {5, 2}; break;
      case Phase::authentication:
        ++snapshot_.authentication_count; snapshot_.phase = Phase::connect;
        Expect(Bytes{5, 1, 0, 1, 198, 18, 0, 77, 0x46, 0xa0});
        reply = {1, 0}; break;
      case Phase::connect:
        ++snapshot_.connect_count; snapshot_.phase = Phase::challenge;
        Expect(Text("numeric-ipv6-" + nonce_ + "\n"));
        reply = {5, 0, 0, 1, 198, 18, 0, 77, 0x46, 0xa0}; break;
      case Phase::challenge:
        ++snapshot_.challenge_count; snapshot_.phase = Phase::closing;
        reply = Text("accepted-numeric-ipv6-" + nonce_ + "\n"); break;
      default: Fail(Error::protocol); return Finish();
    }
    if (reply.size() > s.window) { Fail(Error::resource_limit); return Finish(); }
    const auto sequence = server_next_;
    const uint8_t flags = snapshot_.phase == Phase::closing ? 0x19 : 0x18;
    server_next_ += static_cast<uint32_t>(reply.size()) + ((flags & 1) ? 1u : 0u);
    return Emit(flags, reply, sequence, true, now_ms);
  }

  Result Poll(uint64_t now_ms) {
    if (!Clock(now_ms)) return Finish();
    if (!outstanding_.empty() && now_ms - last_sent_ms_ >= 300) return Retransmit(now_ms);
    return Finish();
  }
  Snapshot Inspect() const { return snapshot_; }

 private:
  static Bytes Text(const std::string& text) { return Bytes(text.begin(), text.end()); }
  void Expect(Bytes bytes) { expected_ = std::move(bytes); received_.clear(); }
  void Fail(Error why) { snapshot_.phase = Phase::failed; snapshot_.error = why; outstanding_.clear(); }
  bool Clock(uint64_t now) {
    if (clock_seen_ && now < last_now_ms_) { Fail(Error::protocol); return false; }
    clock_seen_ = true; last_now_ms_ = now;
    if (snapshot_.phase == Phase::failed) return false;
    if (armed_ && snapshot_.phase != Phase::closed && now - started_ms_ >= 10000) {
      Fail(Error::deadline); return false;
    }
    return true;
  }
  bool Duplicate(const detail::Segment& s) const {
    if ((s.flags & 1) || s.payload.empty()) return false;
    const uint32_t offset = s.sequence - (client_initial_ + 1);
    return offset <= history_.size() && s.payload.size() <= history_.size() - offset
        && std::equal(s.payload.begin(), s.payload.end(), history_.begin() + offset);
  }
  Result Finish(Bytes packet = {}, bool accepted = false) const {
    return {std::move(packet), accepted, snapshot_.phase == Phase::closed, snapshot_.error};
  }
  Result Accept() { ++snapshot_.accepted_packets; return Finish({}, true); }
  Result Drop() { ++snapshot_.dropped_packets; return Finish(); }
  Result Emit(uint8_t flags, const Bytes& payload, uint32_t sequence, bool retain, uint64_t now) {
    Bytes packet(60 + payload.size(), 0);
    packet[0] = 0x60; detail::Put16(packet, 4, static_cast<uint16_t>(20 + payload.size()));
    packet[6] = 6; packet[7] = 64;
    std::copy(server_address.begin(), server_address.end(), packet.begin() + 8);
    std::copy(client_address.begin(), client_address.end(), packet.begin() + 24);
    detail::Put16(packet, 40, server_port); detail::Put16(packet, 42, snapshot_.client_port);
    detail::Put32(packet, 44, sequence); detail::Put32(packet, 48, client_next_);
    packet[52] = 0x50; packet[53] = flags; detail::Put16(packet, 54, 1024);
    std::copy(payload.begin(), payload.end(), packet.begin() + 60);
    detail::Put16(packet, 56, detail::Checksum(packet.data(), packet.size()));
    if (retain) {
      outstanding_ = packet; outstanding_sequence_ = sequence; last_sent_ms_ = now; retries_ = 0;
    }
    ++snapshot_.accepted_packets; return Finish(std::move(packet), true);
  }
  Result Retransmit(uint64_t now) {
    if (outstanding_.empty()) return Drop();
    if (++retries_ > 4) { Fail(Error::retransmission_limit); return Finish(); }
    ++snapshot_.retransmissions; ++snapshot_.accepted_packets;
    last_sent_ms_ = now; return Finish(outstanding_, true);
  }
  Snapshot snapshot_;
  std::string nonce_;
  Bytes expected_, received_, history_, outstanding_;
  uint32_t client_initial_ = 0, client_next_ = 0, server_initial_ = 0, server_next_ = 0, outstanding_sequence_ = 0;
  uint64_t started_ms_ = 0, last_now_ms_ = 0, last_sent_ms_ = 0;
  unsigned retries_ = 0, matching_packets_ = 0;
  bool armed_ = false, clock_seen_ = false;
};
}  // namespace flutter_vless::wireproof
