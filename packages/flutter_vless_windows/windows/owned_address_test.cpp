#include "owned_address.h"
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
struct Address { unsigned interface_; unsigned suffix; };
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
}

int main() try {
  using flutter_vless::native::RetireOwnedAddress;
  std::optional<Address> owned = Address{42, 2};
  std::vector<unsigned> attempts;
  auto remove = [&](const Address& address) {
    Require(address.suffix == 2, "retry changed the exact owned address");
    attempts.push_back(address.interface_);
    return attempts.size() == 3;
  };
  Require(!RetireOwnedAddress(owned, remove), "failed delete reported success");
  Require(owned && owned->interface_ == 42, "failed delete lost owned address and allowed replacement");
  Require(!RetireOwnedAddress(owned, remove) && owned, "repeated failure lost cleanup ownership");
  Require(RetireOwnedAddress(owned, remove) && !owned, "successful retry retained stale ownership");
  Require(attempts == std::vector<unsigned>({42, 42, 42}), "retry deleted a replacement or foreign interface");
  Require(RetireOwnedAddress(owned, remove) && attempts.size() == 3, "empty owner invoked deletion again");
  owned = Address{77, 3};
  try {
    RetireOwnedAddress(owned, [](const Address&) -> bool { throw std::runtime_error("fixed test failure"); });
    throw std::logic_error("unexpected delete failure was masked");
  } catch (const std::runtime_error&) {
    Require(owned && owned->interface_ == 77 && owned->suffix == 3, "unexpected error discarded cleanup ownership");
  }
  Require(RetireOwnedAddress(owned, [](const Address&) { return true; }) && !owned,
      "verified absence did not release ownership");
  std::cout << "PASS owned address failed-delete retention, exact retry, verified absence and error ownership\n";
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
