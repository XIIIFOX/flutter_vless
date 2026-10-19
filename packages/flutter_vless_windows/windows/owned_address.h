#ifndef FLUTTER_VLESS_OWNED_ADDRESS_H_
#define FLUTTER_VLESS_OWNED_ADDRESS_H_
#include <optional>

namespace flutter_vless::native {
// The worker keeps the exact created row until deletion (or verified absence)
// succeeds. The callback translates platform status; no OS APIs run here.
template <typename Row, typename Remove>
bool RetireOwnedAddress(std::optional<Row>& owned, Remove remove) {
  if (!owned) return true;
  if (!remove(*owned)) return false;
  owned.reset();
  return true;
}
}  // namespace flutter_vless::native
#endif
