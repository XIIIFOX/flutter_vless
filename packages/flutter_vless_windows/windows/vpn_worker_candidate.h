#pragma once
#include "xray_config.h"
#include <functional>
#include <memory>
#include <utility>
#include <type_traits>

namespace flutter_vless::native {
// One finalized worker attempt. It retains the checked file through launch
// and its probe through child shutdown; an unaccepted candidate cleans both.
template <class Probe>
class VpnWorkerCandidate {
 public:
  using RemoveConfig = std::function<void(std::filesystem::path&)>;
  ~VpnWorkerCandidate() { RemoveFile(); }
  VpnWorkerCandidate(const VpnWorkerCandidate&) = delete;
  VpnWorkerCandidate& operator=(const VpnWorkerCandidate&) = delete;

  template <class MakeProbe, class Check>
  static std::unique_ptr<VpnWorkerCandidate> Prepare(const std::string& base,
      const std::string& underlay, uint64_t identity, uint16_t managed_port,
      MakeProbe make_probe, Check check, RemoveConfig remove, preparation::Report report = {}) {
    auto config = xray_config::Parse(base);
    if (underlay.empty() || !config.is_object() || !config.contains("outbounds")
        || !config["outbounds"].is_array()) return nullptr;
    for (auto& outbound : config["outbounds"]) Rebind(outbound, underlay);
    auto candidate = std::unique_ptr<VpnWorkerCandidate>(new VpnWorkerCandidate(
        make_probe(), underlay, identity, std::move(remove)));
    candidate->report_ = std::move(report);
    if (!candidate->probe_ || !candidate->probe_->Start()
        || !candidate->probe_->Configure(config, managed_port, &candidate->probe_guards_)) return nullptr;
    candidate->bytes_ = config.dump();
    // Check must write these exact bytes and test this exact file. Neither
    // serialization nor probe configuration is repeated before its launch.
    bool accepted;
    if constexpr (std::is_invocable_r_v<bool, Check, const std::string&, std::filesystem::path&,
        std::string&, std::filesystem::path&, const std::vector<int64_t>&>) {
      accepted = check(candidate->bytes_, candidate->path_, candidate->metadata_, candidate->metadata_path_, candidate->probe_guards_);
    } else accepted = check(candidate->bytes_, candidate->path_);
    if (!accepted || candidate->path_.empty() || candidate->metadata_.empty() != candidate->metadata_path_.empty()) return nullptr;
    candidate->report_.CheckedFinal();
    return candidate;
  }

  const preparation::Report& PreparationReport() const { return report_; }
  const std::string& Bytes() const { return bytes_; }
  const std::filesystem::path& Path() const { return path_; }
  const std::string& Underlay() const { return underlay_; }
  uint64_t Identity() const { return identity_; }
  const Probe& PacketProbe() const { return *probe_; }
  bool Routing() const { return !metadata_.empty(); }
  const std::string& Metadata() const { return metadata_; }
  const std::filesystem::path& MetadataPath() const { return metadata_path_; }
  void RemoveFile() {
    if (!path_.empty()) remove_(path_);
    if (!metadata_path_.empty()) remove_(metadata_path_);
  }

 private:
  VpnWorkerCandidate(std::unique_ptr<Probe> probe, std::string underlay,
      uint64_t identity, RemoveConfig remove)
      : probe_(std::move(probe)), underlay_(std::move(underlay)),
        identity_(identity), remove_(std::move(remove)) {}
  static void Rebind(xray_config::Json& node, const std::string& interface_name) {
    if (!node.is_object()) return;
    if (node.contains("sockopt") && node["sockopt"].is_object()) node["sockopt"]["interface"] = interface_name;
    for (auto it = node.begin(); it != node.end(); ++it) {
      if (it.key() == "streamSettings" || it.key() == "xhttpSettings" || it.key() == "splithttpSettings"
          || it.key() == "extra" || it.key() == "downloadSettings") Rebind(it.value(), interface_name);
    }
  }
  std::unique_ptr<Probe> probe_;
  std::string underlay_;
  uint64_t identity_;
  RemoveConfig remove_;
  preparation::Report report_;
  std::string bytes_;
  std::filesystem::path path_;
  std::string metadata_;
  std::filesystem::path metadata_path_;
  std::vector<int64_t> probe_guards_;
};
}  // namespace flutter_vless::native
