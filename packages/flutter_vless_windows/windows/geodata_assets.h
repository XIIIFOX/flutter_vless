#pragma once
#include "xray_config.h"
#include <fstream>
#include <random>
#include <stdexcept>
#include <cstdio>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

namespace flutter_vless::geodata_assets {
using Json = xray_config::Json;
namespace fs = std::filesystem;
inline const Json* Field(const Json& value, const char* key) {
  if (!value.is_object()) throw std::invalid_argument("Invalid GeoDAT configuration");
  const Json* result = nullptr;
  for (auto it = value.begin(); it != value.end(); ++it) if (xray_config::Fold(it.key()) == key) {
    if (result) throw std::invalid_argument("Conflicting GeoDAT fields");
    result = &it.value();
  }
  return result && !result->is_null() ? result : nullptr;
}
inline bool HasSchedule(const Json& config) {
  auto section = Field(config, "geodata");
  if (!section) return false;
  auto cron = Field(*section, "cron");
  if (!cron) return false;
  if (!cron->is_string()) throw std::invalid_argument("Invalid GeoDAT schedule");
  return !cron->get_ref<const std::string&>().empty();
}
inline bool Probe(const fs::path& parent) {
  std::random_device random;
  std::string nonce;
  for (unsigned i=0; i<8; ++i) nonce += std::to_string(random());
  auto first=parent/(".flutter-vless-geodat-check-"+nonce+"-one.tmp");
  auto second=parent/(".flutter-vless-geodat-check-"+nonce+"-two.tmp");
  bool one=false, two=false, replaced=false;
#ifdef _WIN32
  auto create=[](const fs::path& path) {
    HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if (file==INVALID_HANDLE_VALUE) return false;
    return CloseHandle(file)!=0;
  };
  one=create(first);
  if (one) two=create(second);
  if (one && two) replaced=MoveFileExW(first.c_str(),second.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
#else
  auto create=[](const fs::path& path) {
    int file=open(path.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);
    if (file<0) return false;
    return close(file)==0;
  };
  one=create(first);
  if (one) two=create(second);
  if (one && two) replaced=std::rename(first.c_str(),second.c_str())==0;
#endif
  std::error_code error;
  bool clean=true;
  if (one && !replaced) { fs::remove(first,error); clean=clean && !error; }
  if (two) { error.clear(); fs::remove(second,error); clean=clean && !error; }
  return replaced && clean;
}
inline bool ValidateWritable(const Json& config, const fs::path& directory) try {
  if (!HasSchedule(config)) return true;
  auto section=Field(config,"geodata");
  auto assets=Field(*section,"assets");
  if (!assets) return true;
  if (!assets->is_array() || assets->size()>100) return false;
  if (assets->empty()) return true;
  if (!directory.is_absolute() || !fs::is_directory(directory)) return false;
  std::set<fs::path> parents;
  for (const auto& asset:*assets) {
    auto field=Field(asset,"file");
    if (!field || !field->is_string()) return false;
    auto name=field->get<std::string>();
    if (name.empty() || name[0]=='/' || name.find('\0')!=std::string::npos || name.size()<4 || xray_config::Fold(name.substr(name.size()-4))!=".dat") return false;
#ifdef _WIN32
    if (name.find('\\')!=std::string::npos || name.find(':')!=std::string::npos) return false;
#endif
    size_t begin=0;
    do { auto end=name.find('/',begin); auto part=name.substr(begin,end==std::string::npos?end:end-begin);
      if (part.empty() || part=="." || part=="..") return false;
      if (end==std::string::npos) break;
      begin=end+1;
    } while (true);
    auto file=directory/fs::u8path(name);
    if (!fs::is_regular_file(file)) return false;
#ifdef _WIN32
    const auto flags=GetFileAttributesW(file.c_str());
    if (flags==INVALID_FILE_ATTRIBUTES || (flags&FILE_ATTRIBUTE_READONLY)) return false;
#endif
    parents.insert(file.parent_path());
  }
  for (const auto& parent:parents) if (!Probe(parent)) return false;
  return true;
} catch (...) { return false; }
} // namespace flutter_vless::geodata_assets
