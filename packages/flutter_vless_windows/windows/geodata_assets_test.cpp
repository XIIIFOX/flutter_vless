#include "geodata_assets.h"
#include <iostream>

static void Require(bool value) { if (!value) throw std::runtime_error("GeoDAT asset regression"); }

int main() {
  namespace fs=std::filesystem;
  using namespace flutter_vless;
  const auto root=fs::temp_directory_path()/("flutter-vless-geodat-"+std::to_string(std::random_device{}()));
  fs::create_directories(root/"nested");
  struct Cleanup {fs::path root;~Cleanup(){std::error_code e;fs::remove_all(root,e);}} cleanup{root};
  std::ofstream(root/"nested/custom.DAT")<<"caller-full-dataset";
  auto config=xray_config::Parse(R"({"geodata":{"cron":"@daily","assets":[{"file":"nested/custom.DAT","url":"https://example.test/full.dat"}]}})");
  Require(geodata_assets::HasSchedule(config));
  Require(geodata_assets::ValidateWritable(config,root));
  std::ifstream input(root/"nested/custom.DAT");std::string bytes;std::getline(input,bytes);Require(bytes=="caller-full-dataset");input.close();
  Require(std::distance(fs::directory_iterator(root/"nested"),fs::directory_iterator{})==1);
  Require(!fs::exists(root/"geoip.dat")&&!fs::exists(root/"geosite.dat"));
  for (const auto* source:{"{}",R"({"geodata":{"cron":""}})",R"({"geodata":{"cron":"@daily"}})"})
    Require(geodata_assets::ValidateWritable(xray_config::Parse(source),{}));
  for (const auto* file:{"../escape.dat","/absolute.dat","nested//custom.DAT","missing.dat","script.lua"}) {
    auto invalid=config;invalid["geodata"]["assets"][0]["file"]=file;
    Require(!geodata_assets::ValidateWritable(invalid,root));
  }
#ifdef _WIN32
  Require(SetFileAttributesW((root/L"nested/custom.DAT").c_str(),FILE_ATTRIBUTE_READONLY));
  Require(!geodata_assets::ValidateWritable(config,root));
  Require(SetFileAttributesW((root/L"nested/custom.DAT").c_str(),FILE_ATTRIBUTE_NORMAL));
#else
  fs::permissions(root/"nested",fs::perms::owner_read|fs::perms::owner_exec);
  if (geteuid()!=0) Require(!geodata_assets::ValidateWritable(config,root));
  fs::permissions(root/"nested",fs::perms::owner_all);
#endif
  auto alias=xray_config::Parse(R"({"GEODATA":{"Cron":"@daily","Aſſets":[]}})");
  Require(geodata_assets::HasSchedule(alias)&&geodata_assets::ValidateWritable(alias,{}));
  std::cout<<"PASS GeoDAT real filesystem root/preservation/atomic probe/cleanup\n";
}
