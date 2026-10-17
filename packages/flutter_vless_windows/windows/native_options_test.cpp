#include "native_options.h"
#include <cassert>
#include <iostream>
using flutter_vless::NativeOptions;
using Json = NativeOptions::Json;
template<class Body> void Reject(Body body) { bool rejected=false; try { body(); } catch(const std::exception&) { rejected=true; } assert(rejected); }
int main() {
  const NativeOptions defaults;
  assert(!defaults.quick_enabled && defaults.reconnect_enabled && defaults.kill_switch=="required" && defaults.always_on=="system");
  const auto options = NativeOptions::Parse(Json::parse(R"({"version":1,
    "notification":{"iconResourceType":"drawable","iconResourceName":"vpn_icon","buttonLabel":"Stop","action":"openApp"},
    "quickAccess":{"enabled":true,"surface":"systemTray","label":"Private VPN","action":"toggle","requireUnlock":false,"androidIconResourceName":"vpn_tile","appleSymbol":"shield","windowsIconPath":"C:\\icons\\vpn.ico"},
    "reconnect":{"enabled":true,"initialDelayMs":200,"maxDelayMs":800,"maxAttempts":3},
    "protection":{"killSwitch":"platformDefault","onDemand":"disabled","alwaysOn":"system"},
    "diagnostics":{"enabled":false,"maxBytes":4096,"maxLines":7}})"));
  assert(options.icon_type=="drawable" && options.icon_name=="vpn_icon" && options.button_label=="Stop" && options.notification_action=="openApp");
  assert(options.quick_enabled && options.surface=="systemTray" && options.label=="Private VPN" && options.quick_action=="toggle" && !options.require_unlock && options.android_icon=="vpn_tile" && options.apple_symbol=="shield" && options.windows_icon=="C:\\icons\\vpn.ico");
  assert(options.reconnect_enabled && options.max_attempts==3 && options.initial_delay_ms==200 && options.max_delay_ms==800);
  assert(options.kill_switch=="platformDefault" && options.on_demand=="disabled" && options.always_on=="system");
  assert(!options.diagnostics_enabled && options.diagnostics_bytes==4096 && options.diagnostics_lines==7);
  options.ValidateWindows();
  assert(options.RetryDelay(0)==200 && options.RetryDelay(1)==400 && options.RetryDelay(2)==800 && options.RetryDelay(INT32_MAX)==800);
  assert(options.MayRetry(2) && !options.MayRetry(3));
  struct Invalid { const char* section; const char* key; Json value; };
  for (const auto& entry : std::initializer_list<Invalid>{
      {"notification","iconResourceType","file"},{"notification","iconResourceName","../bad"},{"notification","buttonLabel","bad\nlabel"},{"notification","action","callback"},
      {"quickAccess","enabled",1},{"quickAccess","surface","unknown"},{"quickAccess","label"," "},{"quickAccess","action","callback"},{"quickAccess","requireUnlock",0},{"quickAccess","androidIconResourceName","x.svg"},{"quickAccess","appleSymbol","\n"},{"quickAccess","windowsIconPath","relative.ico"},
      {"reconnect","enabled","true"},{"reconnect","initialDelayMs",99},{"reconnect","initialDelayMs",1.5},{"reconnect","maxDelayMs",600001},{"reconnect","maxAttempts",1001},
      {"protection","killSwitch","off"},{"protection","onDemand","off"},{"protection","alwaysOn","off"},
      {"diagnostics","enabled","false"},{"diagnostics","maxBytes",4095},{"diagnostics","maxLines",301}}) {
    Reject([&] { NativeOptions::Parse(Json{{entry.section,Json{{entry.key,entry.value}}}}); });
  }
  Reject([] { NativeOptions::Parse(Json{{"version",2}}); });
  Reject([] { NativeOptions::Parse(Json{{"notification","wrong"}}); });
  Reject([] { NativeOptions::Parse(Json{{"reconnect",{{"enabled",false}}},{"protection",{{"onDemand","enabled"}}}}); });
  Reject([] { auto value=NativeOptions(); value.surface="quickTile"; value.quick_enabled=true; value.ValidateWindows(); });
  Reject([] { auto value=NativeOptions(); value.always_on="requireEnabled"; value.ValidateWindows(); });
  Reject([] { auto value=NativeOptions(); value.on_demand="enabled"; value.ValidateWindows(); });
  std::cout << "PASS Windows options: every field, unsupported features, malformed inputs and capped retry policy\n";
}
