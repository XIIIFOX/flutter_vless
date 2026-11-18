#include "balancer_selection_protocol.h"
#include "native_routing_protocol.h"
#include <cassert>
#include <iostream>

int main() {
  using namespace flutter_vless::balancer_selection;
  using flutter_vless::native_routing::SuccessfulReply;
  assert(SuccessfulReply(R"({"stage":"capabilities","code":0,"capability":1})", "capabilities", true));
  assert(!SuccessfulReply("Unknown command: native-balancer\n", "capabilities", true));
  assert(!SuccessfulReply(R"({"stage":"capabilities","code":0,"capability":0})", "capabilities", true));
  const std::string valid = "1,1,2\n3,1,1\n9,2,7";
  assert(BoundedRows(valid, 10, 100) == valid);
  assert(BoundedRows(valid, 2, 100) == "3,1,1\n9,2,7");
  assert(BoundedRows(valid, 10, 10) == "9,2,7");
  assert(BoundedRows(valid, 10, 4) == "");
  assert(BoundedRows("1,1,2", 10, 5) == "1,1,2");
  assert(BoundedRows("9223372036854775807,1,2", 10, 100) == "9223372036854775807,1,2");
  for (const auto* rows : {"1,1,node.example", "1,0,7", "1,2,03", "2,1,1\n2,1,2", "2,1,1\n1,1,2",
      "1,1,2\n", "1,1,2\r", "1,1,2,3", "1, 1,2", "1,+1,2", "1,1,-2", "1,,2", "1,2", "\n2,1,1",
      "9223372036854775808,1,2", "1,9223372036854775808,2", "1,1,9223372036854775808",
      "1,1,private-canary\n5,6,7"}) {
    assert(!BoundedRows(rows, 1, 10));
  }
  std::string maximum;
  for (size_t index = 1; index <= kMaxRows; ++index) {
    if (!maximum.empty()) maximum.push_back('\n');
    maximum += std::to_string(index) + ",1,2";
  }
  assert(BoundedRows(maximum, kMaxRows, kMaxPayloadBytes) == maximum);
  assert(!BoundedRows(maximum + "\n301,1,2", 1, 10));
  assert(!BoundedRows(std::string(kMaxPayloadBytes + 1, '9'), kMaxRows, kMaxPayloadBytes));

  assert(ParseReply(R"({"stage":"selections","code":0,"rows":""})", 10, 100) == "");
  assert(ParseReply(R"({"stage":"selections","code":0,"rows":"1,1,2\n2,1,1"})", 10, 100) == "1,1,2\n2,1,1");
  for (const auto* reply : {"", "false", "1,2,3", R"({"stage":"started","code":0})",
      R"({"stage":"selections","code":1,"rows":"1,1,1"})", R"({"stage":"selections","code":0,"rows":[]})",
      R"({"stage":"selections","code":0,"rows":"1,1,1","tag":"private-canary"})",
      R"({"stage":"selections","code":0,"rows":"private-canary","rows":"1,1,1"})",
      R"({"stage":"selections","code":0,"rows":"1,1,1\u0000"})", R"({"stage":"selections","code":0,"rows":"1,1,1"} {})"}) {
    assert(!ParseReply(reply, 10, 100));
  }
  assert(!ParseReply(std::string(kMaxReplyBytes + 1, ' '), 10, 100));
  std::cout << "PASS Windows balancer reply: bounded ordinals, strict framing and privacy\n";
}
