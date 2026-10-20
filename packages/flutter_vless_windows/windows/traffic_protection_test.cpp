// Executes the production WFP transaction builder against a recording API.
// No filters, routes or DNS settings are installed on the test machine.
#include "traffic_protection.h"
#include <fwpmu.h>
#include "wfp_compat.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <sddl.h>
#include <iostream>
#include <vector>

namespace {
GUID owned_provider{};
GUID foreign_provider = {0xdec0de,0x1234,0x5678,{1,2,3,4,5,6,7,8}};
size_t enumeration_offset = 0;
struct Rule {
  GUID layer{}; FWP_ACTION_TYPE action{}; UINT64 weight=0, interface_=0, id=0;
  bool loop=false, app=false, service_app=false, elevated=false, service=false, has_address=false; UINT8 protocol=0; UINT16 local=0, remote=0;
  std::array<uint8_t, 16> address{};
};
std::vector<Rule> live, pending;
int fail_add = -1, additions = 0;
bool transaction = false;
bool same(const GUID& a,const GUID& b) { return std::memcmp(&a,&b,sizeof(a))==0; }
struct Flow { bool v6=false, inbound=false, loop=false, xray=false; UINT64 interface_=0; bool elevated=false, service_app=false, service=false; UINT8 protocol=IPPROTO_TCP; UINT16 local=50000, remote=443; std::array<uint8_t, 16> address{}; };
bool permits(Flow flow) {
  GUID layer = flow.v6 ? (flow.inbound ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 : FWPM_LAYER_ALE_AUTH_CONNECT_V6)
      : (flow.inbound ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V4);
  const Rule* chosen=nullptr;
  for (const auto& rule:live) {
    if (!same(rule.layer,layer) || (rule.loop&&!flow.loop) || (rule.app&&!flow.xray) || (rule.service_app&&!flow.service_app) || (rule.elevated&&!flow.elevated) || (rule.service&&!flow.service)
        || (rule.interface_&&rule.interface_!=flow.interface_) || (rule.protocol&&rule.protocol!=flow.protocol)
        || (rule.local&&rule.local!=flow.local) || (rule.remote&&rule.remote!=flow.remote)
        || (rule.has_address&&rule.address!=flow.address)) continue;
    if(!chosen||rule.weight>chosen->weight) chosen=&rule;
  }
  return !chosen || chosen->action==FWP_ACTION_PERMIT;
}
void require_physical_dns_boundary() {
  for (bool inbound : {false, true}) {
    for (UINT8 protocol : {static_cast<UINT8>(IPPROTO_TCP), static_cast<UINT8>(IPPROTO_UDP)}) {
      Flow dns; dns.inbound=inbound; dns.protocol=protocol; dns.remote=53; dns.interface_=99;
      assert(!permits(dns)); // Ordinary application/OS DNS cannot bypass the TUN.
      dns.elevated=true; assert(!permits(dns)); // Elevation alone is no image grant.
      dns.elevated=false; dns.xray=true; assert(!permits(dns));
      dns.elevated=true; assert(permits(dns)); // Existing owned Core IPv4 direct egress includes caller DNS.
      dns.v6=true; assert(!permits(dns)); // Direct DNS does not add a physical IPv6 grant.
    }
  }
}
void require_tunnel_only_ipv6(UINT64 tunnel) {
  for (bool inbound : {false, true}) {
    for (UINT8 protocol : {static_cast<UINT8>(IPPROTO_TCP), static_cast<UINT8>(IPPROTO_UDP)}) {
      Flow flow;flow.v6=true;flow.inbound=inbound;flow.protocol=protocol;flow.interface_=tunnel;
      assert(permits(flow)); // inner IPv6 packet must reach the owned Wintun
      for (UINT64 physical : {UINT64{0}, UINT64{99}}) {
        flow.interface_=physical;assert(!permits(flow));
        flow.xray=true;flow.elevated=true;assert(!permits(flow)); // no physical exception, even for Xray
        flow.xray=false;flow.elevated=false;
      }
    }
  }
  for (const auto& rule : live) {
    const bool v6 = same(rule.layer,FWPM_LAYER_ALE_AUTH_CONNECT_V6) || same(rule.layer,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
    if (v6 && rule.action==FWP_ACTION_PERMIT && !rule.loop) {
      assert(rule.interface_==tunnel && !rule.app && !rule.elevated && !rule.service_app && !rule.service);
    }
  }
}
}
extern "C" {
DWORD WINAPI FwpmEngineOpen0(const wchar_t*,UINT32,SEC_WINNT_AUTH_IDENTITY_W*,const FWPM_SESSION0* session,HANDLE* engine) {
  assert(!session || !(session->flags & FWPM_SESSION_FLAG_DYNAMIC)); *engine=reinterpret_cast<HANDLE>(1); return ERROR_SUCCESS;
}
DWORD WINAPI FwpmEngineClose0(HANDLE) { return ERROR_SUCCESS; }
DWORD WINAPI FwpmTransactionBegin0(HANDLE,UINT32) { transaction=true; pending=live; additions=0; return ERROR_SUCCESS; }
DWORD WINAPI FwpmTransactionAbort0(HANDLE) { transaction=false; pending.clear(); return ERROR_SUCCESS; }
DWORD WINAPI FwpmTransactionCommit0(HANDLE) { transaction=false; live=pending; return ERROR_SUCCESS; }
DWORD WINAPI FwpmProviderAdd0(HANDLE,const FWPM_PROVIDER0* provider,PSECURITY_DESCRIPTOR) {
  assert(provider->flags&FWPM_PROVIDER_FLAG_PERSISTENT); owned_provider=provider->providerKey; return ERROR_SUCCESS;
}
DWORD WINAPI FwpmSubLayerAdd0(HANDLE,const FWPM_SUBLAYER0* layer,PSECURITY_DESCRIPTOR) {
  assert(layer->flags&FWPM_SUBLAYER_FLAG_PERSISTENT); return ERROR_SUCCESS;
}
DWORD WINAPI FwpmGetAppIdFromFileName0(const wchar_t* path,FWP_BYTE_BLOB** result) {
  auto* blob=static_cast<FWP_BYTE_BLOB*>(LocalAlloc(LPTR,sizeof(FWP_BYTE_BLOB)+1));
  blob->size=1;blob->data=reinterpret_cast<UINT8*>(blob+1);blob->data[0]=std::wstring(path).find(L"svchost.exe")!=std::wstring::npos?2:1;*result=blob;return ERROR_SUCCESS;
}
void WINAPI FwpmFreeMemory0(void** value) { LocalFree(*value);*value=nullptr; }
DWORD WINAPI FwpmFilterCreateEnumHandle0(HANDLE,const FWPM_FILTER_ENUM_TEMPLATE0* match,HANDLE* enumeration) {
  assert(!match); enumeration_offset=0; *enumeration=reinterpret_cast<HANDLE>(1);return ERROR_SUCCESS;
}
DWORD WINAPI FwpmFilterDestroyEnumHandle0(HANDLE,HANDLE) {return ERROR_SUCCESS;}
DWORD WINAPI FwpmFilterEnum0(HANDLE,HANDLE,UINT32 maximum,FWPM_FILTER0*** entries,UINT32* count) {
  const auto& source = transaction ? pending : live;
  *count=std::min<UINT32>(maximum,static_cast<UINT32>(source.size()+1-enumeration_offset));
  auto* block=static_cast<unsigned char*>(LocalAlloc(LPTR, std::max<size_t>(1,*count*(sizeof(FWPM_FILTER0*)+sizeof(FWPM_FILTER0)))));
  *entries=reinterpret_cast<FWPM_FILTER0**>(block);
  auto* rows=reinterpret_cast<FWPM_FILTER0*>(block+*count*sizeof(FWPM_FILTER0*));
  for(UINT32 i=0;i<*count;++i){
    const size_t index=enumeration_offset+i;
    rows[i].filterId=index==0?9999:source[index-1].id;
    rows[i].providerKey=index==0?&foreign_provider:&owned_provider;
    (*entries)[i]=&rows[i];
  }
  enumeration_offset+=*count;
  return ERROR_SUCCESS;
}
DWORD WINAPI FwpmFilterDeleteById0(HANDLE,UINT64 id) {
  assert(id!=9999); // foreign filters must survive every cleanup and rollback
  pending.erase(std::remove_if(pending.begin(),pending.end(),[&](const Rule& r){return r.id==id;}),pending.end());return ERROR_SUCCESS;
}
DWORD WINAPI FwpmFilterAdd0(HANDLE,const FWPM_FILTER0* filter,PSECURITY_DESCRIPTOR,UINT64* id) {
  if(additions++==fail_add)return ERROR_ACCESS_DENIED;
  assert(filter->providerKey && (filter->flags&FWPM_FILTER_FLAG_PERSISTENT));
  Rule rule;rule.layer=filter->layerKey;rule.action=filter->action.type;rule.weight=*filter->weight.uint64;rule.id=pending.size()+1;
  for(UINT32 i=0;i<filter->numFilterConditions;++i){
    const auto& c=filter->filterCondition[i];
    if(same(c.fieldKey,FWPM_CONDITION_FLAGS)){assert(c.matchType==FWP_MATCH_FLAGS_ALL_SET);rule.loop=true;}
    else if(same(c.fieldKey,FWPM_CONDITION_ALE_APP_ID)) {
      rule.app=c.conditionValue.byteBlob->data[0]==1;
      rule.service_app=c.conditionValue.byteBlob->data[0]==2;
    } else if(same(c.fieldKey,FWPM_CONDITION_ALE_USER_ID)) {
      LPWSTR descriptor=nullptr;
      assert(ConvertSecurityDescriptorToStringSecurityDescriptorW(c.conditionValue.sd->data, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &descriptor, nullptr));
      const std::wstring sddl(descriptor); LocalFree(descriptor);
      rule.elevated=sddl.find(L";;;BA")!=std::wstring::npos;
      rule.service=sddl.find(L"S-1-5-80-")!=std::wstring::npos;
      assert(rule.elevated||rule.service);
    }
    else if(same(c.fieldKey,FWPM_CONDITION_IP_LOCAL_INTERFACE))rule.interface_=*c.conditionValue.uint64;
    else if(same(c.fieldKey,FWPM_CONDITION_IP_PROTOCOL))rule.protocol=c.conditionValue.uint8;
    else if(same(c.fieldKey,FWPM_CONDITION_IP_LOCAL_PORT))rule.local=c.conditionValue.uint16;
    else if(same(c.fieldKey,FWPM_CONDITION_IP_REMOTE_PORT))rule.remote=c.conditionValue.uint16;
    else if(same(c.fieldKey,FWPM_CONDITION_IP_REMOTE_ADDRESS)) {
      assert(c.conditionValue.type==FWP_BYTE_ARRAY16_TYPE); rule.has_address=true;
      std::copy_n(c.conditionValue.byteArray16->byteArray16,16,rule.address.begin());
    }
    else assert(false);
  }
  pending.push_back(rule);if(id)*id=rule.id;return ERROR_SUCCESS;
}
}
int main() {
  {
    flutter_vless::TrafficProtection protection([] { return L"S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582"; });
    assert(protection.Inspect() && !protection.Active());
    assert(protection.Install(L"C:\\app\\xray.exe"));
    assert(protection.Active());
    require_physical_dns_boundary();
    assert(!permits({})); // IPv4 before TUN ready
    Flow dns;dns.protocol=IPPROTO_UDP;dns.remote=53;assert(!permits(dns));
    Flow v6;v6.v6=true;assert(!permits(v6));v6.xray=true;assert(!permits(v6));
    Flow xray;xray.xray=true;assert(!permits(xray));xray.elevated=true;assert(permits(xray)); // transport/direct outbound
    Flow loop;loop.loop=true;assert(permits(loop));loop.v6=true;assert(permits(loop));
    Flow dhcp;dhcp.protocol=IPPROTO_UDP;dhcp.local=68;dhcp.remote=67;assert(!permits(dhcp));dhcp.service_app=true;assert(!permits(dhcp));dhcp.service=true;assert(permits(dhcp));
    NET_LUID tun{};tun.Value=42;assert(protection.Install(L"C:\\app\\xray.exe",&tun));
    require_physical_dns_boundary();
    require_tunnel_only_ipv6(tun.Value);
    Flow client;client.interface_=42;assert(permits(client));
    client.interface_=99;assert(!permits(client)); // new physical adapter
    dns.interface_=42;assert(permits(dns));dns.interface_=99;assert(!permits(dns));
    const size_t count=live.size();
    // Every failed partial replacement must retain the complete old barrier.
    for(int failure=0;failure<static_cast<int>(count);++failure){
      fail_add=failure;assert(!protection.Install(L"C:\\app\\xray.exe",&tun));
      assert(live.size()==count && !permits({}) && !permits(v6));
      require_tunnel_only_ipv6(tun.Value);
    }
    fail_add=-1;
    // Runtime exit does not call Release; destructor closes only engine handles.
  }
  assert(!live.empty() && !permits({}));
  {
    flutter_vless::TrafficProtection recovery;
    assert(recovery.Inspect() && recovery.Active());
    assert(recovery.Release()); // explicit stop after application crash
    assert(live.empty() && permits({}));
  }
  {
    flutter_vless::TrafficProtection protection;
    flutter_vless::Ipv6TcpScope scope; scope.interface_luid = 99;
    flutter_vless::Ipv6TcpEndpoint endpoint; endpoint.address = {0xfd,0,0,0x85,0,2,0,0,0,0,0,0,0,0,0,2}; endpoint.port = 18443;
    scope.endpoints.push_back(endpoint);
    assert(protection.Install(L"C:\\app\\xray.exe", nullptr, &scope));
    Flow allowed; allowed.v6=true; allowed.xray=true; allowed.elevated=true;
    allowed.interface_=scope.interface_luid; allowed.address=endpoint.address; allowed.remote=endpoint.port;
    assert(permits(allowed));
    for (int variant=0; variant<7; ++variant) {
      auto denied=allowed;
      if(variant==0)denied.xray=false;
      if(variant==1)denied.elevated=false;
      if(variant==2)denied.interface_=100; // new/different underlay
      if(variant==3)denied.address[15]=3; // dynamic direct IPv6 cannot borrow the grant
      if(variant==4)denied.remote=53;
      if(variant==5)denied.protocol=IPPROTO_UDP;
      if(variant==6)denied.inbound=true; // no passive physical Core listener grant
      assert(!permits(denied));
    }
    NET_LUID tun{}; tun.Value=42;
    assert(protection.Install(L"C:\\app\\xray.exe", &tun, &scope) && permits(allowed));
    Flow captured;captured.v6=true;captured.interface_=42;assert(permits(captured));
    const auto count=live.size();
    for(int failure=0;failure<static_cast<int>(count);++failure) {
      fail_add=failure;assert(!protection.Install(L"C:\\app\\xray.exe", &tun, &scope));
      assert(live.size()==count && permits(allowed));
      auto other=allowed;other.address[15]=3;assert(!permits(other));
    }
    fail_add=-1;
    auto bad=scope;bad.interface_luid=0;assert(!protection.Install(L"C:\\app\\xray.exe", &tun, &bad));
    bad=scope;bad.interface_luid=tun.Value;assert(!protection.Install(L"C:\\app\\xray.exe", &tun, &bad));
    bad=scope;bad.endpoints[0].port=0;assert(!protection.Install(L"C:\\app\\xray.exe", &tun, &bad));
    bad=scope;bad.endpoints[0].address={};assert(!protection.Install(L"C:\\app\\xray.exe", &tun, &bad));
    assert(permits(allowed) && protection.Release() && live.empty());
    std::cout<<"WINDOWS_NUMERIC_IPV6_WFP_PASS=1\n";
  }
  std::cout<<"PASS WFP policy, IPv4/IPv6/DNS, new adapters, atomic failure rollback and explicit-stop recovery (recording backend)\n";
}
