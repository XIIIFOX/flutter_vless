# Xray profile API

The Dart API adds an immutable profile, typed outbounds, groups and routes,
atomic editing and exact JSON paths. Existing entry points and mutable models
retain their contracts. Profiles launch through
`startVless(remark: ..., config: profile.toCoreJson())`.

The target native runtime for Android, iOS, macOS and Windows is Xray-core
26.11.9. The compatibility suite also runs against the previous Core 26.10.31.

## Profile and editing

- `XrayProfile.fromJson` accepts JSON and JSONC and snapshots the complete
  document. Unknown fields, key spelling, array order, nulls and empty
  containers are preserved. Re-encoding may change formatting and comments.
- `XrayProfile.build` constructs a new profile. `edit` applies a synchronous
  draft transaction to a copy. A failed transaction leaves the source
  untouched. Maps and lists passed in or exported are independent. A retained
  draft cannot mutate a committed snapshot.
- `CorePath.root.key(...).index(...)` selects literal keys and array indices.
  `setRaw(path, null)` stores null, `removeRaw` deletes a member and a list
  value replaces the complete list. Writes to a missing or invalid parent
  report an error. Conflicting writes require explicit replacement.
- Typed edits use the existing schema lookup for aliases and reject ambiguous
  known keys. Raw keys retain their exact spelling. Node and group references
  are scoped to one draft. Use `nodeAt` and `groupAt` to reference imported
  entries or reacquire a reference in a later edit. A deleted or replaced
  target and a foreign reference fail with an actionable error.
- `requireCoreAtLeast` writes Xray's `version.min` explicitly. It preserves a
  stricter minimum, an existing maximum and unknown version members, and
  rejects a contradictory range. Native features use their own capability
  checks. Raw preservation applies to the authored profile. Existing runtime
  preparation, including TLS and protected DNS rules, still applies at start.

## Typed routing and observation

`ProxyNode.fromLink` reuses the existing link parsers. The draft returns typed
references from `addNode` and `addGroup`. A node may belong to multiple
groups. `RouteTarget` supports a node, a group, direct and block. The compiler
emits `outboundTag` or `balancerTag` and preserves the order of routing rules.

`BalanceStrategy` is a final Dart type with factories for `random`,
`roundRobin`, `leastPing` and `leastLoad`, and a `raw(type:, settings:)`
factory. Core matches selectors by prefix. Verify the effective member set
before export and after native preparation, including private service tags.

`leastPing` uses Observatory. `leastLoad` uses Burst Observatory for latency,
dispersion and failure data. There is one effective observation provider per
generated profile. Use an explicit probe URL and one compatible provider
across groups. Preserve imported observer sections and report conflicts when
a typed edit requires different observation. Random and round robin without
observation do not emit a health fallback. A generated least-ping preset can
choose `GroupFallback.block()` before observations arrive or when Core has
no candidate. This policy applies to new flows matched by the group.

The generated last route covers TCP and UDP across the actual traffic
ingress. Subsequent edits to the same in-memory profile keep authored
exceptions ahead of its default. If an imported profile already has an
unscoped catch-all, edit it explicitly before setting a new default. A rule
scoped to an imported inbound requires `VpnRoutingOptions.sourceInboundIndex`
when the platform uses a private SOCKS listener. Native preparation keeps
protected DNS and platform guard rules ahead of the catch-all. The group controls
flows matched by its rule. An OS kill switch and platform protected DNS have their
own policy. Test uncached A and AAAA lookups separately after the primary
outbound fails, with a fixture that explicitly routes its DNS through the
group. Existing protected DNS on Apple, Android and Windows may select a
specific outbound.

```dart
final profile = XrayProfile.build((draft) {
  final first = draft.addNode(ProxyNode.fromLink(firstLink));
  final second = draft.addNode(ProxyNode.fromLink(secondLink));
  final group = draft.addGroup(
    nodes: [first, second],
    strategy: BalanceStrategy.leastPing(),
    fallback: GroupFallback.block(),
  );
  draft.setHealthProbe(HealthProbe.http(probeUrl));
  draft.addRule(RouteRule.domains(
    ['domain:example.org'],
    to: RouteTarget.direct(),
  ));
  draft.setDefaultRoute(RouteTarget.group(group));
});
```

```dart
final original = XrayProfile.fromJson(savedJson);
final rule = CorePath.root
    .key('outbounds').index(0)
    .key('settings').key('finalRules').index(0);
final updated = original.edit((draft) {
  draft.removeRaw(rule.key('blockDelay'));
  draft.setRaw(rule.key('delay'), 0);
  draft.setRaw(rule.key('logLevel'), 'warning');
  draft.requireCoreAtLeast('26.11.9');
});
```

The raw example assumes the first outbound is Freedom and its first final
rule blocks traffic. Core 26.11.9 supports `delay` and `logLevel` on block
rules. A later typed setter can emit the same fields. App-specific typed
wrappers can use raw paths in the meantime.

## Acceptance

| Check | Pass condition |
| --- | --- |
| Existing client upgraded to 1.1.8 | Legacy code compiles, starts and imports links, JSONC, full JSON and profile lists as before |
| Atomic copy | Nested unknowns, aliases, nulls, order and original snapshot survive edits. Reject foreign references, ambiguous paths and conflicting operations |
| New field on both Cores | Both parse `delay: 0`. A blocked request closes immediately on 26.11.9. 26.10.31 rejects the guarded profile |
| Group on both Cores | Real local traffic proves round robin across connections, least-ping selection and failover, no direct leak when all members fail, recovery and correct selector membership |
| Native Proxy and VPN | Verify direct and grouped domains, private ingress and service selectors, uncached DNS after failure, and session cleanup on Android, iOS, macOS and Windows |
| Promoted typed field | Typed and raw edits produce equivalent Core JSON and retain unknown siblings |

The Dart tests compare the generated outbound tags, routing and Observatory
with the [native fixture](../tool/fixtures/compatibility/typed-profile-balancer.json).
The root CI job runs the generated profiles against verified Xray 26.10.31
and 26.11.9 executables. For the same checks locally, point
`XRAY_PROFILE_TEST_OLD_CORE` and `XRAY_PROFILE_TEST_NEW_CORE` at the corresponding
executables and run `flutter test test/xray_profile_core_integration_test.dart`.

Android runs the failover fixture through the VPN service and TUN on an emulator.
The Apple privacy harness uses the native VPN configuration preparer and its
authenticated SOCKS and DNS paths on macOS and iOS Simulator. The Windows
runtime workflow checks the prepared config, then tests Wintun traffic, DNS
failover and removal of WFP state. These fixtures give DNS an explicit group
route, retain the private inbound guards and check fresh A and AAAA records
through the selected proxy.

[Xray 26.11.9 release](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9)
