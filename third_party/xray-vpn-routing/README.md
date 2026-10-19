# Optional VPN routing seam (unpublished)

This source preview is independent of the strict DNS experiment in
`../xray-native-dns`. It keeps the ordinary pinned Core's protocols, transports,
caller router and dynamic Routing API. It is not yet enabled by the Android,
Apple or Windows launchers and is not a public supported option.

The native owner selects the exact compiled private SOCKS inbound configuration
before `core.NewWithContext`. Caller JSON cannot enable the seam. The inbound
constructor binds that key to the actual Core and handler; an equal tag or an
API-created replacement cannot acquire the binding. Only a single authenticated
loopback TCP SOCKS control listener is admitted. Routing tokens follow Core's
logical rays, including its existing SOCKS UDP association semantics; this does
not add per-packet re-routing inside one established association.

`dispatcher.ContextWithNativeVPNRouting` takes this owner and immutable generated
private guard rules. The host must seal the owner against the returned Core
instance before `Start`, and close the owner on construction/start failure as
well as normal shutdown. The optional `NewWithContext` failure hook revokes the
owner before closing the partial Core, retaining the original construction
error. Unseeded construction keeps upstream behavior. The dispatcher also seals
at its own Start boundary.
The shared mobile factory now retains those exact compiled objects from a
digest-bound final JSON/spec pair, seals before Start and publishes only after
success. It rejects replacement of an active Core before candidate processing.
Stop clears the published pair and revokes the owner before Core cleanup.
Platform launchers still need to adopt this factory and negotiate the actual
binary capability.

Ordinary mobile builds export `RoutingCapability() == 0` and refuse the new
check/start calls. The `flutter_vless_vpn_routing` build tag requires this
overlay and exposes capability 1. `CheckRoutingPrivate` is a decode/build-only
check; `StartRoutingPrivate` uses the same strict spec and constructs one Core.
The spec binds the final JSON digest, private inbound index/tag/auth user,
optional source inbound index, optional default outbound tag and generated guard
indices. It is launcher-owned metadata, never a field imported from caller JSON.
Selected guards are cloned from the compiled router. Nonempty root `env` is
refused before Build to protect the in-process preflight environment.

For an unpublished Apple compile preview use:

```sh
tool/build_apple_core_preview.sh ios build/apple-routing-preview --vpn-routing
```

The same final flag works with `macos`. It copies both modules, validates the
pinned Core checksum and checks generated bridge headers without replacing a
shipped artifact. The receipt records compile expectations separately from
runtime acceptance.

The additive `flutter_vless_vpn_routing_cli` tag registers `native-routing`
in ordinary Core's main package. With the factory tag it exposes capability,
check and foreground run commands over the same private config/spec pair.
It retains ordinary commands and restores their upstream logger after importing
the mobile bridge. The private command emits only fixed status/code JSON.
The executable owns signal cancellation; successful Start is followed by one
Stop before the command returns. Capability refusal precedes file reads.
Android's existing FD protection and Windows service identity still need to be
wired into the opt-in build and launch paths.

`tool/test_native_routing_cli.py` compiles both CLI modes in further disposable
module copies. It executes only stock `version`, native capabilities and native
Check; main registration/logging and lifecycle tests use inert fakes. It never
executes ordinary `run -test`, which constructs Core before reporting its result.
The Apple compatibility shim independently checks the actual linked ABI;
missing check/start entries or a version other than one remain unsupported.

For admitted flows, generated DNS/probe/bootstrap guards see physical inbound
metadata first, ahead of a forced detour. The real caller router then sees a
view overriding only `GetInboundTag`. Its complete `IPIfNonMatch` DNS/IP pass,
scripts, balancers and live rules remain in Core. The explicit VPN default is
considered only after `common.ErrNoClue`; other errors and missing selected
handlers close the ray. The caller's session tag, authentication, sniffing and
DNS flags are not rewritten. A loopback handoff permanently ends that ray's
alias/default privilege without affecting sibling UDP targets.

Control and ray lifetimes are separate. Mux retains a ray before publishing an
asynchronous session and releases it on session Close; returning from
`Handler.Dispatch` alone must not retire that session. Closing the selected
input revokes the owner before underlying listener/proxy cleanup. Imported
flows retain ordinary Core behavior after owner revocation.

The patcher refuses a changed pin, existing destinations and module-cache
destinations. It copies Core before applying the optional hooks, leaving the
shared source untouched. Pure tests use inert identities, fake DNS and logical
routers. The separate actual-Core fixture is CI-only; no local VPN/TUN, Core
instance or socket runtime is required for default validation. The factory
runner compiles both artifacts and selects pure tests explicitly; its separate
actual Start/Stop/restart fixture requires an explicit runtime flag in GitHub
Actions. Neither this preview nor a passing Core fixture qualifies native
device/system VPN support.
