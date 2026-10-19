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
well as normal shutdown. The dispatcher also seals at its own Start boundary.
Native runtime preparation, exact final-document selection, failure cleanup and
binary capability negotiation still need launcher integration.

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
instance or socket runtime is required for default validation. Neither this
preview nor a passing Core fixture qualifies native device/system VPN support.
