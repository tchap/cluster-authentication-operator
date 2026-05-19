## PR title

```
enhancements/authentication: Add proxy support for integrated auth stack
```

## PR description

```
This enhancement adds an optional, component-scoped proxy configuration
to the Authentication operator (operator.openshift.io/v1) so that
authentication components (CAO, OAuth Server) can reach external identity
providers through a proxy without requiring the cluster-wide egress proxy.

In disconnected environments, the auth stack is the only component that
must reach arbitrary, customer-chosen external endpoints — on every login.
Today the only option is the cluster-wide proxy, which opens egress for
all components uniformly. Existing workarounds (proxy ACLs, network
policy, internal IdP federation, egress sidecars, manual env var
injection) are fragile, unsupported, or disproportionately complex.

This enhancement introduces Authentication.spec.proxy with httpProxy,
httpsProxy, noProxy, and trustedCA fields, mirroring the cluster-wide
proxy API. When set, these override the cluster-wide proxy for auth
components only. When absent, behavior is unchanged.

Changes proposed:
- API: new AuthenticationProxyConfig type on AuthenticationSpec, gated
  behind FeatureGateAuthenticationComponentProxy (TechPreviewNoUpgrade)
- OAuth Server: resolved proxy injected as HTTP_PROXY/HTTPS_PROXY/NO_PROXY
  env vars; trustedCA synced and appended to system trust via entrypoint
- Operator process: proxy-aware HTTP transport for OIDC discovery during
  config observation
- Proxy validation: URL format and trustedCA validation (Degraded on
  error); IdP connectivity validation on config change (Warning events
  for transient failures)

HyperShift, External OIDC mode, and per-IdP proxy are out of scope.

Tracking: https://redhat.atlassian.net/browse/CNTRLPLANE-3376
See also: enhancements/proxy/global-cluster-egress-proxy.md
```
