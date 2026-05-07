# Implementation Proposal: Proxy Support for Authentication Resources in Disconnected Environments

**JIRA:** [OCPSTRAT-3174](https://redhat.atlassian.net/browse/OCPSTRAT-3174)
**Date:** 2026-05-07
**Status:** Draft

## Background

OpenShift authentication has three components that make outbound calls to external Identity Providers (IdPs). In disconnected environments, these calls must go through a proxy -- but today the only mechanism is the cluster-wide `proxy.config.openshift.io/cluster`, which opens egress for *all* components.

```
                        ┌─────────────────────────────────────────────────────┐
                        │                   OpenShift Cluster                 │
                        │                                                     │
  User                  │  ┌───────────────────────────────────────────────┐  │
  (oc login,            │  │  Cluster Authentication Operator (CAO)        │  │
   console)             │  │  namespace: openshift-authentication-operator │  │
       │                │  │                                               │  │
       │                │  │  • Deploys and configures the other two       │  │
       │                │  │  • Validates IdP configuration ───────────────│──│──► External IdP
       │                │  │  • Syncs certificates and secrets             │  │    (OIDC discovery)
       │                │  └───────────────────────────────────────────────┘  │
       │                │                                                     │
       │                │  ┌───────────────────────────────────────────────┐  │
       ▼                │  │  OAuth Server                                 │  │
  ┌──────────┐          │  │  namespace: openshift-authentication          │  │
  │  Route   │──────────│─►│                                               │  │
  │ (ingress)│          │  │  • Hosts /login, /oauth/authorize, /callback  │  │
  └──────────┘          │  │  • Redirects user to external IdP ────────────│──│──► External IdP
                        │  │  • Exchanges auth codes for tokens ───────────│──│──► External IdP
                        │  │  • Fetches user info and group membership ────│──│──► External IdP
                        │  │  • Issues OpenShift OAuth access tokens       │  │
                        │  └───────────────────────────────────────────────┘  │
                        │                                                     │
                        │  ┌───────────────────────────────────────────────┐  │
  kube-apiserver ──────►│  │  OAuth API Server                             │  │
  (token validation     │  │  namespace: openshift-oauth-apiserver         │  │
   webhook)             │  │                                               │  │
                        │  │  • Stores OAuth tokens, clients, identities   │  │
                        │  │  • Validates tokens on behalf of KAS          │  │
                        │  │  • (External OIDC mode) fetches JWKS ─────────│──│──► External IdP
                        │  │    from external provider for JWT validation  │  │
                        │  └───────────────────────────────────────────────┘  │
                        └─────────────────────────────────────────────────────┘
```

The arrows leaving the cluster boundary (►) are the outbound calls that need proxy support.

### Components and their outbound calls

**Cluster Authentication Operator (CAO)** -- the control plane. Deploys, configures, and monitors both operands. Makes outbound OIDC discovery calls (`/.well-known/openid-configuration`) during config observation to validate IdP endpoints. Uses `transport.TransportForCARef()` → `net.SetTransportDefaults()`, which respects proxy env vars injected by CVO from the cluster-wide proxy.

**OAuth Server** (`oauth-openshift` Deployment) -- the user-facing authentication endpoint. Implements OAuth 2.0 Authorization Code flow: redirects users to the external IdP, exchanges auth codes for tokens, fetches user info and group membership (GitHub orgs/teams, OIDC userinfo claims). Supports GitHub, GitLab, Google, OIDC, LDAP, HTPasswd, Basic Auth, Keystone, and Request Header IdPs. The component with the most outbound calls. Uses `knet.SetTransportDefaults()` → `http.ProxyFromEnvironment`, so it picks up proxy env vars automatically.

**OAuth API Server** -- the storage and validation backend. Stores opaque OAuth tokens (`sha256~<random>` hashed with SHA256) as `OAuthAccessToken` objects in etcd. Validates tokens via webhook from kube-apiserver (internal, no proxy needed). In **External OIDC mode**, fetches JWKS and discovery documents from the external provider -- these outbound calls **have no proxy support today** (see Gaps below).

### Where outbound calls happen

| Outbound call | Component | When | Proxy today |
|---|---|---|---|
| OIDC discovery | CAO | IdP config change | `net.SetTransportDefaults()` (process env vars; no component-scoped override) |
| OIDC discovery + JWKS | OAuth API Server (external OIDC) | Startup + key rotation | **None -- no proxy env vars injected** |
| Token exchange | OAuth Server | Every login | `knet.SetTransportDefaults()` (env vars) |
| UserInfo / groups | OAuth Server | Every login | `knet.SetTransportDefaults()` (env vars) |
| LDAP bind/search | OAuth Server | LDAP login | LDAP protocol (not HTTP; out of scope) |

## Problem Statement

Customers in restricted environments need auth components to reach external IdPs through a proxy **without** configuring a cluster-wide proxy, which opens egress for all components.

### Identified gaps

1. **No component-scoped proxy API** -- the only proxy source is the cluster-wide `Proxy` resource.
2. **OAuth API Server has no proxy injection at all** -- neither `syncStandardDeployment()` nor `syncExternalOIDCDeployment()` inject proxy env vars. This is a gap even for cluster-wide proxy users.
3. **OAuth API Server OIDC transport ignores env vars** -- even if env vars were injected, `configurator.go:182-186` constructs `oidc.Options{}` without passing an `*http.Client`. The `oidc.Options.Client` field exists and is threaded through to the upstream K8s OIDC authenticator, but is not used. The API types document: "Note that egress selection configuration is not used for this network connection."
4. **CAO and transport layer have no component-scoped proxy override** -- `transport.TransportForCARef()` delegates to `net.SetTransportDefaults()`, which **does** set `Proxy = http.ProxyFromEnvironment` -- so the transport respects proxy env vars injected by CVO from the cluster-wide proxy. But there is no mechanism to override these with component-scoped settings. When no cluster-wide proxy is configured, there are no env vars to read.

## Design

### API: Extend `operator.openshift.io/v1` Authentication spec

Add an optional `proxy` stanza to `AuthenticationSpec` in `operator.openshift.io/v1`. This is the operator-level configuration -- the correct place for operand-scoped infrastructure knobs.

```go
// In openshift/api: operator/v1/types_authentication.go

type AuthenticationSpec struct {
    OperatorSpec `json:",inline"`

    // proxy configures proxy settings specifically for authentication
    // components (OAuth server, OAuth API server, and the operator itself).
    // When set, these values override the cluster-wide proxy for
    // authentication operands. When unset, the cluster-wide proxy (if any)
    // is used as today.
    // +optional
    Proxy *AuthenticationProxyConfig `json:"proxy,omitempty"`
}

// AuthenticationProxyConfig holds proxy configuration scoped to
// authentication components.
type AuthenticationProxyConfig struct {
    // httpProxy is the URL of the proxy for HTTP requests.
    // +optional
    HTTPProxy string `json:"httpProxy,omitempty"`

    // httpsProxy is the URL of the proxy for HTTPS requests.
    // +optional
    HTTPSProxy string `json:"httpsProxy,omitempty"`

    // noProxy is a comma-separated list of hostnames and/or CIDRs and/or IPs
    // for which the proxy should not be used.
    // +optional
    NoProxy string `json:"noProxy,omitempty"`

    // trustedCA is a reference to a ConfigMap in the openshift-config
    // namespace containing a CA certificate bundle under the key
    // "ca-bundle.crt". This CA bundle is used for proxy TLS connections
    // by authentication components.
    // +optional
    TrustedCA configv1.ConfigMapNameReference `json:"trustedCA,omitempty"`
}
```

**Why this approach:**
- `operator.openshift.io/v1/authentications` is the standard place for operator-specific knobs.
- Mirrors `config.openshift.io/v1 Proxy` for familiarity.
- Fully optional -- `nil` means unchanged behavior.
- Does not touch the cluster-wide proxy API (out of scope per OCPSTRAT-3174).
- Feature-gated behind `FeatureGateAuthenticationComponentProxy` (TechPreviewNoUpgrade initially).

### Proxy resolution semantics

The resolution function handles three states. A non-nil but empty `Proxy` struct means "explicitly no proxy for auth, even if the cluster has one" -- this prevents surprises when an admin sets `spec.proxy: {}`.

1. `spec.proxy` set with values → use component-scoped proxy
2. `spec.proxy` set but empty (`proxy: {}`) → explicitly no proxy
3. `spec.proxy` absent (`nil`) → fall back to `proxy.config.openshift.io/cluster`
4. Neither configured → no proxy

### Rejected alternatives

**Per-IDP proxy fields on `oauth.config.openshift.io`:** Feature scopes to component-level, not per-IDP (explicitly out of scope in OCPSTRAT-3174).

**Annotations on the Authentication operator resource:** Loses validation, discoverability, and documentation.

## Implementation Plan

The implementation spans four repositories (`openshift/api`, `cluster-authentication-operator`, `oauth-apiserver`, `oauth-server`) and is broken into phases.

### Phase 1: API changes (`openshift/api`)

- `operator/v1/types_authentication.go` -- add `Proxy *AuthenticationProxyConfig` field and type
- `operator/v1/zz_generated.deepcopy.go`, `zz_generated.swagger_doc_generated.go` -- regenerate
- `config/v1/feature_gates.go` -- add `FeatureGateAuthenticationComponentProxy` (TechPreviewNoUpgrade)
- Add CRD validation markers for URL format, noProxy format

### Phase 2: Bug fix -- OAuth API Server cluster-wide proxy injection

Independent bug fix that benefits all users regardless of the component-proxy feature gate.

**Part A: Operator-side env var injection** (`pkg/operator/workload/sync_openshift_oauth_apiserver.go`)

Add proxy env var injection to both `syncStandardDeployment()` and `syncExternalOIDCDeployment()`, using the cluster-wide proxy only (no feature gate needed):

```go
proxyConfig, _ := c.proxyLister.Get("cluster")
if proxyConfig != nil {
    for i := range required.Spec.Template.Spec.Containers {
        required.Spec.Template.Spec.Containers[i].Env = append(
            required.Spec.Template.Spec.Containers[i].Env,
            proxyEnvVars(proxyConfig.Status.HTTPProxy,
                         proxyConfig.Status.HTTPSProxy,
                         proxyConfig.Status.NoProxy)...,
        )
    }
}
```

**Part B: oauth-apiserver code change** (`pkg/externaloidc/authenticator/jwt/config/configurator.go`)

Env var injection alone is insufficient -- `configurator.go:182-186` constructs `oidc.Options{}` without an `*http.Client`. Build a proxy-aware client and pass it via `oidc.Options.Client`.

`Client` and `CAContentProvider` are **mutually exclusive** in `oidc.Options`, so the CA must be embedded in the client's `TLSClientConfig`:

```go
var tlsConfig *tls.Config
if len(jwt.Issuer.CertificateAuthority) > 0 {
    roots := x509.NewCertPool()
    roots.AppendCertsFromPEM([]byte(jwt.Issuer.CertificateAuthority))
    tlsConfig = &tls.Config{RootCAs: roots}
} else {
    tlsConfig = &tls.Config{}
}

httpClient := &http.Client{
    Transport: knet.SetTransportDefaults(&http.Transport{
        TLSClientConfig: tlsConfig,
    }),
}

tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
    JWTAuthenticator: jwt,
    Client:           httpClient,
    Compiler:         compiler,
})
```

### Phase 3: Component-scoped proxy (cluster-authentication-operator)

All code paths guarded by `FeatureGateAuthenticationComponentProxy`.

#### Accessing `spec.proxy` from controllers

Library-go's `OperatorClient` exposes only base `OperatorSpec` fields. The operator already creates a typed informer factory (`replacement_starter.go:258`):

```go
operatorInformer: operatorinformer.NewSharedInformerFactory(authOperatorInput.operatorClient, 24*time.Hour)
```

Controllers that need `spec.proxy` add an `AuthenticationLister` and read the full typed resource:

```go
authOperator, err := c.authOperatorLister.Get("cluster")
proxy := authOperator.Spec.Proxy
```

Each controller needing proxy config must be wired with this lister in `starter.go`.

#### 3a. Proxy resolution helper

New file: `pkg/controllers/common/proxy.go`

```go
func ResolveProxyConfig(
    authSpec *operatorv1.AuthenticationSpec,
    clusterProxy *configv1.Proxy,
) (httpProxy, httpsProxy, noProxy string) {
    if authSpec != nil && authSpec.Proxy != nil {
        return authSpec.Proxy.HTTPProxy,
               authSpec.Proxy.HTTPSProxy,
               authSpec.Proxy.NoProxy
    }
    if clusterProxy != nil {
        return clusterProxy.Status.HTTPProxy,
               clusterProxy.Status.HTTPSProxy,
               clusterProxy.Status.NoProxy
    }
    return "", "", ""
}
```

#### 3b. Trusted CA bundle syncing

When `spec.proxy.trustedCA` is set:
1. Sync the referenced ConfigMap from `openshift-config` to `openshift-authentication`, `openshift-oauth-apiserver`, and `openshift-authentication-operator`.
2. Mount it into OAuth Server and OAuth API Server deployments.
3. Append to system trust (PEM concatenation, don't replace). Follows the cluster-wide proxy CA pattern.

Changes in `pkg/operator/starter.go`: wire the Authentication operator lister, add informer watches, extend resource sync controller.

#### 3c. OAuth Server deployment injection

**`pkg/controllers/deployment/default_deployment.go`** -- change `getOAuthServerDeployment()` to accept resolved proxy strings instead of `*configv1.Proxy`:

```go
// Before:
func getOAuthServerDeployment(operatorSpec *operatorv1.OperatorSpec,
    proxyConfig *configv1.Proxy, ...) (*appsv1.Deployment, error)

// After:
func getOAuthServerDeployment(operatorSpec *operatorv1.OperatorSpec,
    httpProxy, httpsProxy, noProxy string, ...) (*appsv1.Deployment, error)
```

The OAuth Server picks up env vars automatically via `knet.SetTransportDefaults()` → `http.ProxyFromEnvironment`. All IdP transports (GitHub, GitLab, Google, OIDC) and group resolution flows go through this path.

**`pkg/controllers/deployment/deployment_controller.go`** -- resolve proxy in `sync()` and include in the deployment hash to trigger redeployments:

```go
httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(&authConfig.Spec, clusterProxy)
resourceVersions = append(resourceVersions,
    "auth-proxy:"+httpProxy+":"+httpsProxy+":"+noProxy)
```

#### 3d. OAuth API Server deployment injection

Extend Phase 2 to use `ResolveProxyConfig()` when feature gate is enabled:

```go
if featureGates.Enabled(features.FeatureGateAuthenticationComponentProxy) {
    httpProxy, httpsProxy, noProxy = common.ResolveProxyConfig(authSpec, clusterProxy)
} else {
    // Phase 2 behavior: cluster-wide proxy only
}
```

#### 3e. Operator process proxy configuration

The CAO makes outbound OIDC discovery calls in `discoverOpenIDURLs()` (`idp_conversions.go:315`) via `transport.TransportForCARef()`. This delegates to `net.SetTransportDefaults()`, which sets `Proxy = http.ProxyFromEnvironment` -- so it respects env vars from the cluster-wide proxy. To support component-scoped proxy, add a variant that **overrides** the env-var-based proxy:

**`pkg/transport/transport.go`:**

```go
func TransportForCARefWithProxy(
    cmLister corelistersv1.ConfigMapLister,
    caConfigMapName, key string,
    proxyURL *url.URL,
) (http.RoundTripper, error) {
    // ... build transport as before (net.SetTransportDefaults sets
    // Proxy = http.ProxyFromEnvironment by default) ...
    if proxyURL != nil {
        transport.Proxy = http.ProxyURL(proxyURL)
    }
    return transport, nil
}
```

**`pkg/controllers/configobservation/oauth/idp_conversions.go`** -- update `discoverOpenIDURLs()` to accept and use proxy configuration via the `AuthenticationLister`. If the component-scoped `trustedCA` is set, load that CA from the synced ConfigMap in `openshift-authentication-operator`.

#### 3f. Proxy validation controller

**`pkg/controllers/proxyconfig/proxyconfig_controller.go`**

The current controller reads proxy from process env vars (`httpproxy.FromEnvironment()`) and validates that the OAuth route's `/healthz` endpoint is reachable. When external OIDC is configured, the check is skipped entirely.

Extend to validate the component-scoped proxy:
- Test connectivity to IdP endpoints through the component proxy
- Report `ProxyConfigControllerDegraded` if misconfigured
- Load CA from the component-scoped `trustedCA` ConfigMap
- Validate that `noProxy` includes essential cluster-internal CIDRs; warn if entries from cluster-wide `noProxy` are missing

#### 3g. Upgradeable condition

Set `Upgradeable=False` on the ClusterOperator when `spec.proxy` is configured. Prevents accidental upgrades during TechPreview.

### Phase 4: Testing

**Unit tests:**
- `proxy_test.go` -- resolution precedence (component > cluster > none), explicit disable
- `default_deployment_test.go` -- env var injection with component proxy
- `transport_test.go` -- proxy function override on transport

**E2E tests:**
- Deploy a test proxy (e.g., Squid) in the cluster
- Configure `Authentication.spec.proxy` → verify OAuth login succeeds via proxy
- Verify non-auth components do NOT use the component proxy
- Test fallback (remove component proxy → cluster-wide proxy used)
- Test explicit disable (`proxy: {}` → no proxy even with cluster-wide)
- Test error reporting (invalid proxy → degraded condition)
- Test feature gate cross-product: `AuthenticationComponentProxy` × `ExternalOIDC`

**CI:** Dedicated periodic job on a TechPreview cluster. Graduation bar: 5+ tests, 7+/week, 95%+ pass rate for 14+ days.

## User Experience

```yaml
apiVersion: operator.openshift.io/v1
kind: Authentication
metadata:
  name: cluster
spec:
  managementState: Managed
  proxy:
    httpProxy: "http://proxy.corp.example.com:3128"
    httpsProxy: "http://proxy.corp.example.com:3128"
    noProxy: ".cluster.local,.svc,10.0.0.0/8,172.16.0.0/12"
    trustedCA:
      name: "auth-proxy-ca-bundle"
```

The referenced ConfigMap must exist in `openshift-config` with key `ca-bundle.crt`.

**Status reporting:** `ProxyConfigControllerDegraded` when proxy is unreachable. `Upgradeable=False` during TechPreview. Resolved proxy config surfaced in operator status / deployment annotations for `oc adm inspect` / must-gather.

**Backward compatibility:** When `spec.proxy` is `nil`, behavior is identical to today. The OAuth API Server proxy injection (Phase 2) is a bug fix -- when no proxy is configured, no env vars are set.

## Scope and Topology

**Supported:** Standalone OpenShift (multi-node, compact, SNO), restricted/disconnected networks.

**HyperShift (Hosted Control Planes) -- not supported initially.** The CAO does not run in HyperShift (explicitly excluded from CVO payload). Auth pods run in the management cluster's HCP namespace. HyperShift already has proxy support via `HostedCluster.spec.configuration.proxy` and konnectivity sidecar injection (`InjectKonnectivityContainer()` with dual SOCKS5/HTTP CONNECT mode). HyperShift's `idp_convert.go:683-754` already builds proxy-aware HTTP transports for OIDC discovery -- essentially what Phase 3e proposes for standalone. For the initial release: document as unsupported on HCP; consider a validation webhook to reject the field. Future HCP support would require a HyperShift-side change to read the field -- the transport plumbing already exists.

## Risks and Mitigations

Informed by code analysis and by precedent from existing enhancement proposals: [Global Cluster Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/proxy/global-cluster-egress-proxy.md), [Windows Node Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/windows-containers/windows-node-egress-proxy.md), [Direct External OIDC Provider](https://github.com/openshift/enhancements/blob/master/enhancements/authentication/direct-external-oidc-provider.md), [AuthConfig Missing Fields](https://github.com/openshift/enhancements/blob/master/enhancements/authentication/AuthConfig-missing-fields.md), and [IBM Service Endpoint Dynamic Override](https://github.com/openshift/enhancements/blob/master/enhancements/cloud-integration/ibm/service-endpoint-dynamic-override.md).

### Implementation risks

| Risk | Mitigation |
|------|------------|
| API change requires openshift/api PR and review cycle | Start with API PR early; operator changes proceed in parallel using vendored types |
| Env var injection alone does not reach the oauth-apiserver OIDC transport | Pass a proxy-configured `*http.Client` via `oidc.Options.Client` (Phase 2B). `Client` and `CAContentProvider` are mutually exclusive -- CA must be in `TLSClientConfig` |
| CA bundle conflicts between component and cluster trust | Component `trustedCA` is appended to system trust (PEM concatenation), not replacing it |
| OAuth API Server proxy injection could change behavior for existing clusters | No env vars set when no proxy is configured (no behavior change). Bug fix (Phase 2) is un-gated; component proxy (Phase 3d) is feature-gated |
| `Authentication.spec.proxy` silently ignored on HyperShift | Document as unsupported; consider validation webhook |

### Operational risks

| Risk | Mitigation |
|------|------------|
| **Cluster bricking from invalid proxy config** -- misconfigured proxy can lock all users out | Validate IdP connectivity before applying. Report `ProxyConfigControllerDegraded`. Document recovery via `kubeadmin` or client cert auth |
| **Proxy as untrusted intermediary** -- could intercept auth codes, tokens, user info | Document trust model. `trustedCA` pins proxy TLS certificate. Same model as cluster-wide proxy |
| **Network dependency in auth path** -- proxy failure blocks all authentication | Same class of failure as cluster-wide proxy. Document HA requirement. Set `Degraded` when unreachable |
| **Debugging complexity** -- component proxy differs from cluster proxy | Surface resolved config in operator status and deployment annotations. Document precedence |
| **noProxy conflicts** -- users must reconcile component and cluster settings | Validate essential cluster-internal CIDRs. Warn via status condition |
| **SNO disruption** -- only one OAuth server instance | Same as any OAuth config change on SNO. Document brief auth outage during rollout |

### Lifecycle risks

| Risk | Mitigation |
|------|------------|
| **Feature gate proliferation** -- adds to ExternalOIDC test matrix | Gate is orthogonal to External OIDC. Test the cross-product |
| **Z-stream rollback strips `spec.proxy`** -- CRD pruning during TechPreview | Set `Upgradeable=False`. Document cluster-wide proxy fallback before rollback. Risk disappears at GA |
| **Limited TechPreview CI** | Dedicated periodic job. Graduation bar: 5+ tests, 7+/week, 95%+ pass rate, 14+ days |
| **Proxy credential leakage** | Same model as cluster-wide proxy (credentials in URL). Future: optional `proxyCredentials` SecretNameReference |
| **Support scope creep** -- users may expect per-component proxy for other operators | Scope explicitly to authentication only. Single-component solution, not a framework |

## Open Questions

1. **Should proxy credentials be supported via a Secret reference?** The cluster-wide proxy embeds credentials in the URL. An optional `proxyCredentials` SecretNameReference would improve security. Could be a follow-up enhancement.

2. **Should the operator validate proxy connectivity during config observation?** The current proxy validation controller tests OAuth route `/healthz` reachability via `httpproxy.FromEnvironment()`. Extending to test IdP endpoints through the component proxy is desirable, but the validation target may not be known at operator startup.

3. **Interaction with `unsupportedConfigOverrides`** -- should component proxy settings be overridable via the existing mechanism? Likely yes, for debugging.
