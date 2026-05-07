# Implementation Proposal: Proxy Support for Authentication Resources in Disconnected Environments

**JIRA:** [OCPSTRAT-3174](https://redhat.atlassian.net/browse/OCPSTRAT-3174)
**Date:** 2026-05-07
**Status:** Draft

## Background

This section introduces the authentication architecture for readers who don't work with OpenShift auth day-to-day.

### How OpenShift authentication works

When a user runs `oc login` or opens the OpenShift console, the cluster needs to verify their identity. OpenShift supports many ways to do this -- corporate LDAP, GitHub accounts, Google, generic OIDC providers like Keycloak or Azure AD, and others. These are called **Identity Providers (IdPs)**.

The authentication system has three main components, each running as a separate process in the cluster:

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

The arrows leaving the cluster boundary (►) are the **outbound calls that need proxy support** in disconnected environments.

### Component descriptions

#### Cluster Authentication Operator (CAO)

The CAO is the **control plane** for the authentication subsystem. It is an OpenShift operator that deploys, configures, and monitors both the OAuth Server and the OAuth API Server. It runs in the `openshift-authentication-operator` namespace.

Key responsibilities:
- **Deploys operands** -- creates and updates the Deployment resources for the OAuth Server and OAuth API Server, injecting the correct images, flags, certificates, and environment variables.
- **Observes configuration** -- watches the cluster's `OAuth` config resource (`oauth.config.openshift.io/cluster`) and translates IdP definitions into the format each operand expects. During this process, it makes **outbound OIDC discovery calls** to validate IdP endpoints (e.g., fetching `/.well-known/openid-configuration`).
- **Syncs resources** -- copies secrets, ConfigMaps, and CA bundles from the `openshift-config` namespace (where admins place them) into the operand namespaces where they're consumed.
- **Health checking** -- validates that OAuth routes are reachable, services have endpoints, proxy configuration is correct, and operands are healthy. Reports status via standard ClusterOperator conditions.

The CAO itself makes outbound HTTP calls during config observation, which is why it also needs proxy support.

#### OAuth Server

The OAuth Server is the **user-facing authentication endpoint**. It runs in the `openshift-authentication` namespace as the `oauth-openshift` Deployment. Users interact with it (usually via browser redirect) when they log in.

It implements the OAuth 2.0 Authorization Code flow:
1. User is redirected to the OAuth Server's `/oauth/authorize` endpoint.
2. The OAuth Server redirects the user to the external IdP's login page.
3. After the user authenticates, the IdP redirects back to `/callback/<provider>`.
4. The OAuth Server **exchanges the authorization code for tokens** by calling the IdP's token endpoint (outbound HTTPS call).
5. The OAuth Server **fetches user info and group membership** from the IdP's userinfo endpoint or API (outbound HTTPS call -- e.g., GitHub's `/user/orgs` and `/user/teams` APIs).
6. The OAuth Server issues an OpenShift OAuth access token -- an opaque string in the format `sha256~<random>` -- and stores its SHA256 hash as an `OAuthAccessToken` object in etcd via the OAuth API Server. This is the token that `oc login` saves to `~/.kube/config` and that is sent as `Authorization: Bearer sha256~...` on every subsequent API call. Because it is an opaque random string (not a JWT), every request requires the OAuth API Server to look it up in etcd to validate it (see below).

Supported identity provider types: GitHub, GitLab, Google, OpenID Connect (generic OIDC), LDAP, HTPasswd, Basic Auth (remote), Keystone, and Request Header (external proxy-based auth).

The OAuth Server is the component with the **most outbound calls** to external IdPs. It already receives cluster-wide proxy env vars today.

#### OAuth API Server

The OAuth API Server is the **storage and validation backend**. It runs in the `openshift-oauth-apiserver` namespace and serves the `oauth.openshift.io` API group. It is not user-facing -- other cluster components call it.

Key responsibilities:

- **Token storage** -- OpenShift OAuth tokens are **opaque random strings**, not JWTs. The OAuth Server generates 256 bits of random entropy per token, hashes the value with SHA256, and stores the hash as a Kubernetes `OAuthAccessToken` object in etcd (via the OAuth API Server's REST API). The user receives `sha256~<random>`; the plaintext is never stored. This design enables revocation (delete the object), inactivity timeouts (stateful tracking per token), and user-UID binding (detecting when a user is deleted and recreated with the same name). It also serves `OAuthAuthorizeToken`, `OAuthClient`, and `OAuthClientAuthorization` resources.

- **Token validation (integrated OAuth)** -- because tokens are opaque, they cannot be validated cryptographically. Instead, the kube-apiserver calls the OAuth API Server via a **webhook** on every authenticated request. The flow:
  1. User sends a request with `Authorization: Bearer sha256~<random>`.
  2. KAS forwards a `TokenReview` to `https://<oauth-apiserver>/apis/oauth.openshift.io/v1/tokenreviews`.
  3. The OAuth API Server recomputes `SHA256(<random>)`, looks up the matching `OAuthAccessToken` object in etcd, then runs a validation chain: expiration check, inactivity timeout check, and user-UID check.
  4. If valid, it resolves the user's groups and returns the authenticated identity to KAS.

  This webhook call is **internal** (KAS → OAuth API Server within the cluster), so it does not need proxy support.

- **External OIDC mode** -- when the cluster is configured to use an external OIDC provider (instead of the built-in OAuth flow), the OAuth API Server takes on JWT validation directly. Unlike opaque tokens, JWTs *can* be validated cryptographically -- but the OAuth API Server still needs to fetch the provider's public keys (JWKS) and OIDC discovery documents from the external provider. These are **outbound HTTPS calls** that need proxy support. Today, the OAuth API Server has **no proxy injection at all**, not even the cluster-wide proxy. This is a gap.

### Key concepts

**Identity Provider (IdP):** An external service that authenticates users (e.g., Azure AD, Keycloak, GitHub). The cluster trusts the IdP to verify user identity, and the IdP returns information about the user (name, email, group memberships) after successful authentication.

**OIDC (OpenID Connect):** A protocol built on top of OAuth 2.0 that adds an identity layer. The IdP publishes a discovery document at `/.well-known/openid-configuration` listing its endpoints, and a JWKS document containing the public keys used to sign tokens. Clients (like our OAuth Server or OAuth API Server) fetch these documents to validate tokens. These fetches are outbound HTTPS calls.

**OAuth 2.0 Authorization Code flow:** The standard browser-based login flow. The user's browser is redirected to the IdP, authenticates there, and is redirected back with a short-lived authorization code. The server then exchanges that code for tokens by making a direct server-to-server HTTPS call to the IdP -- this is the call that needs proxy support, since it originates from within the cluster.

**Cluster-wide proxy (`proxy.config.openshift.io/cluster`):** OpenShift's global proxy configuration. When set, operators inject `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables into their operand pods. Go's standard library (`http.ProxyFromEnvironment`) picks these up automatically. The problem: this is all-or-nothing -- it opens egress for every component, not just auth.

**Component-scoped proxy (what this proposal adds):** A proxy configuration that applies only to the three authentication components, without affecting anything else in the cluster. This is the core of OCPSTRAT-3174.

### Where outbound calls happen -- summary

| Outbound call | Component | When it happens | Proxy mechanism today |
|---|---|---|---|
| OIDC discovery | CAO (config observation) | IdP config created/changed | `http.DefaultTransport` (no explicit proxy function) |
| OIDC discovery + JWKS fetch | OAuth API Server (external OIDC mode) | Startup + periodic key rotation | **None -- no proxy env vars injected** |
| Token exchange (auth code → token) | OAuth Server | Every user login | `knet.SetTransportDefaults()` picks up env vars |
| UserInfo / group membership fetch | OAuth Server | Every user login | `knet.SetTransportDefaults()` picks up env vars |
| Webhook/group resolution | OAuth Server (internally) | Every user login | Covered by OAuth Server env vars (groups come from IdP calls in steps above; webhook token review is internal, not external) |
| LDAP bind and search | OAuth Server | LDAP user login | LDAP protocol (not HTTP, out of scope for HTTP proxy) |

## Problem Statement

Customers operating OpenShift in restricted or disconnected environments need their authentication components to reach external Identity Providers through a proxy, **without** configuring a cluster-wide proxy. Today the only mechanism is the global `proxy.config.openshift.io/cluster` resource, which opens egress for *all* components -- an unacceptable security posture when only authentication needs external access.

### Identified gaps

1. **No component-scoped proxy API** -- the only proxy source is the cluster-wide `Proxy` resource.
2. **OAuth API Server has no proxy injection at all** -- a gap even for cluster-wide proxy users. Neither `syncStandardDeployment()` nor `syncExternalOIDCDeployment()` inject proxy env vars.
3. **OAuth API Server OIDC transport ignores env vars** -- even if env vars were injected, the OIDC authenticator in `configurator.go` constructs an `oidc.Options{}` without passing an `*http.Client`, so the upstream Kubernetes OIDC code may not respect `HTTP_PROXY` env vars. The API types explicitly document: "Note that egress selection configuration is not used for this network connection."
4. **CAO operator process** uses `http.DefaultTransport` (which respects process env) for IdP discovery, but there is no mechanism to configure per-component proxy settings for this process.
5. **Transport layer** (`pkg/transport/transport.go`) builds custom `http.Transport` instances for CA/TLS but does not configure a proxy function on them.

## Design

### Option A: Extend `operator.openshift.io/v1` Authentication spec (Recommended)

Add an optional `proxy` stanza to the `AuthenticationSpec` in `operator.openshift.io/v1`. This is the operator-level configuration -- the correct place for operand-scoped infrastructure knobs that don't belong on the user-facing `oauth.config.openshift.io` resource.

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
- The `operator.openshift.io/v1/authentications` resource is the standard place for operator-specific configuration knobs.
- It mirrors the structure of `config.openshift.io/v1 Proxy` for familiarity.
- It is fully optional -- when `nil`, behavior is unchanged (cluster-wide proxy or no proxy).
- It does not touch the cluster-wide proxy API (explicitly out of scope per the feature).
- Feature-gated behind `FeatureGateAuthenticationComponentProxy` to allow phased rollout.

### Design decision: explicit "no proxy" semantics

The resolution function must handle three states: component proxy configured, fall back to cluster proxy, or explicitly no proxy. A non-nil but empty `Proxy` struct should mean "explicitly no proxy for auth, even if the cluster has one" rather than silently falling through to the cluster-wide proxy. This prevents surprises when an admin sets `spec.proxy: {}` intending to disable proxy for auth.

### Rejected alternatives

**Option B: Per-IDP proxy fields on `oauth.config.openshift.io`.** Rejected because the feature scopes to component-level proxy, not per-IDP; per-IDP proxy is explicitly out of scope in OCPSTRAT-3174.

**Option C: Annotations on the Authentication operator resource.** Loses validation, discoverability, and documentation. Not suitable for a first-class feature.

## Implementation Plan

The implementation spans four repositories (`openshift/api`, `cluster-authentication-operator`, `oauth-apiserver`, and potentially `oauth-server`) and is broken into phases.

### Phase 1: API changes (`openshift/api`)

**Files to change:**
- `operator/v1/types_authentication.go` -- add `Proxy *AuthenticationProxyConfig` field and new type
- `operator/v1/zz_generated.deepcopy.go` -- regenerate
- `operator/v1/zz_generated.swagger_doc_generated.go` -- regenerate
- `config/v1/feature_gates.go` -- add `FeatureGateAuthenticationComponentProxy` (TechPreviewNoUpgrade initially)
- Add CRD validation markers for URL format, noProxy format

**Deliverable:** PR to `openshift/api` with the new types, feature gate definition, and generated code.

### Phase 2: Bug fix -- OAuth API Server cluster-wide proxy injection

This is an **independent bug fix** that benefits all users, regardless of the component-proxy feature gate. Today the OAuth API Server receives no proxy env vars at all, which means even the cluster-wide proxy doesn't work for it.

**This phase has two parts:**

**Part A: Operator-side env var injection** (cluster-authentication-operator)

**File:** `pkg/operator/workload/sync_openshift_oauth_apiserver.go`

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

**Part B: oauth-apiserver code change** (oauth-apiserver repo)

Env var injection alone is insufficient. The OIDC authenticator in `pkg/externaloidc/authenticator/jwt/config/configurator.go:182-186` constructs `oidc.Options{}` without passing an `*http.Client`. The `oidc.Options` struct (`pkg/externaloidc/oidc/oidc.go`) supports a `Client *http.Client` field that is forwarded to the upstream Kubernetes OIDC authenticator, but it is not being used.

**Change:** Build a proxy-aware `*http.Client` from env vars and pass it via `oidc.Options.Client`:

```go
// In configurator.go, before creating the authenticator:
httpClient := &http.Client{
    Transport: knet.SetTransportDefaults(&http.Transport{
        TLSClientConfig: tlsConfig, // existing CA config
    }),
}

tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
    JWTAuthenticator:  jwt,
    CAContentProvider: caContentProvider,
    Client:            httpClient,
    Compiler:          compiler,
})
```

### Phase 3: Component-scoped proxy -- core logic (cluster-authentication-operator)

This phase implements the feature-gated component-scoped proxy. All code paths are guarded by `FeatureGateAuthenticationComponentProxy`.

#### 3a. Proxy resolution helper

```
pkg/controllers/common/proxy.go  (new file)
```

```go
// ResolveProxyConfig returns proxy settings for authentication components.
// Component-scoped proxy takes precedence; a non-nil but empty Proxy struct
// means "explicitly no proxy." Falls back to cluster-wide proxy when Proxy is nil.
func ResolveProxyConfig(
    authSpec *operatorv1.AuthenticationSpec,
    clusterProxy *configv1.Proxy,
) (httpProxy, httpsProxy, noProxy string) {
    if authSpec != nil && authSpec.Proxy != nil {
        // Non-nil Proxy means the admin explicitly configured it.
        // Even if all fields are empty, this is intentional ("no proxy").
        return authSpec.Proxy.HTTPProxy,
               authSpec.Proxy.HTTPSProxy,
               authSpec.Proxy.NoProxy
    }
    // Proxy is nil -- fall back to cluster-wide proxy
    if clusterProxy != nil {
        return clusterProxy.Status.HTTPProxy,
               clusterProxy.Status.HTTPSProxy,
               clusterProxy.Status.NoProxy
    }
    return "", "", ""
}
```

#### 3b. Trusted CA bundle syncing

When `spec.proxy.trustedCA` is set, the operator must:
1. Sync the referenced ConfigMap from `openshift-config` to `openshift-authentication` (for the OAuth Server), `openshift-oauth-apiserver` (for the OAuth API Server), and `openshift-authentication-operator` (for the operator process itself).
2. Mount it into the OAuth Server and OAuth API Server deployments.
3. Merge it with system trust (append PEM bundles, don't replace). This follows the same pattern as the cluster-wide proxy CA.

**Files to change:**
- `pkg/operator/starter.go` -- wire the Authentication operator lister, add informer watches, extend resource sync controller
- Extend resource sync controller to sync the component-scoped trusted CA ConfigMap to all three target namespaces

#### 3c. OAuth Server deployment injection

**File:** `pkg/controllers/deployment/default_deployment.go`

Change `getOAuthServerDeployment()` to accept resolved proxy values instead of `*configv1.Proxy`:

```go
// Before:
func getOAuthServerDeployment(operatorSpec *operatorv1.OperatorSpec,
    proxyConfig *configv1.Proxy, ...) (*appsv1.Deployment, error)

// After:
func getOAuthServerDeployment(operatorSpec *operatorv1.OperatorSpec,
    httpProxy, httpsProxy, noProxy string, ...) (*appsv1.Deployment, error)
```

The oauth-server picks up proxy env vars automatically via `knet.SetTransportDefaults()` → `http.ProxyFromEnvironment` in its `transportFor()` function. All IdP transports (GitHub, GitLab, Google, OIDC) go through this path, so env var injection is sufficient for the OAuth Server. This also covers **group resolution flows** (GitHub orgs/teams, OIDC userinfo claims) since those use the same transports.

**File:** `pkg/controllers/deployment/deployment_controller.go`

In the `sync()` method, resolve the proxy and pass it through. Include the resolved proxy values in the deployment hash to trigger redeployments on proxy config changes:

```go
httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(&authConfig.Spec, clusterProxy)
resourceVersions = append(resourceVersions,
    "auth-proxy:"+httpProxy+":"+httpsProxy+":"+noProxy)
```

#### 3d. OAuth API Server deployment injection (upgrade from bug fix)

Extend the Phase 2 bug fix to use `ResolveProxyConfig()` when the feature gate is enabled:

```go
if featureGates.Enabled(features.FeatureGateAuthenticationComponentProxy) {
    httpProxy, httpsProxy, noProxy = common.ResolveProxyConfig(authSpec, clusterProxy)
} else {
    // existing behavior: cluster-wide proxy only (Phase 2 bug fix)
}
```

#### 3e. Operator process proxy configuration

The CAO process itself makes outbound HTTP calls during config observation (OIDC discovery in `discoverOpenIDURLs()` at `idp_conversions.go:315`). These calls use `transport.TransportForCARef()` which returns an `http.Transport` **without a Proxy function**.

**File:** `pkg/transport/transport.go` -- add a variant that accepts proxy configuration:

```go
func TransportForCARefWithProxy(
    cmLister corelistersv1.ConfigMapLister,
    caConfigMapName, key string,
    proxyURL *url.URL,
) (http.RoundTripper, error) {
    // ... build transport as before ...
    if proxyURL != nil {
        transport.Proxy = http.ProxyURL(proxyURL)
    }
    return transport, nil
}
```

**File:** `pkg/controllers/configobservation/oauth/idp_conversions.go` -- update `discoverOpenIDURLs()` to accept and use proxy configuration. The proxy values are obtained by reading the `Authentication` operator resource via a lister added to the observer's dependencies. If the component-scoped `trustedCA` is set, the operator process also needs that CA loaded from the synced ConfigMap in `openshift-authentication-operator`.

#### 3f. Proxy validation controller

**File:** `pkg/controllers/proxyconfig/proxyconfig_controller.go`

Extend the proxy config checker to validate the component-scoped proxy when configured:
- Test connectivity to IdP endpoints through the component proxy
- Report `ProxyConfigControllerDegraded` if the component proxy is misconfigured
- Load CA from the component-scoped `trustedCA` ConfigMap
- Validate that the component `noProxy` includes essential cluster-internal CIDRs (service CIDR, pod CIDR, `.cluster.local`); warn via status condition if entries from the cluster-wide `noProxy` are missing

#### 3g. Upgradeable condition

When `spec.proxy` is configured, the operator should set `Upgradeable=False` on the ClusterOperator to signal that the feature is in use. This prevents accidental upgrade attempts during the TechPreview phase and serves as documentation for pre-flight checks.

### Phase 4: Testing

**Unit tests:**
- `pkg/controllers/common/proxy_test.go` -- resolution precedence (component > cluster > none), explicit disable (empty struct)
- `pkg/controllers/deployment/default_deployment_test.go` -- env var injection with component proxy
- `pkg/transport/transport_test.go` -- proxy function is set on transport

**Integration / E2E tests:**
- Deploy a test proxy (e.g., Squid) in the cluster
- Configure `Authentication.spec.proxy` to point to the test proxy
- Verify OAuth login flow through external IdP succeeds via the proxy
- Verify no cluster-wide proxy is configured
- Verify non-auth components do NOT use the component proxy
- Test fallback: remove component proxy, verify cluster-wide proxy is used
- Test explicit disable: set empty `spec.proxy: {}`, verify no proxy is used even with cluster-wide proxy
- Test error reporting: configure invalid proxy, verify degraded condition
- Test feature gate cross-product: `AuthenticationComponentProxy` × `ExternalOIDC` enabled/disabled

**CI requirements:**
- Create a dedicated periodic CI job running E2E proxy tests on a TechPreview cluster
- Must meet graduation bar: 5+ tests, running 7+ times per week, 95%+ pass rate for 14+ days before branch cut

## Affected Components

| Repository | File | Change |
|---|---|---|
| `openshift/api` | `operator/v1/types_authentication.go` | Add `Proxy *AuthenticationProxyConfig` to `AuthenticationSpec` |
| `openshift/api` | `config/v1/feature_gates.go` | Add `FeatureGateAuthenticationComponentProxy` |
| `cluster-authentication-operator` | `pkg/controllers/common/proxy.go` | New: proxy resolution helper |
| `cluster-authentication-operator` | `pkg/controllers/deployment/default_deployment.go` | Accept resolved proxy strings instead of `*configv1.Proxy` |
| `cluster-authentication-operator` | `pkg/controllers/deployment/deployment_controller.go` | Resolve component proxy, pass to deployment builder, add proxy hash |
| `cluster-authentication-operator` | `pkg/operator/workload/sync_openshift_oauth_apiserver.go` | Inject proxy env vars (bug fix + feature-gated upgrade) |
| `cluster-authentication-operator` | `pkg/transport/transport.go` | Add proxy-aware transport constructor |
| `cluster-authentication-operator` | `pkg/controllers/configobservation/oauth/idp_conversions.go` | Thread proxy config through OIDC discovery |
| `cluster-authentication-operator` | `pkg/controllers/proxyconfig/proxyconfig_controller.go` | Validate component-scoped proxy, check noProxy completeness |
| `cluster-authentication-operator` | `pkg/operator/starter.go` | Wire new listers, informer watches, resource sync for trusted CA |
| `cluster-authentication-operator` | `bindata/oauth-apiserver/deploy.yaml` | Possibly: trusted CA volume mount placeholder |
| `cluster-authentication-operator` | `bindata/oauth-apiserver/externaloidc-deploy.yaml` | Possibly: trusted CA volume mount placeholder |
| `oauth-apiserver` | `pkg/externaloidc/authenticator/jwt/config/configurator.go` | Build proxy-aware `*http.Client`, pass via `oidc.Options.Client` |

## User Experience

### Configuration

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

The referenced ConfigMap must exist in `openshift-config`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-proxy-ca-bundle
  namespace: openshift-config
data:
  ca-bundle.crt: |
    -----BEGIN CERTIFICATE-----
    ...proxy CA certificate...
    -----END CERTIFICATE-----
```

### Precedence

1. `Authentication.spec.proxy` set with values -- use component-scoped proxy
2. `Authentication.spec.proxy` set but empty (`proxy: {}`) -- explicitly no proxy
3. `Authentication.spec.proxy` absent (`nil`) -- fall back to `proxy.config.openshift.io/cluster`
4. Neither configured -- no proxy

### Status reporting

The operator reports proxy health through standard operator conditions:

- `ProxyConfigControllerDegraded` -- set when the component proxy is unreachable or misconfigured
- `Upgradeable=False` -- set when `spec.proxy` is configured (during TechPreview phase)
- Existing conditions continue to work for cluster-wide proxy validation
- Resolved proxy configuration (component vs. cluster, with the active values) is surfaced in operator status or deployment annotations for debugging

## Backward Compatibility

- When `spec.proxy` is `nil` (the default), behavior is identical to today.
- The `proxyConfigToEnvVars()` function signature changes are internal -- no external API break.
- The OAuth API Server proxy injection (Phase 2) is a **bug fix** that benefits all users. When no proxy is configured, no env vars are set (no behavior change).

## Scope and Topology

### Supported topologies

- **Standalone OpenShift** (multi-node, compact, SNO) -- fully supported, primary target
- **Restricted/disconnected networks** -- the motivating use case

### HyperShift (Hosted Control Planes) -- not supported initially

HyperShift uses a completely different deployment model for authentication:

| Aspect | Standalone OpenShift | HyperShift |
|---|---|---|
| Who deploys auth components? | CAO | HyperShift control-plane-operator, directly |
| Does CAO run? | Yes | **No** -- explicitly excluded from CVO payload |
| Where do auth pods run? | Hosted cluster | Management cluster's HCP namespace |
| Proxy mechanism | Env vars from cluster-wide `Proxy` | Konnectivity tunneling + `HostedCluster.spec.configuration.proxy` |

The CAO does not run in HyperShift, so `Authentication.spec.proxy` has no effect. HyperShift already has proxy support for auth via `HostedCluster.spec.configuration.proxy` and konnectivity sidecar injection (`InjectKonnectivityContainer()` with dual SOCKS5/HTTP CONNECT mode). HyperShift's `idp_convert.go:683-754` already builds proxy-aware HTTP transports for OIDC discovery -- essentially what Phase 3e proposes for standalone.

**For the initial release:**
- Document `Authentication.spec.proxy` as unsupported on HCP
- Consider a validation webhook to reject the field on HyperShift-managed clusters
- HyperShift users should use `HostedCluster.spec.configuration.proxy` (cluster-wide within the hosted cluster scope)

**Future HCP support** would require a HyperShift-side change to read the field and thread it into its deployment logic. The transport plumbing already exists; only the API wiring is missing.

## Risks and Mitigations

Risks are informed by code analysis and by precedent from existing OpenShift enhancement proposals: [Global Cluster Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/proxy/global-cluster-egress-proxy.md), [Windows Node Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/windows-containers/windows-node-egress-proxy.md), [Direct External OIDC Provider](https://github.com/openshift/enhancements/blob/master/enhancements/authentication/direct-external-oidc-provider.md), [AuthConfig Missing Fields](https://github.com/openshift/enhancements/blob/master/enhancements/authentication/AuthConfig-missing-fields.md), and [IBM Service Endpoint Dynamic Override](https://github.com/openshift/enhancements/blob/master/enhancements/cloud-integration/ibm/service-endpoint-dynamic-override.md).

### Implementation risks

| Risk | Mitigation |
|------|------------|
| API change requires openshift/api PR and review cycle | Start with API PR early; operator changes can proceed in parallel using vendored types |
| Env var injection alone does not reach the oauth-apiserver OIDC transport | Pass a proxy-configured `*http.Client` via `oidc.Options.Client` in the oauth-apiserver (Phase 2B) |
| CA bundle conflicts between component and cluster trust | Component `trustedCA` is appended to system trust (PEM concatenation), not replacing it; follows cluster-wide proxy CA pattern |
| OAuth API Server proxy injection could change behavior for existing clusters | When no proxy is configured, no env vars are set (no behavior change). Bug fix (Phase 2) is un-gated; component proxy (Phase 3d) is feature-gated |
| `Authentication.spec.proxy` is silently ignored on HyperShift | Document as unsupported; consider validation webhook. HyperShift users should use `HostedCluster.spec.configuration.proxy` |

### Operational risks

| Risk | Mitigation |
|------|------------|
| **Cluster bricking from invalid proxy config** -- misconfigured proxy URL can make OAuth unreachable, locking all users out. The Global Egress Proxy EP noted proxy validation is "very limited, so this risk cannot be eliminated." | Validate connectivity to at least one IdP endpoint through the component proxy before applying. Report `ProxyConfigControllerDegraded` on failure. Document recovery: edit the `Authentication` CR via `kubeadmin` or client cert auth to remove `spec.proxy`. |
| **Proxy as untrusted intermediary** -- malicious or mis-pointed proxy could intercept auth traffic (authorization codes, tokens, user info) | Document that the proxy is in the trust path. `trustedCA` pins the proxy TLS certificate. Same trust model as cluster-wide proxy. |
| **Network dependency in auth path** -- proxy adds a failure point; if down, all authentication fails | Not a new class of failure (cluster-wide proxy has the same property). Document that the proxy must be highly available. Set `Degraded` when unreachable. |
| **Debugging and support complexity** -- component proxy differing from cluster proxy makes support cases harder (per Windows Node Proxy EP) | Surface resolved proxy config in operator status and deployment annotations so `oc adm inspect` / must-gather captures which proxy is active. Document resolution precedence. |
| **noProxy conflict between component and cluster proxy** -- users must reconcile settings correctly (per IBM Endpoint Override EP) | Validate that component `noProxy` includes essential cluster-internal CIDRs. Warn via status condition if entries from cluster-wide `noProxy` are missing. |
| **SNO disruption during proxy config rollout** -- SNO has only one OAuth server instance | Same behavior as any OAuth server config change on SNO. Document that `spec.proxy` changes trigger a rolling restart with brief auth outage on SNO. |

### Lifecycle risks

| Risk | Mitigation |
|------|------------|
| **Feature gate proliferation** -- auth operator already gates ExternalOIDC + variants; adding another compounds the test matrix | Ensure the gate is orthogonal to External OIDC gates. Test the cross-product of `AuthenticationComponentProxy` × `ExternalOIDC`. |
| **Z-stream rollback deletes `spec.proxy` from etcd** -- during TechPreview, a z-stream rollback to a version without the field causes CRD schema pruning to permanently strip the field on the next CR mutation, breaking auth if no cluster-wide proxy exists | Blast radius limited to TechPreview clusters doing z-stream rollbacks. Set `Upgradeable=False` when `spec.proxy` is set. Document that admins must configure a cluster-wide proxy fallback before rolling back. Risk disappears when the feature graduates to Default (field present in all z-stream CRD schemas). |
| **Limited CI validation during TechPreview** -- TechPreview features are not exercised in default CI runs (per OpenShift supportability guidelines) | Create dedicated periodic CI job. Must meet graduation bar: 5+ tests, 7+/week, 95%+ pass rate for 14+ days. |
| **Proxy credential leakage** | Credentials in proxy URLs follow the same model as cluster-wide proxy. Future enhancement: optional `proxyCredentials` SecretNameReference. |
| **Support scope creep** -- users may expect per-component proxy for other operators (per External OIDC UID EP) | Scope explicitly to authentication only. This is a single-component solution, not a framework. |

## Open Questions

1. **Should proxy credentials be supported via a Secret reference?** The cluster-wide proxy embeds credentials in the URL. An optional `proxyCredentials` SecretNameReference would improve security. Could be a follow-up enhancement.

2. **How should the oauth-apiserver construct the proxy-aware HTTP client?** Options: (a) read proxy env vars and build the client in `configurator.go` (most pragmatic), (b) add a sidecar/init-container mechanism, (c) change the upstream Kubernetes OIDC authenticator to respect env vars by default. Recommend option (a).

3. **Should the operator validate proxy connectivity during config observation?** The proxy validation controller currently validates the cluster-wide proxy. The same should apply to the component proxy, but the validation target (IdP endpoints) may not be known at operator startup.

4. **Interaction with `unsupportedConfigOverrides`** -- should component proxy settings be overridable via the existing unsupported config override mechanism? Likely yes, for debugging.

## Implementation Order

1. **openshift/api PR** -- API types + feature gate (blocks everything else)
2. **Bug fix: OAuth API Server proxy** -- two PRs, can be parallel:
   - Operator: inject cluster-wide proxy env vars into oauth-apiserver deployments (un-gated)
   - oauth-apiserver: build proxy-aware `*http.Client` from env vars, pass via `oidc.Options.Client`
3. **Proxy resolution helper + OAuth Server** -- core `ResolveProxyConfig()` logic + OAuth Server deployment changes (feature-gated)
4. **OAuth API Server component proxy** -- extend the bug fix to use `ResolveProxyConfig()` when feature gate is enabled
5. **Operator process proxy** -- transport layer changes for OIDC discovery, config observer integration, trusted CA sync to operator namespace
6. **Proxy validation + Upgradeable condition** -- extend proxyconfig controller, set `Upgradeable=False`
7. **E2E tests + CI job** -- end-to-end validation with dedicated periodic job
8. **Documentation** -- user-facing docs, troubleshooting guide, HCP unsupported notice
