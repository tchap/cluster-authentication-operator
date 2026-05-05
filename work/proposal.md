# Implementation Proposal: Proxy Support for Authentication Resources in Disconnected Environments

**JIRA:** [OCPSTRAT-3174](https://redhat.atlassian.net/browse/OCPSTRAT-3174)
**Date:** 2026-05-05
**Status:** Draft

## Background

This section introduces the authentication architecture for readers who don't work with OpenShift auth day-to-day. It explains what each affected component does, how they relate to each other, and where external network calls happen -- the key concern for proxy support.

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

- **External OIDC mode** -- when the cluster is configured to use an external OIDC provider (instead of the built-in OAuth flow), the OAuth API Server takes on JWT validation directly. Unlike opaque tokens, JWTs *can* be validated cryptographically -- but the OAuth API Server still needs to fetch the provider's public keys (JWKS) and OIDC discovery documents from the external provider. These are **outbound HTTPS calls** that need proxy support. Today, the OAuth API Server has **no proxy injection at all**, not even the cluster-wide proxy. This is a gap (see Finding 1 in the Review Findings section).

### Key concepts

**Identity Provider (IdP):** An external service that authenticates users (e.g., Azure AD, Keycloak, GitHub). The cluster trusts the IdP to verify user identity, and the IdP returns information about the user (name, email, group memberships) after successful authentication.

**OIDC (OpenID Connect):** A protocol built on top of OAuth 2.0 that adds an identity layer. The IdP publishes a discovery document at `/.well-known/openid-configuration` listing its endpoints, and a JWKS document containing the public keys used to sign tokens. Clients (like our OAuth Server or OAuth API Server) fetch these documents to validate tokens. These fetches are outbound HTTPS calls.

**OAuth 2.0 Authorization Code flow:** The standard browser-based login flow. The user's browser is redirected to the IdP, authenticates there, and is redirected back with a short-lived authorization code. The server then exchanges that code for tokens by making a direct server-to-server HTTPS call to the IdP -- this is the call that needs proxy support, since it originates from within the cluster.

**Cluster-wide proxy (`proxy.config.openshift.io/cluster`):** OpenShift's global proxy configuration. When set, operators inject `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables into their operand pods. Go's standard library (`http.ProxyFromEnvironment`) picks these up automatically. The problem: this is all-or-nothing -- it opens egress for every component, not just auth.

**Component-scoped proxy (what this proposal adds):** A proxy configuration that applies only to the three authentication components, without affecting anything else in the cluster. This is the core of OCPSTRAT-3174.

### Where outbound calls happen -- summary

| Outbound call | Component | Protocol | When it happens |
|---|---|---|---|
| OIDC discovery (`/.well-known/openid-configuration`) | CAO (config observation) | HTTPS | When IdP config is created or changed |
| OIDC discovery + JWKS fetch | OAuth API Server (external OIDC mode) | HTTPS | At startup and periodically for key rotation |
| Token exchange (auth code → access token) | OAuth Server | HTTPS | Every user login |
| UserInfo / group membership fetch | OAuth Server | HTTPS | Every user login (OIDC, GitHub, GitLab, Google) |
| LDAP bind and search | OAuth Server | LDAP/LDAPS | Every LDAP user login (not HTTP, not proxy-relevant) |

All HTTP/HTTPS calls in this table are the ones that need proxy support. LDAP uses its own protocol and is out of scope for HTTP proxy configuration.

## Problem Statement

Customers operating OpenShift in restricted or disconnected environments need their authentication components (OAuth server, OAuth API server, cluster-authentication-operator) to reach external Identity Providers (IdPs) through a proxy, **without** configuring a cluster-wide proxy. Today the only mechanism is the global `proxy.config.openshift.io/cluster` resource, which opens egress for *all* components -- an unacceptable security posture when only authentication needs external access.

## Current State

### What already works

| Component | Receives cluster-wide proxy env vars? | Makes outbound IdP calls? |
|-----------|---------------------------------------|---------------------------|
| OAuth Server (`oauth-openshift` Deployment) | **Yes** -- `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` injected via `proxyConfigToEnvVars()` in `pkg/controllers/deployment/default_deployment.go:146` | Yes -- login flows, token exchange, OIDC userinfo |
| OAuth API Server (`oauth-apiserver` Deployment) | **No** -- neither `syncStandardDeployment()` nor `syncExternalOIDCDeployment()` inject proxy env vars | Yes (external OIDC) -- discovery, metadata retrieval |
| Cluster Authentication Operator (CAO process) | Inherits process-level env | Yes -- OIDC discovery during config observation (`discoverOpenIDURLs()` in `idp_conversions.go:315`), proxy config validation |

### Identified gaps

1. **No component-scoped proxy API** -- the only proxy source is the cluster-wide `Proxy` resource.
2. **OAuth API Server has no proxy injection at all** -- a gap even for cluster-wide proxy users.
3. **CAO operator process** uses `http.DefaultTransport` (which respects process env) for IdP discovery, but there is no mechanism to configure per-component proxy settings for this process.
4. **Transport layer** (`pkg/transport/transport.go`) builds custom `http.Transport` instances for CA/TLS but does not configure a proxy function on them.

## Design

### Option A: Extend `operator.openshift.io/v1` Authentication spec (Recommended)

Add an optional `proxy` stanza to the `AuthenticationSpec` in `operator.openshift.io/v1`. This is the operator-level configuration -- the correct place for operand-scoped infrastructure knobs that don't belong on the user-facing `oauth.config.openshift.io` resource.

```go
// In vendor/github.com/openshift/api/operator/v1/types_authentication.go
// (changes go in openshift/api first, then vendored)

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
- Feature-gated behind a new feature gate (`AuthenticationComponentProxy` or similar) to allow phased rollout.

### Option B: Add proxy fields per-IDP on `oauth.config.openshift.io` (Not recommended)

This would add proxy settings to each `IdentityProvider` entry. Rejected because:
- The feature explicitly scopes to *component-level* proxy, not per-IDP.
- Per-IDP proxy is listed as out of scope in the feature requirements.
- It would complicate the OAuth config API surface significantly.

### Option C: Annotations on the Authentication operator resource (Not recommended)

Using annotations avoids an API change but loses validation, discoverability, and documentation. Not suitable for a first-class feature.

## Implementation Plan

The implementation spans three repositories and is broken into phases.

### Phase 1: API Changes (`openshift/api`)

**Files to change:**
- `operator/v1/types_authentication.go` -- add `Proxy *AuthenticationProxyConfig` field and new type
- `operator/v1/zz_generated.deepcopy.go` -- regenerate
- `operator/v1/zz_generated.swagger_doc_generated.go` -- regenerate
- `config/v1/feature_gates.go` -- add `FeatureGateAuthenticationComponentProxy` (TechPreviewNoUpgrade initially)
- Add CRD validation markers for URL format, noProxy format

**Deliverable:** PR to `openshift/api` with the new types, feature gate definition, and generated code.

### Phase 2: Operator Core -- Proxy Resolution Logic (`cluster-authentication-operator`)

#### 2a. Proxy resolution helper

Create a new helper that implements the resolution order:
1. If `Authentication.spec.proxy` is set and non-empty, use it.
2. Otherwise fall back to `proxy.config.openshift.io/cluster` (existing behavior).

```
pkg/controllers/common/proxy.go  (new file)
```

```go
package common

import (
    configv1 "github.com/openshift/api/config/v1"
    operatorv1 "github.com/openshift/api/operator/v1"
)

// ResolveProxyConfig returns proxy settings for authentication components.
// Component-scoped proxy (from the Authentication operator spec) takes
// precedence over the cluster-wide proxy.
func ResolveProxyConfig(
    authSpec *operatorv1.AuthenticationSpec,
    clusterProxy *configv1.Proxy,
) (httpProxy, httpsProxy, noProxy string) {
    if authSpec != nil && authSpec.Proxy != nil {
        p := authSpec.Proxy
        if p.HTTPProxy != "" || p.HTTPSProxy != "" || p.NoProxy != "" {
            return p.HTTPProxy, p.HTTPSProxy, p.NoProxy
        }
    }
    // Fall back to cluster-wide proxy
    if clusterProxy != nil {
        return clusterProxy.Status.HTTPProxy,
               clusterProxy.Status.HTTPSProxy,
               clusterProxy.Status.NoProxy
    }
    return "", "", ""
}
```

#### 2b. Trusted CA bundle syncing

When `spec.proxy.trustedCA` is set, the operator must:
1. Sync the referenced ConfigMap from `openshift-config` to `openshift-authentication` (and `openshift-authentication-operator` for the operator's own use).
2. Mount it into the OAuth server and OAuth API server deployments alongside (or in place of) the cluster-injected trusted CA bundle.

**Files to change:**
- `pkg/operator/starter.go` -- wire the Authentication operator lister, add informer watches
- `pkg/controllers/deployment/deployment_controller.go` -- read `AuthenticationSpec.Proxy`, pass to deployment builder
- Extend resource sync controller to sync the component-scoped trusted CA configmap

#### 2c. OAuth Server deployment injection

**File:** `pkg/controllers/deployment/default_deployment.go`

Change `getOAuthServerDeployment()` to accept resolved proxy values instead of the raw `*configv1.Proxy`. The resolution happens in the controller before calling this function.

```go
// Before (line 29):
func getOAuthServerDeployment(
    operatorSpec *operatorv1.OperatorSpec,
    proxyConfig *configv1.Proxy,
    ...
) (*appsv1.Deployment, error) {

// After:
func getOAuthServerDeployment(
    operatorSpec *operatorv1.OperatorSpec,
    httpProxy, httpsProxy, noProxy string,
    ...
) (*appsv1.Deployment, error) {
```

Update `proxyConfigToEnvVars()` (line 146) to accept raw strings:

```go
func proxyEnvVars(httpProxy, httpsProxy, noProxy string) []corev1.EnvVar {
    var envVars []corev1.EnvVar
    envVars = appendEnvVar(envVars, "NO_PROXY", noProxy)
    envVars = appendEnvVar(envVars, "HTTP_PROXY", httpProxy)
    envVars = appendEnvVar(envVars, "HTTPS_PROXY", httpsProxy)
    return envVars
}
```

**File:** `pkg/controllers/deployment/deployment_controller.go`

In the `sync()` method:
```go
authConfig, err := c.authConfigLister.Get("cluster")
// ...
httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(
    &authConfig.Spec, clusterProxy,
)
deployment, err := getOAuthServerDeployment(
    operatorSpec, httpProxy, httpsProxy, noProxy, ...
)
```

#### 2d. OAuth API Server deployment injection (NEW -- currently missing)

**File:** `pkg/operator/workload/sync_openshift_oauth_apiserver.go`

Both `syncStandardDeployment()` and `syncExternalOIDCDeployment()` need proxy env var injection. This is needed even without the component-scoped proxy feature because the cluster-wide proxy is also not injected today.

Changes:
1. Add `proxyLister` and `authConfigLister` fields to `OAuthAPIServerWorkload`.
2. In both sync functions, after building the deployment:
   ```go
   httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(authSpec, clusterProxy)
   for i := range required.Spec.Template.Spec.Containers {
       required.Spec.Template.Spec.Containers[i].Env = append(
           required.Spec.Template.Spec.Containers[i].Env,
           proxyEnvVars(httpProxy, httpsProxy, noProxy)...,
       )
   }
   ```
3. If component-scoped `trustedCA` is configured, mount the synced CA ConfigMap.

#### 2e. Operator process proxy configuration

The CAO process itself makes outbound HTTP calls during config observation (OIDC discovery in `discoverOpenIDURLs()`). These calls use `transport.TransportForCARef()` which returns an `http.Transport` **without a Proxy function**.

**File:** `pkg/transport/transport.go`

Add a variant that accepts proxy configuration:

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

**File:** `pkg/controllers/configobservation/oauth/idp_conversions.go`

Update `discoverOpenIDURLs()` to accept and use proxy configuration. The proxy values are threaded through from the config observation context which has access to listers.

#### 2f. Proxy validation controller update

**File:** `pkg/controllers/proxyconfig/proxyconfig_controller.go`

Extend the proxy config checker to also validate the component-scoped proxy when configured:
- Test connectivity to IdP endpoints through the component proxy
- Report degraded conditions if the component proxy is misconfigured
- Load CA from the component-scoped `trustedCA` ConfigMap

### Phase 3: Feature Gate and Testing

#### Feature gate

The feature is gated behind `FeatureGateAuthenticationComponentProxy`:
- Initially `TechPreviewNoUpgrade` -- available in TechPreview clusters only.
- Promoted to `Default` once validated.

In the operator, guard the new code paths:

```go
if featureGates.Enabled(features.FeatureGateAuthenticationComponentProxy) {
    // use component-scoped proxy resolution
} else {
    // existing behavior: cluster-wide proxy only
}
```

#### Testing

**Unit tests:**
- `pkg/controllers/common/proxy_test.go` -- test resolution precedence (component > cluster > none)
- `pkg/controllers/deployment/default_deployment_test.go` -- verify env var injection with component proxy
- `pkg/transport/transport_test.go` -- verify proxy function is set on transport

**Integration / E2E tests:**
- Deploy a test proxy (e.g., Squid) in the cluster
- Configure `Authentication.spec.proxy` to point to the test proxy
- Verify OAuth login flow through external IdP succeeds via the proxy
- Verify no cluster-wide proxy is configured
- Verify non-auth components do NOT use the component proxy
- Test fallback: remove component proxy, verify cluster-wide proxy is used
- Test error reporting: configure invalid proxy, verify degraded condition

**File:** `test/e2e/` -- new test file for component proxy scenarios

## Affected Components Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `openshift/api: operator/v1/types_authentication.go` | API addition | Add `Proxy *AuthenticationProxyConfig` to `AuthenticationSpec` |
| `openshift/api: config/v1/feature_gates.go` | Feature gate | Add `FeatureGateAuthenticationComponentProxy` |
| `pkg/controllers/common/proxy.go` | New file | Proxy resolution helper |
| `pkg/controllers/deployment/default_deployment.go` | Modify | Accept resolved proxy strings instead of `*configv1.Proxy` |
| `pkg/controllers/deployment/deployment_controller.go` | Modify | Resolve component proxy, pass to deployment builder |
| `pkg/operator/workload/sync_openshift_oauth_apiserver.go` | Modify | Inject proxy env vars into OAuth API server deployments |
| `pkg/transport/transport.go` | Modify | Add proxy-aware transport constructor |
| `pkg/controllers/configobservation/oauth/idp_conversions.go` | Modify | Thread proxy config through OIDC discovery |
| `pkg/controllers/proxyconfig/proxyconfig_controller.go` | Modify | Validate component-scoped proxy |
| `pkg/operator/starter.go` | Modify | Wire new listers, informer watches, resource sync |
| `bindata/oauth-apiserver/deploy.yaml` | Possibly modify | Add trusted CA volume mount placeholder |
| `bindata/oauth-apiserver/externaloidc-deploy.yaml` | Possibly modify | Add trusted CA volume mount placeholder |
| `oauth-apiserver: pkg/externaloidc/authenticator/jwt/config/configurator.go` | Modify | Build proxy-aware `*http.Client` from env vars, pass via `oidc.Options.Client` (Finding 1) |
| `oauth-apiserver: pkg/externaloidc/oidc/oidc.go` | No change needed | Already passes `Client` through to upstream `k8soidc.Options` |

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

1. `Authentication.spec.proxy` (component-scoped) -- highest priority
2. `proxy.config.openshift.io/cluster` (cluster-wide) -- fallback
3. No proxy -- default when neither is configured

### Status Reporting

The operator reports proxy health through standard operator conditions:

- `ProxyConfigControllerDegraded` -- set when the component proxy is unreachable or misconfigured
- Existing conditions continue to work for cluster-wide proxy validation

## Backward Compatibility

- When `spec.proxy` is `nil` (the default), behavior is identical to today.
- The `proxyConfigToEnvVars()` function signature changes are internal -- no external API break.
- The OAuth API Server proxy injection is a **bug fix** that benefits all users, not just component-proxy users. It should be delivered even if the feature gate is not enabled.

## Review Findings

The following findings are based on a thorough review of this proposal against OCPSTRAT-3174 requirements and the actual codebases of cluster-authentication-operator, oauth-apiserver, and oauth-server.

### Finding 1: Env var injection is insufficient for oauth-apiserver OIDC discovery (Critical)

The proposal assumes injecting `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars into the oauth-apiserver deployment (Phase 2d) will make OIDC discovery work through a proxy. **This is not guaranteed.**

The oauth-apiserver's OIDC authenticator is constructed in `pkg/externaloidc/authenticator/jwt/config/configurator.go:182-186`:

```go
tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
    JWTAuthenticator:  jwt,
    CAContentProvider: caContentProvider,
    Compiler:          compiler,
})
```

The `oidc.Options` struct (in `pkg/externaloidc/oidc/oidc.go:14-50`) accepts an optional `Client *http.Client` field, but **it is not being set**. Whether the upstream Kubernetes OIDC authenticator's default client respects env vars depends on its internal transport construction. If it constructs a custom `http.Transport` for TLS without going through `knet.SetTransportDefaults()`, the proxy env vars will be silently ignored.

Additionally, the oauth-apiserver API types explicitly document this gap (`pkg/externaloidc/apis/authentication/types.go:74`):
> "Note that egress selection configuration is not used for this network connection."

By contrast, the oauth-server is fine -- its `transportFor()` in `pkg/oauthserver/auth.go:774-805` calls `knet.SetTransportDefaults()`, which explicitly sets `Proxy = NewProxierWithNoProxyCIDR(http.ProxyFromEnvironment)`.

**Required action:** The oauth-apiserver needs a code change to pass a proxy-configured `*http.Client` via `oidc.Options.Client`. Env var injection alone is insufficient. This means Phase 2d requires a change to the oauth-apiserver repo, not just the operator. Add this to the Affected Components table and the implementation plan.

### Finding 2: `ResolveProxyConfig` has no "explicitly disable proxy" mechanism (Medium)

The resolution function checks `p.HTTPProxy != "" || p.HTTPSProxy != "" || p.NoProxy != ""`. This creates a gap:

- Setting `spec.proxy: {}` (non-nil but empty struct) silently falls through to the cluster-wide proxy. An admin who sets this intending to **disable** proxy for auth components gets the opposite behavior.
- There is no way to express "use no proxy for auth, even though the cluster has one."

The cluster-wide `Proxy` resource doesn't have this problem because it's a singleton, but a component-scoped override needs an explicit opt-out mechanism.

**Required action:** Add a field to express "no proxy" intent. Options:
- A boolean `disabled` field on `AuthenticationProxyConfig`
- Treating a non-nil but fully empty `Proxy` struct as explicit "no proxy"
- A `mode` enum field (`Custom`, `ClusterWide`, `None`)

### Finding 3: Webhook/group resolution flows should be explicitly addressed (Medium)

The JIRA requirement lists "Webhook/group resolution flows" as requiring proxy support. The proposal doesn't mention these by name. The actual situation:

- **Webhook token review** (KAS → oauth-apiserver at `/apis/oauth.openshift.io/v1/tokenreviews`) is an **internal cluster call**, not an external one. It doesn't need proxy. This should be stated explicitly.
- **Group resolution** happens inside the oauth-server during IdP authentication:
  - GitHub: `getUserOrgs()` and `getUserTeams()` call the GitHub API (`pkg/oauth/external/github/github.go`)
  - OIDC: `fetchUserInfo()` calls the IdP userinfo endpoint (`pkg/oauth/external/openid/openid.go`)
  - All of these use transports created via `transportFor()` → `knet.SetTransportDefaults()` → `http.ProxyFromEnvironment`

Since the oauth-server already picks up env vars through `knet.SetTransportDefaults()`, group resolution is covered by the existing Phase 2c env var injection. This should be called out explicitly in the proposal to demonstrate that the JIRA requirement is fully met.

### Finding 4: Redeployment trigger for proxy changes is unspecified (Medium)

The deployment controller currently hashes the cluster-wide Proxy resource's `ResourceVersion` to trigger rolling updates (`deployment_controller.go:212-213`):

```go
if len(proxyConfig.Name) > 0 {
    resourceVersions = append(resourceVersions, "proxy:"+proxyConfig.Name+":"+proxyConfig.ResourceVersion)
}
```

The proposal doesn't explain how changes to `Authentication.spec.proxy` trigger redeployment. The `Authentication` resource is already watched by the deployment controller, so changes will trigger a sync. However, the deployment hash needs to include the resolved proxy values (or a hash of the proxy stanza), not just the Authentication `ResourceVersion` -- because other spec fields changing would cause unnecessary redeployments if only the top-level ResourceVersion is tracked.

**Required action:** Specify that the resolved proxy values (`httpProxy`, `httpsProxy`, `noProxy`) should be included in the `resourceVersions` hash, e.g.:

```go
resourceVersions = append(resourceVersions,
    "auth-proxy:"+httpProxy+":"+httpsProxy+":"+noProxy)
```

### Finding 5: Operator process proxy threading through config observers is underspecified (Medium)

Section 2e proposes adding `TransportForCARefWithProxy()` for the CAO's own OIDC discovery calls. But the proposal doesn't explain how the proxy config flows through the config observation chain:

1. Config observers in library-go have a specific contract -- observed data flows through `ObservedConfig` maps, not arbitrary parameters.
2. `discoverOpenIDURLs()` is called from config observers. The proxy values need to be threaded from the `Authentication` operator resource through the observer context to the discovery function.
3. If the component-scoped proxy has a custom CA (`trustedCA`), the operator process needs that CA loaded into its transport -- not just the operand deployments. This requires the resource sync controller to also sync the CA ConfigMap into `openshift-authentication-operator`.

**Required action:** Detail the config observer integration pattern. Either:
- Add proxy config to the observer's lister dependencies and pass it through
- Or read the `Authentication` resource directly in `discoverOpenIDURLs()` via a lister

### Finding 6: TrustedCA sync targets and merge behavior are unspecified (Low-Medium)

Section 2b says "sync the referenced ConfigMap from `openshift-config` to `openshift-authentication`" but doesn't specify:

- The exact resource sync controller source/destination mapping
- Target namespaces: `openshift-authentication` (for OAuth server), `openshift-authentication-operator` (for the operator process), and potentially the namespace where oauth-apiserver runs
- How the component-scoped CA interacts with the cluster-wide proxy's injected CA bundle (`trusted-ca-bundle` ConfigMap managed by the network operator). The Risks section says "merged with system trust, not replacing it" but there is no corresponding implementation detail.

**Required action:** Specify the sync mappings and the CA merge strategy (concatenation of PEM bundles, or separate volume mounts).

### Finding 7: OAuth API Server bug fix and feature-gated logic should be separated (Low)

The proposal correctly identifies that the OAuth API Server's lack of cluster-wide proxy injection is a **standalone bug fix** (line 369). However, Phase 2d uses `ResolveProxyConfig()` which includes component-scoped proxy logic. These should be clearly separated in the implementation:

- **Bug fix (un-gated):** Inject cluster-wide proxy env vars into oauth-apiserver deployments, matching what the OAuth server already does. This benefits all users regardless of the feature gate.
- **Feature (gated behind `FeatureGateAuthenticationComponentProxy`):** Upgrade the injection to use `ResolveProxyConfig()` when the feature gate is enabled.

This is correctly separated in the Implementation Order (steps 2 vs 4) but conflated in the Phase 2d implementation details.

### Finding 8: Upgrade/downgrade behavior is not addressed (Low)

If a cluster with `spec.proxy` configured is downgraded to a version without the feature:
- The field is silently ignored by the older operator
- Auth will break if no cluster-wide proxy exists and external IdP connectivity depends on the component proxy
- There is no automatic fallback or warning

**Required action:** Document this as a known limitation. The feature gate graduation criteria should include upgrade/downgrade testing. Consider having the operator set a status condition when `spec.proxy` is configured, so that downgrade pre-flight checks can warn about it.

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| API change requires openshift/api PR and review cycle | Start with API PR early; operator changes can proceed in parallel using vendored types |
| Proxy credentials in `httpProxy`/`httpsProxy` URLs could leak | Use Kubernetes Secrets for proxy auth (future enhancement); document security best practices; proxy URLs are already handled this way for cluster-wide proxy |
| OAuth API Server currently has no proxy at all -- adding it could change behavior for existing clusters | Gate the OAuth API Server proxy injection behind the same resolution logic; when no proxy is configured, no env vars are set (no behavior change) |
| CA bundle conflicts between component and cluster trust | Component `trustedCA` is merged with system trust, not replacing it; follows the same pattern as cluster-wide proxy CA |
| Feature gate lifecycle management | Start as TechPreviewNoUpgrade; clear graduation criteria before promoting to Default |
| Env var injection may not reach oauth-apiserver OIDC transport (see Finding 1) | Pass a proxy-configured `*http.Client` via `oidc.Options.Client` in the oauth-apiserver; env vars alone are insufficient |
| No way to explicitly disable proxy for auth when cluster-wide proxy exists (see Finding 2) | Add a mechanism (e.g. boolean field or empty-struct semantics) to express "no proxy" intent |
| Downgrade breaks auth if component proxy was the only egress path (see Finding 8) | Document as known limitation; add status condition for downgrade pre-flight checks |

## Open Questions

1. **Should proxy credentials be supported via a Secret reference?** The cluster-wide proxy embeds credentials in the URL. We could add an optional `proxyCredentials` SecretNameReference for improved security. This could be a follow-up enhancement.

2. **HCP (Hosted Control Planes) support** is listed as TBD in the feature. The control plane components run in a different namespace/cluster in HCP. This proposal focuses on standalone/SNO/compact topologies first.

3. **Should the operator validate proxy connectivity during configuration observation?** Currently `proxyconfig_controller.go` validates the cluster-wide proxy. The same validation should apply to the component proxy, but the validation target (IdP endpoints) may not be known at operator startup time.

4. **Interaction with `unsupportedConfigOverrides`** -- should component proxy settings be overridable via the existing unsupported config override mechanism? Likely yes, for debugging purposes, but needs explicit documentation.

5. **How should the oauth-apiserver receive proxy configuration?** (from Finding 1) Options: (a) the operator generates the `AuthenticationConfiguration` file with a proxy-aware HTTP client baked in via a sidecar/init-container mechanism, (b) the oauth-apiserver reads proxy env vars and constructs a `*http.Client` to pass via `oidc.Options.Client`, or (c) a code change to the upstream Kubernetes OIDC authenticator to respect env vars by default. Option (b) is the most pragmatic -- a small code change in the oauth-apiserver's `configurator.go` to build a proxy-aware client from env vars and pass it through.

6. **What is the explicit "no proxy" API?** (from Finding 2) Should it be a `disabled bool` field, or should a non-nil empty `Proxy` struct mean "explicitly no proxy"? The latter is more idiomatic for Kubernetes APIs but harder to distinguish from "not yet configured."

## Implementation Order

1. **openshift/api PR** -- API types + feature gate (blocks everything else)
2. **Bug fix: OAuth API Server cluster-wide proxy injection** -- inject cluster-wide proxy env vars into oauth-apiserver deployments (independent of the feature, fixes an existing gap). This is the env-var injection only -- see step 4a for the oauth-apiserver code change.
3. **Proxy resolution helper + OAuth Server integration** -- core logic + OAuth server changes
4. **OAuth API Server integration** -- two parts:
   - 4a. **oauth-apiserver repo change:** Build a proxy-aware `*http.Client` from env vars and pass it via `oidc.Options.Client` in `configurator.go` (required because the upstream OIDC authenticator may not respect env vars -- see Finding 1)
   - 4b. **operator change:** Extend the bug fix to use `ResolveProxyConfig()` when the feature gate is enabled
5. **Operator process proxy** -- transport layer changes for OIDC discovery, including config observer integration
6. **Proxy validation** -- extend proxyconfig controller
7. **E2E tests** -- end-to-end validation
8. **Documentation** -- user-facing docs and troubleshooting guide
