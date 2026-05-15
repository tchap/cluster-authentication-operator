# Implementation Proposal: Proxy Support for Authentication Resources in Disconnected Environments

**JIRA:** [OCPSTRAT-3174](https://redhat.atlassian.net/browse/OCPSTRAT-3174)
**Date:** 2026-05-11
**Status:** Draft

## Background

OpenShift authentication has two components that make outbound calls to external Identity Providers (IdPs): the Cluster Authentication Operator and the OAuth Server. In disconnected environments, these calls must go through a proxy -- but today the only mechanism is the cluster-wide `proxy.config.openshift.io/cluster`, which opens egress for *all* components.

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
                        │  └───────────────────────────────────────────────┘  │
                        └─────────────────────────────────────────────────────┘
```

The arrows leaving the cluster boundary (►) are the outbound calls that need proxy support.

### Components and their outbound calls

**Cluster Authentication Operator (CAO)** -- the control plane. Deploys, configures, and monitors both operands. Makes outbound OIDC discovery calls (`/.well-known/openid-configuration`) during config observation to validate IdP endpoints. Uses `transport.TransportForCARef()` → `net.SetTransportDefaults()`, which respects proxy env vars injected by CVO from the cluster-wide proxy.

**OAuth Server** (`oauth-openshift` Deployment) -- the user-facing authentication endpoint. Implements OAuth 2.0 Authorization Code flow: redirects users to the external IdP, exchanges auth codes for tokens, fetches user info and group membership (GitHub orgs/teams, OIDC userinfo claims). Supports GitHub, GitLab, Google, OIDC, LDAP, HTPasswd, Basic Auth, Keystone, and Request Header IdPs. The component with the most outbound calls. Uses `knet.SetTransportDefaults()` → `http.ProxyFromEnvironment`, so it picks up proxy env vars automatically.

**OAuth API Server** -- the storage and validation backend. Stores opaque OAuth tokens (`sha256~<random>` hashed with SHA256) as `OAuthAccessToken` objects in etcd. Validates tokens via webhook from kube-apiserver (internal, no proxy needed). In **External OIDC mode** (itself still feature-gated), the OAuth API Server can fetch JWKS and discovery documents from external providers, but this egress path is gated behind the `external-oidc` subcommand and is **out of scope** for this proposal -- proxy support for it can be added when External OIDC graduates.

### Where outbound calls happen

| Outbound call | Component | When | Proxy today |
|---|---|---|---|
| OIDC discovery | CAO | IdP config change | `net.SetTransportDefaults()` (process env vars; no component-scoped override) |
| Token exchange | OAuth Server | Every login | `knet.SetTransportDefaults()` (env vars) |
| UserInfo / groups | OAuth Server | Every login | `knet.SetTransportDefaults()` (env vars) |

## Problem Statement

Customers in restricted environments need auth components to reach external IdPs through a proxy **without** configuring a cluster-wide proxy, which opens egress for all components.

### Current workarounds

There is no mechanism between "no proxy" and "proxy for everything." Customers working around this today have three options, none of which are satisfactory:

1. **Cluster-wide proxy + network policy** -- enable the cluster-wide proxy, then use `NetworkPolicy` or `EgressFirewall` (OVN-Kubernetes) to restrict which pods can reach the proxy endpoint. Only auth pods get network-level egress to the proxy; everything else is blocked. This works but is fragile -- every component is configured with proxy settings, and a separate mechanism prevents most of them from using it.

2. **Cluster-wide proxy + restrictive proxy ACLs** -- configure the cluster-wide proxy but lock down the proxy server itself to only forward traffic to IdP domains. Every component receives the env vars and attempts to use the proxy, but only auth-related traffic is allowed through. This leaks intent and generates noise from failed proxy connections in non-auth components.

3. **Manual env var injection** -- skip the cluster-wide proxy API entirely and patch the OAuth Server and operator deployments directly with proxy env vars. This is unsupported, breaks on upgrades when the CVO reconciles the deployments, and doesn't survive operator-managed redeployments.

### Identified gaps

1. **No component-scoped proxy API** -- the only proxy source is the cluster-wide `Proxy` resource.
2. **CAO and transport layer have no component-scoped proxy override** -- `transport.TransportForCARef()` delegates to `net.SetTransportDefaults()`, which **does** set `Proxy = http.ProxyFromEnvironment` -- so the transport respects proxy env vars injected by CVO from the cluster-wide proxy. But there is no mechanism to override these with component-scoped settings. When no cluster-wide proxy is configured, there are no env vars to read.

## Design

### API: Extend `operator.openshift.io/v1` Authentication spec

Add an optional `proxy` stanza to `AuthenticationSpec` in `operator.openshift.io/v1`. This is the operator-level configuration -- the correct place for operand-scoped infrastructure knobs.

```go
// In openshift/api: operator/v1/types_authentication.go

type AuthenticationSpec struct {
    OperatorSpec `json:",inline"`

    // proxy configures proxy settings specifically for authentication
    // components (OAuth server and the operator itself).
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
    // An empty string means no HTTP proxy is used.
    // +required
    HTTPProxy *string `json:"httpProxy"`

    // httpsProxy is the URL of the proxy for HTTPS requests.
    // An empty string means no HTTPS proxy is used.
    // +required
    HTTPSProxy *string `json:"httpsProxy"`

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

**Precedent:** every `operator.openshift.io/v1` resource embeds the base `OperatorSpec` inline and extends it with component-specific fields. This is the standard pattern for operand-scoped configuration that doesn't belong in the cluster-wide `config.openshift.io` APIs. Examples:

- [**Console**](https://github.com/openshift/api/blob/master/operator/v1/types_console.go#L36) -- embeds `OperatorSpec` and adds `customization`, `providers`, `route`, `plugins`, and `ingress` to control console operand behavior.
- [**Network**](https://github.com/openshift/api/blob/master/operator/v1/types_network.go#L58) -- embeds `OperatorSpec` and adds `clusterNetwork`, `serviceNetwork`, `defaultNetwork`, and extensive CNI-specific configuration.
- [**ClusterCSIDriver**](https://github.com/openshift/api/blob/master/operator/v1/types_csi_cluster_driver.go#L94) -- embeds `OperatorSpec` and adds `storageClassState`, `driverConfig`, and other CSI driver knobs.
- [**MachineConfiguration**](https://github.com/openshift/api/blob/master/operator/v1/types_machineconfiguration.go#L40) -- embeds `StaticPodOperatorSpec` and adds `managedBootImages`, `nodeDisruptionPolicy`, and other machine config fields.

The Authentication operator spec has been unusually bare (no additional fields beyond `OperatorSpec` until now), so this is a natural extension.

### Proxy resolution semantics

The resolution function handles three states. Since `httpProxy` and `httpsProxy` are required `*string` fields, a non-nil `Proxy` struct always has both fields present. Setting them to empty strings means "explicitly no proxy for auth, even if the cluster has one."

1. `spec.proxy` set with non-empty values → use component-scoped proxy
2. `spec.proxy` set with empty strings (`httpProxy: ""`, `httpsProxy: ""`) → explicitly no proxy
3. `spec.proxy` absent (`nil`) → fall back to `proxy.config.openshift.io/cluster`
4. Neither configured → no proxy

### Rejected alternatives

**Per-IDP proxy fields on `oauth.config.openshift.io`:** Feature scopes to component-level, not per-IDP (explicitly out of scope in OCPSTRAT-3174).

**Annotations on the Authentication operator resource:** Loses validation, discoverability, and documentation.

## Implementation Plan

The implementation spans two repositories (`openshift/api`, `cluster-authentication-operator`) and is broken into phases.

### Phase 1: API changes (`openshift/api`)

- `operator/v1/types_authentication.go` -- add `Proxy *AuthenticationProxyConfig` field and type
- `operator/v1/zz_generated.deepcopy.go`, `zz_generated.swagger_doc_generated.go` -- regenerate
- `config/v1/feature_gates.go` -- add `FeatureGateAuthenticationComponentProxy` (TechPreviewNoUpgrade)
- Add CRD validation markers for URL format, noProxy format

### Phase 2: Component-scoped proxy (cluster-authentication-operator)

All code paths guarded by `FeatureGateAuthenticationComponentProxy`.

#### Affected controllers and components

| Controller / Component | File(s) | Role | What changes |
|---|---|---|---|
| **Proxy resolution helper** | `pkg/controllers/common/proxy.go` (new) | Resolves effective proxy config: component-scoped > cluster-wide > none | New `ResolveProxyConfig()` function used by all other controllers |
| **Deployment controller** | `pkg/controllers/deployment/deployment_controller.go`, `default_deployment.go` | Builds and reconciles the OAuth Server Deployment; injects `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars into the pod spec | Call `ResolveProxyConfig()` instead of reading the cluster-wide proxy directly; include resolved proxy in deployment hash to trigger rollouts on change |
| **Config observation (IDP conversions)** | `pkg/controllers/configobservation/oauth/idp_conversions.go` | Runs OIDC discovery (`discoverOpenIDURLs()`) to validate IdP endpoints during config observation | Use new `TransportForCARefWithProxy()` so discovery calls go through the component-scoped proxy |
| **Transport layer** | `pkg/transport/transport.go` | Builds `http.RoundTripper` for outbound calls from the operator process | Add `TransportForCARefWithProxy()` variant that overrides the env-var-based proxy with a caller-supplied proxy URL |
| **Proxy validation controller** | `pkg/controllers/proxyconfig/proxyconfig_controller.go` | Validates proxy connectivity by testing the OAuth route's `/healthz` endpoint | Also validate the component-scoped proxy; test IdP connectivity; load component `trustedCA`; warn on missing `noProxy` entries |
| **Trust distribution controller** | `pkg/controllers/trustdistribution/trustdistribution_controller.go` | PEM read/filter/write for CA bundles distributed to operands | Under Option B (server-side merge): merge injected system trust with component-scoped proxy CA into a single ConfigMap. Under Option A: no changes (entrypoint handles merge) |
| **Resource sync (starter wiring)** | `pkg/operator/starter.go` | Syncs ConfigMaps/Secrets from `openshift-config` into operand namespaces | Sync the component-scoped `trustedCA` ConfigMap into `openshift-authentication` and `openshift-authentication-operator` |
| **OAuth Server deployment manifest** | `bindata/oauth-openshift/deployment.yaml` | Deployment template for the OAuth Server pods | Add volume/mount for component CA (Option A: also extend entrypoint); update hash annotations |

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

#### 2a. Proxy resolution helper

New file: `pkg/controllers/common/proxy.go`

```go
func ResolveProxyConfig(
    authSpec *operatorv1.AuthenticationSpec,
    clusterProxy *configv1.Proxy,
) (httpProxy, httpsProxy, noProxy string) {
    if authSpec != nil && authSpec.Proxy != nil {
        return authSpec.Proxy.HTTPProxy,
               authSpec.Proxy.HTTPSProxy,
               mergeNoProxy(authSpec.Proxy.NoProxy)
    }
    if clusterProxy != nil {
        return clusterProxy.Status.HTTPProxy,
               clusterProxy.Status.HTTPSProxy,
               clusterProxy.Status.NoProxy
    }
    return "", "", ""
}
```

**Auto-populated `noProxy` entries.** Following the precedent set by the [Global Cluster Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/proxy/global-cluster-egress-proxy.md), the operator auto-appends cluster-internal addresses to the user-provided `noProxy` value when `spec.proxy` is set. This prevents auth components from accidentally routing internal traffic through the proxy.

Auto-appended entries (deduplicated against user-provided values):
- `.cluster.local`, `.svc`, `localhost`, `127.0.0.1`

The CNO's `MergeUserSystemNoProxy()` additionally appends service/pod/machine network CIDRs, the internal API hostname, and platform-specific metadata IPs. These are omitted here because auth components connect to internal services via DNS names (`kubernetes.default.svc`, etc.) which are already covered by `.svc` and `.cluster.local`. The OAuth Server's kube client uses in-cluster config, not raw CIDRs or the `api-int` hostname. Network CIDRs would require adding `Network` and `Infrastructure` informers/listers across multiple controllers for no practical benefit to auth workloads.

#### 2b. Trusted CA bundle syncing

**How the cluster-wide proxy CA works today:** The cluster-network-operator's CA bundle injector watches for ConfigMaps labeled `config.openshift.io/inject-trusted-cabundle: "true"` and populates their `ca-bundle.crt` key with system trust + cluster-wide proxy CA already merged. The OAuth Server (`bindata/oauth-openshift/deployment.yaml:62-64`) mounts this ConfigMap and the entrypoint copies the bundle to the system trust path:

```bash
cp -f .../ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
```

The component-scoped `trustedCA` ConfigMap is admin-provided and won't be processed by the CA bundle injector (no label), so the operator must handle merging.

**When `spec.proxy.trustedCA` is set**, the component CA must be merged with the existing trust chain (system trust + cluster-wide proxy CA). Two approaches are under consideration:

**Option A: Entrypoint append.** Sync the component CA ConfigMap as-is, mount it as an additional volume, and extend the container entrypoint to concatenate it after the existing system trust copy:

1. **Sync** the referenced ConfigMap from `openshift-config` to the operand namespace and operator namespace via the resource sync controller (same pattern as other config syncs in `starter.go`).

2. **Mount** it as an additional volume in the OAuth Server deployment (e.g., at `/var/config/system/configmaps/auth-proxy-ca`).

3. **Append to system trust** by extending the container entrypoint:

    ```bash
    if [ -s /var/config/system/configmaps/auth-proxy-ca/ca-bundle.crt ]; then
        cat /var/config/system/configmaps/auth-proxy-ca/ca-bundle.crt \
            >> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    fi
    ```

    This runs after the existing `cp -f` of the injected system trust bundle, so the result is system trust + cluster-wide proxy CA + component-scoped proxy CA.

4. **CAO process**: load the component CA into the cert pool in `TransportForCARefWithProxy()` (Phase 2d) and in the proxy validation controller's `getCACerts()` (which already uses `AppendCertsFromPEM` to load from a configurable set of ConfigMaps).

5. **Deployment hash tracking**: include the component CA ConfigMap's ResourceVersion so changes trigger rollouts. The OAuth Server controller already watches all `v4-0-config-*` ConfigMaps by prefix (`deployment_controller.go:304`); add the component CA ConfigMap to that set.

Files to change: `starter.go` (resource sync), `bindata/oauth-openshift/deployment.yaml` (volume/mount + entrypoint), `deployment_controller.go` (hash tracking).

**Option B: Server-side merge.** The operator reads both the injected system trust ConfigMap and the component CA, concatenates the PEM content, and writes a pre-merged ConfigMap to the operand namespace. Pods get a single ConfigMap with everything already merged -- no entrypoint or volume mount changes.

1. **Sync** the component CA ConfigMap from `openshift-config` to the operator namespace (for reading).

2. **Merge controller**: extend the `trustdistribution` controller (which already does PEM read/filter/write in `trustdistribution_controller.go:97-105`) or create a new controller that:
   - Reads the injected system trust ConfigMap (e.g., `v4-0-config-system-trusted-ca-bundle` in `openshift-authentication`)
   - Reads the synced component CA ConfigMap
   - Concatenates PEM bundles
   - Writes the result to a new ConfigMap (e.g., `merged-trusted-ca-bundle`) in the operand namespace
   - Must not write back to the injected ConfigMap -- the CA bundle injector would overwrite it

3. **Update deployment volumes** to reference the merged ConfigMap instead of the injected one. No entrypoint changes needed -- the existing `cp -f` picks up the merged bundle.

4. **CAO process**: same as Option A (load component CA in cert pools).

5. **Watch both sources**: re-merge and trigger rollout when either the injected bundle or the component CA changes.

Files to change: `starter.go` (resource sync + merge controller wiring), `trustdistribution_controller.go` or new controller (merge logic), `deployment.yaml` (volume source name only), `deployment_controller.go` (hash tracking for merged ConfigMap).

**Tradeoffs:**

| | Option A: Entrypoint append | Option B: Server-side merge |
|---|---|---|
| Entrypoint changes | Yes | No |
| Deployment YAML changes | Add volume/mount + entrypoint | Change volume source name |
| New controller code | No | Yes -- reconciliation loop |
| Failure mode | Straightforward -- pod has both files or it doesn't | Must handle ordering: merged ConfigMap must be ready before pod starts; changes to either source must trigger re-merge then rollout |
| Existing pattern in repo | Entrypoint `cp -f` already exists | `trustdistribution_controller.go` already does PEM processing |

#### 2c. OAuth Server deployment injection

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

#### 2d. Operator process proxy configuration

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

#### 2e. Proxy validation controller

**`pkg/controllers/proxyconfig/proxyconfig_controller.go`**

The current controller reads proxy from process env vars (`httpproxy.FromEnvironment()`) and validates that the OAuth route's `/healthz` endpoint is reachable. When external OIDC is configured, the check is skipped entirely.

Extend to validate the component-scoped proxy:
- Test connectivity to IdP endpoints through the component proxy (see below)
- Report `ProxyConfigControllerDegraded` if misconfigured
- Load CA from the component-scoped `trustedCA` ConfigMap

**IdP endpoint validation.** Following the [Global Cluster Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/proxy/global-cluster-egress-proxy.md) precedent of validating proxy connectivity before accepting configuration, the controller should test that configured IdP endpoints (extracted from `oauth.config.openshift.io/cluster`) are reachable through the component proxy. However, unlike the cluster-wide proxy's validation endpoints (which are cluster-controlled), external IdP endpoints can experience transient outages, rate-limiting, or geo-restrictions unrelated to proxy configuration. To avoid noisy false positives:
- Validate IdP connectivity on **configuration change only** (not on every sync loop)
- **Emit an event** (not a condition) for transient IdP unreachability — visible via `oc get events` without polluting operator conditions
- Report `Degraded` only for proxy-level failures (connection refused, TLS handshake errors with the proxy itself)

### Phase 3: Testing

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

**Status reporting:** `ProxyConfigControllerDegraded` when proxy is unreachable. Resolved proxy config surfaced in operator status / deployment annotations for `oc adm inspect` / must-gather.

**Backward compatibility:** When `spec.proxy` is `nil`, behavior is identical to today.

## Scope and Topology

**Supported:** Standalone OpenShift (multi-node, compact, SNO), restricted/disconnected networks.

**OAuth API Server (External OIDC mode):** The OAuth API Server's outbound calls (JWKS/discovery fetches) only exist in External OIDC mode, which is itself still feature-gated behind the `external-oidc` subcommand. Proxy support for this code path is out of scope and can be added when External OIDC graduates.

**HyperShift (Hosted Control Planes) -- not supported initially.** The CAO does not run in HyperShift (explicitly excluded from CVO payload). Auth pods run in the management cluster's HCP namespace. HyperShift already has proxy support via `HostedCluster.spec.configuration.proxy` and konnectivity sidecar injection (`InjectKonnectivityContainer()` with dual SOCKS5/HTTP CONNECT mode). HyperShift's `idp_convert.go:683-754` already builds proxy-aware HTTP transports for OIDC discovery -- essentially what Phase 2d proposes for standalone. For the initial release: document as unsupported on HCP; consider a validation webhook to reject the field. Future HCP support would require a HyperShift-side change to read the field -- the transport plumbing already exists.

## Risks and Mitigations

Informed by code analysis and by precedent from existing enhancement proposals: [Global Cluster Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/proxy/global-cluster-egress-proxy.md), [Windows Node Egress Proxy](https://github.com/openshift/enhancements/blob/master/enhancements/windows-containers/windows-node-egress-proxy.md), [Direct External OIDC Provider](https://github.com/openshift/enhancements/blob/master/enhancements/authentication/direct-external-oidc-provider.md), [AuthConfig Missing Fields](https://github.com/openshift/enhancements/blob/master/enhancements/authentication/AuthConfig-missing-fields.md), and [IBM Service Endpoint Dynamic Override](https://github.com/openshift/enhancements/blob/master/enhancements/cloud-integration/ibm/service-endpoint-dynamic-override.md).

### Implementation risks

| Risk | Mitigation |
|------|------------|
| API change requires openshift/api PR and review cycle | Start with API PR early; operator changes proceed in parallel using vendored types |
| CA bundle conflicts between component and cluster trust | Component `trustedCA` is appended to system trust (PEM concatenation), not replacing it |
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
| **Feature gate proliferation** -- adds to test matrix | Gate is orthogonal to External OIDC |
| **Z-stream rollback strips `spec.proxy`** -- CRD pruning during TechPreview | The TechPreviewNoUpgrade feature gate set prevents upgrades. Document cluster-wide proxy fallback before rollback. Risk disappears at GA |
| **Limited TechPreview CI** | Dedicated periodic job. Graduation bar: 5+ tests, 7+/week, 95%+ pass rate, 14+ days |
| **Proxy credential leakage** | Same model as cluster-wide proxy (credentials in URL). Future: optional `proxyCredentials` SecretNameReference |
| **Support scope creep** -- users may expect per-component proxy for other operators | Scope explicitly to authentication only. Single-component solution, not a framework |

## Open Questions

1. **Should proxy credentials be supported via a Secret reference?** The cluster-wide proxy embeds credentials in the URL. An optional `proxyCredentials` SecretNameReference would improve security. Could be a follow-up enhancement.
