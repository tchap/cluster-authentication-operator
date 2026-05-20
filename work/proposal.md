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

There is no mechanism between "no proxy" and "proxy for everything." Customers working around this today have several options, none of which are satisfactory:

1. **Cluster-wide proxy + restrictive proxy ACLs** -- configure the cluster-wide proxy but lock down the proxy server itself to only forward traffic to IdP domains. Every component receives the env vars and attempts to use the proxy, but only auth-related traffic is allowed through. This leaks intent and generates noise from failed proxy connections in non-auth components.

2. **Cluster-wide proxy + network policy** -- enable the cluster-wide proxy, then use `NetworkPolicy` or `EgressFirewall` (OVN-Kubernetes) to restrict which pods can reach the proxy endpoint. Only auth pods get network-level egress to the proxy; everything else is blocked. This works but is fragile -- every component is configured with proxy settings, and a separate mechanism prevents most of them from using it.

3. **Internal IdP federation** -- deploy an internal identity provider (e.g., Keycloak) that federates to the external IdP, and only allow the internal IdP to reach the outside network. This adds significant operational overhead: a full identity service to deploy, maintain, and upgrade, with its own HA, certificates, and storage requirements. It also doubles auth latency.

4. **Egress sidecar** -- inject a sidecar proxy (e.g., Envoy) into the OAuth Server pod to intercept outbound IdP traffic and forward it through a network path permitted to egress, avoiding proxy environment variables entirely. This requires deploying, configuring, and maintaining the sidecar (TLS origination, routing rules, health checks) and managing its lifecycle across upgrades. It also does not cover the operator's own outbound calls (OIDC discovery during config observation), which run in a separate pod -- requiring either a second sidecar or a cluster-level solution like a service mesh.

5. **Manual env var injection** -- skip the cluster-wide proxy API entirely and patch the OAuth Server and operator deployments directly with proxy env vars. This is unsupported, breaks on upgrades when the CVO reconciles the deployments, and doesn't survive operator-managed redeployments.

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
| **Proxy resolution helper** | `pkg/controllers/common/proxy.go` (new) | Resolves effective proxy config: component-scoped > cluster-wide > none | New `GetComponentProxyConfig()` and `ResolveProxyConfig()` functions used by all other controllers |
| **Deployment controller** | `pkg/controllers/deployment/deployment_controller.go`, `default_deployment.go` | Builds and reconciles the OAuth Server Deployment; injects `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars into the pod spec | Call `ResolveProxyConfig()` instead of reading the cluster-wide proxy directly; sync component proxy CA ConfigMap; inject volume/mount + entrypoint append dynamically; include resolved proxy in deployment hash to trigger rollouts on change |
| **Config observation (IDP conversions)** | `pkg/controllers/configobservation/oauth/idp_conversions.go`, `observe_idps.go` | Runs OIDC discovery (`discoverOpenIDURLs()`) to validate IdP endpoints during config observation | Accept `CARefTransportFunc` closure; use `TransportForCARefWithProxy()` so discovery calls go through the component-scoped proxy |
| **Transport layer** | `pkg/transport/transport.go` | Builds `http.RoundTripper` for outbound calls from the operator process | Add `CARefTransportFunc` type, `loadCAData()` helper, `TransportForCARefWithProxy()` variant that overrides the env-var-based proxy with caller-supplied proxy values |
| **Proxy validation controller** | `pkg/controllers/proxyconfig/proxyconfig_controller.go` | Validates proxy connectivity by testing the OAuth route's `/healthz` endpoint | Also validate the component-scoped proxy; test IdP connectivity on config change (warning events, not Degraded); load component `trustedCA` |
| **Endpoint accessible controller** | `pkg/libs/endpointaccessible/endpoint_accessible_controller.go`, `pkg/controllers/oauthendpoints/oauth_endpoints_controller.go` | Checks whether the OAuth route, service, and service endpoints are reachable | The route check (`OAuthServerRoute`) hits the external route hostname, which in cloud environments resolves to an external load balancer. In a disconnected environment with only a component-scoped proxy, `http.ProxyFromEnvironment` finds no env vars and the check fails. Add an optional proxy function callback so the route check uses the resolved component proxy |
| **Config observer controller** | `pkg/controllers/configobservation/configobservercontroller/observe_config_controller.go` | Wires config observer with informers and listers | Register operator auth informer and pass feature gate accessor |
| **Listers interface** | `pkg/controllers/configobservation/interfaces.go` | Provides listers to config observers | Add `OperatorAuthLister` and `FeatureGateAccessor` fields |
| **Starter wiring** | `pkg/operator/starter.go` | Wires controllers with informers and dependencies | Pass operator auth informer/lister, feature gate accessor, and source namespace informer to all modified controllers |

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

#### Proxy resolution helper

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

#### Trusted CA bundle syncing

**How the cluster-wide proxy CA works today:** The cluster-network-operator's CA bundle injector watches for ConfigMaps labeled `config.openshift.io/inject-trusted-cabundle: "true"` and populates their `ca-bundle.crt` key with system trust + cluster-wide proxy CA already merged. The OAuth Server (`bindata/oauth-openshift/deployment.yaml:62-64`) mounts this ConfigMap and the entrypoint copies the bundle to the system trust path:

```bash
cp -f .../ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
```

The component-scoped `trustedCA` ConfigMap is admin-provided and won't be processed by the CA bundle injector (no label), so the operator must handle merging.

**When `spec.proxy.trustedCA` is set**, the component CA must be merged with the existing trust chain (system trust + cluster-wide proxy CA). The entrypoint append approach is used: sync the component CA ConfigMap as-is, mount it as an additional volume, and extend the container entrypoint to concatenate it after the existing system trust copy.

1. **Sync** the referenced ConfigMap from `openshift-config` to `openshift-authentication` via direct `resourceapply.ApplyConfigMap()` in the deployment controller's `Sync()`. The `resourceSyncController.SyncConfigMap()` cannot be used because it registers a fixed source→destination mapping at startup, but the source name (`spec.proxy.trustedCA.name`) is dynamic. The synced ConfigMap uses the `v4-0-config-system-auth-proxy-ca` name so `getConfigResourceVersions()` automatically picks it up for deployment hash tracking, triggering rollouts on CA changes.

2. **Mount** it as an additional volume in the OAuth Server deployment (at `/var/config/system/configmaps/v4-0-config-system-auth-proxy-ca`), marked as optional.

3. **Append to system trust** by extending the container entrypoint:

    ```bash
    if [ -s /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt ]; then
        echo "Appending component proxy CA bundle"
        cat /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt \
            >> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    fi
    ```

    This runs after the existing `cp -f` of the injected system trust bundle, so the result is system trust + cluster-wide proxy CA + component-scoped proxy CA. The volume, mount, and entrypoint injection are done dynamically in the deployment controller, not in the static YAML template (matching the pattern used for custom router certs).

4. **CAO process**: load the component CA into the cert pool in `TransportForCARefWithProxy()` and in the proxy validation controller's `getCACerts()` (which already uses `AppendCertsFromPEM` to load from a configurable set of ConfigMaps). The config observer and proxy validation controller read the proxy CA directly from `openshift-config` via the existing cross-namespace `ConfigMapLister`, eliminating a second cross-namespace copy.

5. **Watch for changes**: CAO must watch the source ConfigMap in `openshift-config`, copy it into `openshift-authentication` on any change, and re-deploy OAuth Server so that the updated ConfigMap is picked up. The deployment controller registers the `openshift-config` ConfigMap informer (`kubeInformersForSourceNamespace.Core().V1().ConfigMaps().Informer()`) in its namespaced informers, so changes to the source CA ConfigMap trigger a controller re-sync, ConfigMap re-copy, and rollout via the `v4-0-config-` prefix hash tracking.

6. **Cleanup**: when `spec.proxy.trustedCA` is removed, `syncComponentProxyCA()` deletes the stale `v4-0-config-system-auth-proxy-ca` ConfigMap from `openshift-authentication`.

An alternative (server-side merge in the `trustdistribution` controller) was considered but rejected: it would add a new reconciliation loop with ordering constraints (merged ConfigMap must be ready before pod starts) and source-watching complexity, while the entrypoint approach is straightforward and extends an existing pattern.

#### OAuth Server deployment injection

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
httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(authProxy, clusterProxy)
resourceVersions = append(resourceVersions,
    fmt.Sprintf("proxy:%s:%s:%s", httpProxy, httpsProxy, noProxy))
```

#### Operator process proxy configuration

The CAO makes outbound OIDC discovery calls in `discoverOpenIDURLs()` (`idp_conversions.go`) via `transport.TransportForCARef()`. This delegates to `net.SetTransportDefaults()`, which sets `Proxy = http.ProxyFromEnvironment` -- so it respects env vars from the cluster-wide proxy. To support component-scoped proxy, a new `CARefTransportFunc` type and `TransportForCARefWithProxy()` variant are added:

**`pkg/transport/transport.go`:**

```go
type CARefTransportFunc func(caConfigMapName, key string) (http.RoundTripper, error)

func TransportForCARefWithProxy(
    cmLister corelistersv1.ConfigMapLister,
    caConfigMapName, key string,
    httpProxy, httpsProxy, noProxy string,
    extraCAData []byte,
) (http.RoundTripper, error)
```

The function always creates a dedicated `*http.Transport` (never returns `http.DefaultTransport`), applies proxy via `httpproxy.Config.ProxyFunc()`, and sets `transport.Proxy = nil` when all proxy values are empty (explicit no-proxy). A shared `loadCAData()` helper avoids duplicating CA-loading logic with `TransportForCARef`.

**`pkg/controllers/configobservation/oauth/idp_conversions.go`** -- instead of threading proxy params through the call chain, a `CARefTransportFunc` closure is built once in `ObserveIdentityProviders()` and passed down to `convertIdentityProviders()`, `discoverOpenIDURLs()`, and `checkOIDCPasswordGrantFlow()`. This allowed removing `cmLister` from leaf function signatures since it was only used for transport creation. If the component-scoped `trustedCA` is set, the CA is loaded directly from `openshift-config` via the existing `ConfigMapLister`.

#### Proxy validation controller

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
