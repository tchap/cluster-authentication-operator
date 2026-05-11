# Phase 2: Component-Scoped Proxy Implementation Plan

## Context

OCPSTRAT-3174 requires authentication components (CAO, OAuth Server) to reach external IdPs through a proxy without configuring the cluster-wide proxy. Phase 1 (API) is vendored: `operatorv1.AuthenticationSpec.Proxy *AuthenticationProxyConfig` with fields `HTTPProxy`, `HTTPSProxy`, `NoProxy`, `TrustedCA`. Feature gate: `FeatureGateAuthenticationComponentProxy` (TechPreviewNoUpgrade).

**Resolution semantics:**
1. `spec.proxy` with values -> component proxy
2. `spec.proxy: {}` (empty) -> explicitly no proxy  
3. `spec.proxy` absent (nil) -> cluster-wide proxy fallback
4. Neither -> no proxy

---

## Step 1: Proxy resolution helper

**New file:** `pkg/controllers/common/proxy.go`

```go
func ResolveProxyConfig(
    authProxy *operatorv1.AuthenticationProxyConfig,
    clusterProxy *configv1.Proxy,
) (httpProxy, httpsProxy, noProxy string) {
    if authProxy != nil {
        return authProxy.HTTPProxy, authProxy.HTTPSProxy, authProxy.NoProxy
    }
    if clusterProxy != nil {
        return clusterProxy.Status.HTTPProxy, clusterProxy.Status.HTTPSProxy, clusterProxy.Status.NoProxy
    }
    return "", "", ""
}
```

Pure function, no feature gate logic -- callers decide whether to pass `authProxy` based on the gate. Unit tests in `proxy_test.go` covering all 4 resolution states plus partial-values case.

Helper to get the proxy object with feature gate guarding:

```go
func GetComponentProxyConfig(
    featureGateAccessor featuregates.FeatureGateAccess,
    operatorAuthLister operatorv1listers.AuthenticationLister,
) (*operatorv1.AuthenticationProxyConfig, error)
```

Returns `(nil, nil)` when the gate is disabled, not yet observed, or the resource is not found. Returns a non-nil error only when the lister fails unexpectedly -- callers log the error and fall back to cluster-wide proxy.

---

## Step 2: OAuth Server deployment injection (2c)

**Files:**
- `pkg/controllers/deployment/deployment_controller.go`
- `pkg/controllers/deployment/default_deployment.go`
- `pkg/operator/starter.go`

### deployment_controller.go

Add fields to `oauthServerDeploymentSyncer`:
```go
configMaps          corev1client.ConfigMapsGetter     // for CA ConfigMap apply
sourceConfigMapLister corev1listers.ConfigMapLister   // openshift-config namespace
operatorAuthLister  operatorv1listers.AuthenticationLister
featureGateAccessor featuregates.FeatureGateAccess
```

Add params to `NewOAuthServerWorkloadController()`:
```go
kubeInformersForSourceNamespace informers.SharedInformerFactory,  // openshift-config
operatorAuthLister operatorv1listers.AuthenticationLister,
featureGateAccessor featuregates.FeatureGateAccess,
operatorAuthInformer factory.Informer,
```

Register `operatorAuthInformer` in the controller's `clusterScopedInformers`.
Register `kubeInformersForSourceNamespace.Core().V1().ConfigMaps().Informer()` in the controller's namespaced informers -- this ensures changes to the source CA ConfigMap in `openshift-config` trigger a re-sync.

In `Sync()`, resolve proxy via helper:
```go
authProxy, err := common.GetComponentProxyConfig(c.featureGateAccessor, c.operatorAuthLister)
if err != nil {
    klog.Warningf("failed to get component proxy config, falling back to cluster-wide proxy: %v", err)
}
clusterProxy, err := c.getProxyConfig()
httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(authProxy, clusterProxy)
```

Update resource version tracking: replace `"proxy:"+proxyConfig.Name+":"+proxyConfig.ResourceVersion` with `fmt.Sprintf("proxy:%s:%s:%s", httpProxy, httpsProxy, noProxy)`. This tracks the resolved values instead of the cluster proxy object identity, so changes to either source trigger redeployment.

### default_deployment.go

Change `getOAuthServerDeployment()` signature:
```go
func getOAuthServerDeployment(
    operatorSpec *operatorv1.OperatorSpec,
    httpProxy, httpsProxy, noProxy string,  // was: proxyConfig *configv1.Proxy
    bootstrapUserExists bool,
    resourceVersions ...string,
) (*appsv1.Deployment, error)
```

Replace `proxyConfigToEnvVars(proxyConfig)` with `proxyEnvVars(httpProxy, httpsProxy, noProxy)` -- same logic, reads from string params instead of `proxy.Status.*`. Remove unused `configv1` import.

### starter.go

Update deployment controller wiring to pass new deps:
```go
informerFactories.kubeInformersForNamespaces.InformersFor("openshift-config"),  // source namespace
informerFactories.operatorInformer.Operator().V1().Authentications().Lister(),
featureGateAccessor,
informerFactories.operatorInformer.Operator().V1().Authentications().Informer(),
```

**Implementation note:** The typed `operatorv1.Authentication` lister comes from `informerFactories.operatorInformer.Operator().V1().Authentications()`, which is distinct from `informerFactories.operatorConfigInformer.Config().V1().Authentications()` (the `configv1.Authentication` used by `AuthConfigChecker`).

---

## Step 3: Trusted CA syncing and mounting (2b, Option A)

**Files:**
- `pkg/controllers/deployment/deployment_controller.go` (CA ConfigMap copy + volume/mount + entrypoint)

### ConfigMap copy via direct apply (not resourceSyncController)

`resourceSyncController.SyncConfigMap()` registers a fixed source→destination mapping at startup. The source name comes from `spec.proxy.trustedCA.name` which is dynamic. `SyncConfigMapConditionally` has the same limitation. So we use direct `resourceapply.ApplyConfigMap()` in the deployment controller's `Sync()`.

New method `syncComponentProxyCA()` called from `Sync()`:
1. If `authProxy == nil` or `authProxy.TrustedCA.Name` is empty, return nil (no-op)
2. Read source ConfigMap from `openshift-config` via `sourceConfigMapLister`
3. Apply as `v4-0-config-system-auth-proxy-ca` in `openshift-authentication` (for the OAuth Server)
4. Apply as `auth-proxy-ca` in `openshift-authentication-operator` (for the operator's own transport)
5. Add volume + volume mount to the deployment
6. Inject entrypoint append block via `strings.Replace` on the `"exec oauth-server"` marker

The ConfigMap in `openshift-authentication` uses the `v4-0-config-` prefix so `getConfigResourceVersions()` automatically picks it up for deployment hash tracking, triggering rollouts on CA changes.

Volume name and mount follow existing conventions:
```
Name:  v4-0-config-system-auth-proxy-ca
Mount: /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca
ConfigMap is optional (ptr.To(true))
```

Entrypoint append inserted before the `exec` line:
```bash
if [ -s /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt ]; then
    echo "Appending component proxy CA bundle"
    cat /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt >> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
fi
```

This runs after the existing system trust copy, so the result is: system trust + cluster-wide proxy CA + component proxy CA.

---

## Step 4: Operator process proxy (2d)

**Files:**
- `pkg/transport/transport.go`
- `pkg/controllers/configobservation/oauth/idp_conversions.go`
- `pkg/controllers/configobservation/oauth/observe_idps.go`
- `pkg/controllers/configobservation/interfaces.go`
- `pkg/controllers/configobservation/configobservercontroller/observe_config_controller.go`
- `pkg/operator/starter.go`

### transport.go

Renamed `net` import to `knet` (alias for `k8s.io/apimachinery/pkg/util/net`) to avoid conflict with new imports. Added `net/url`, `golang.org/x/net/http/httpproxy`.

New type `CARefTransportFunc` -- a function that builds an `http.RoundTripper` for a given CA ConfigMap reference with cmLister and proxy settings captured in the closure.

New function `TransportForCARefWithProxy()`:
- Loads CA from ConfigMap (same as `TransportForCARef`)
- If `extraCAData` is non-empty, appends to the CA cert pool
- Builds transport via `transportForInner()` (returns `*http.Transport`, not wrapped)
- If proxy values are non-empty, overrides `transport.Proxy` with function built from `httpproxy.Config.ProxyFunc()`
- If all proxy values are empty, sets `transport.Proxy = nil` (explicit no-proxy)
- Wraps with `ktransport.DebugWrappers()` before returning

**Implementation detail:** `httpproxy.Config.ProxyFunc()` returns `func(*url.URL) (*url.URL, error)` but `http.Transport.Proxy` expects `func(*http.Request) (*url.URL, error)`. The adapter closure extracts `req.URL`:
```go
t.Proxy = func(req *http.Request) (*url.URL, error) {
    return proxyFunc(req.URL)
}
```

### idp_conversions.go

Instead of threading 4 proxy params through the call chain, a single `transport.CARefTransportFunc` closure is passed. This captures the cmLister and any proxy settings, so leaf functions don't need to know about proxy at all.

Changed signatures:
- `convertIdentityProviders(cmLister, secretsLister, idps, buildTransport)` -- 1 new param
- `convertProviderConfigToIDPData(cmLister, secretsLister, ..., buildTransport)` -- same
- `discoverOpenIDURLs(issuer, key, ca, buildTransport)` -- `cmLister` removed (only used for transport)
- `checkOIDCPasswordGrantFlow(secretsLister, ..., buildTransport)` -- `cmLister` removed (only used for transport)

The leaf functions call `buildTransport(ca.Name, key)` instead of `transport.TransportForCARef(cmLister, ca.Name, key)`.

**Naming fix:** `checkOIDCPasswordGrantFlow` had a variable named `transport` shadowing the package import. Renamed to `rt`.

### observe_idps.go

Import conflict: both `configobservation` (local) and `configobserver` (library-go) are used. Resolved by aliasing: `localconfigobservation "..."`.

Builds the `CARefTransportFunc` closure once in `ObserveIdentityProviders()`:
```go
buildTransport := transport.CARefTransportFunc(func(caConfigMapName, key string) (http.RoundTripper, error) {
    return transport.TransportForCARef(listers.ConfigMapLister, caConfigMapName, key)
})
if authProxy != nil {
    buildTransport = func(caConfigMapName, key string) (http.RoundTripper, error) {
        return transport.TransportForCARefWithProxy(listers.ConfigMapLister, caConfigMapName, key, ...)
    }
}
```

Uses `GetComponentProxyConfig` helper, logs errors, and loads the component proxy CA from `openshift-authentication-operator/auth-proxy-ca` (copied there by Step 3).

### interfaces.go

Added three fields to `Listers` struct (no trailing underscores, accessed directly):
```go
OperatorAuthLister          operatorv1listers.AuthenticationLister
FeatureGateAccessor         featuregates.FeatureGateAccess
OperatorNamespaceConfigMaps corelistersv1.ConfigMapLister
```

### observe_config_controller.go

New params for `NewConfigObserver()`:
```go
operatorAuthInformer operatorv1informers.AuthenticationInformer,
featureGateAccessor featuregates.FeatureGateAccess,
```

The operator auth informer and `openshift-authentication-operator` ConfigMap informer are registered in `preRunCacheSynced` and `informers`. The operator auth lister is obtained from the informer; nil-guarded if the informer is nil.

Import: `operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"` and `operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"`.

### starter.go

Config observer wiring updated to pass:
```go
informerFactories.operatorInformer.Operator().V1().Authentications(),
featureGateAccessor,
```

### Test updates

Test call sites in `idp_conversions_test.go` build a `CARefTransportFunc` closure wrapping `transport.TransportForCARef` with the test's cmLister, then pass it to the updated function signatures.

---

## Step 5: Proxy validation controller (2e)

**File:** `pkg/controllers/proxyconfig/proxyconfig_controller.go`

Add fields to `proxyConfigChecker`:
```go
operatorAuthLister  operatorv1listers.AuthenticationLister
featureGateAccessor featuregates.FeatureGateAccess
clusterProxyLister  configv1listers.ProxyLister
```

New params for `NewProxyConfigChecker()`:
```go
operatorAuthLister operatorv1listers.AuthenticationLister,
featureGateAccessor featuregates.FeatureGateAccess,
clusterProxyLister configv1listers.ProxyLister,
operatorAuthInformer factory.Informer,
```

The `operatorAuthInformer` is conditionally added to the factory builder (`c.WithInformers()`) if non-nil.

In `sync()`, component proxy check runs first (before the existing cluster-wide proxy check) via `GetComponentProxyConfig` helper (error logged at Warning level). If `spec.proxy` is non-nil, `validateComponentProxy()` is called and the method returns early -- skipping the cluster-wide proxy validation.

New method `validateComponentProxy()`:
- Resolves proxy via `common.ResolveProxyConfig(authProxy, nil)`
- If all values are empty (explicit no-proxy), logs and returns nil
- Loads CA pool from existing `caConfigMaps` + component proxy CA from `openshift-authentication-operator/auth-proxy-ca`
- Builds proxy-aware and proxy-less HTTP clients
- Calls existing `checkProxyConfig()` to test OAuth route reachability

### starter.go

Proxy config controller wiring updated to pass:
```go
informerFactories.operatorInformer.Operator().V1().Authentications().Lister(),
featureGateAccessor,
informerFactories.operatorConfigInformer.Config().V1().Proxies().Lister(),
informerFactories.operatorInformer.Operator().V1().Authentications().Informer(),
```

---

## Step 6: Upgradeable condition (2f)

**File:** `pkg/controllers/deployment/deployment_controller.go`

Added in the deployment controller's `Sync()` right after proxy resolution. Uses `operatorClient.ApplyOperatorStatus()` with `applyoperatorv1.OperatorCondition()` -- same pattern as `UnsupportedConfigOverridesUpgradeable` in library-go.

When `authProxy != nil` (feature gate enabled and spec.proxy is set):
- Sets `AuthenticationComponentProxyUpgradeable=False`
- Reason: `ComponentProxyConfigured`
- Message: explains TechPreview restriction

When `authProxy == nil` (gate disabled or proxy not set): no condition is set (no-op).

The condition is only set, never cleared to True -- once spec.proxy is removed, the condition simply stops being refreshed and the status controller in library-go handles the rest (conditions without the `Upgradeable` type default to True).

**Implementation detail:** Uses `applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"` for the apply configuration builder. The field name passed to `ApplyOperatorStatus()` is `"OAuthServerDeployment"` identifying this controller instance.

---

## Feature gate guard pattern

All call sites use the `GetComponentProxyConfig` helper:

```go
authProxy, err := common.GetComponentProxyConfig(c.featureGateAccessor, c.operatorAuthLister)
if err != nil {
    klog.Warningf("failed to get component proxy config, falling back to cluster-wide proxy: %v", err)
}
```

The helper encapsulates nil-safety, feature gate check, and lister access. Returns `(nil, nil)` when the gate is disabled, not observed, or the resource is not found. Returns a non-nil error only on unexpected lister failures -- callers log and fall back. When `authProxy` is nil, `ResolveProxyConfig(nil, clusterProxy)` returns cluster-wide proxy values -- identical to today.

---

## Key implementation decisions

1. **Direct ConfigMap copy vs resourceSyncController:** `SyncConfigMap()` and `SyncConfigMapConditionally()` register fixed source names at startup. The component proxy CA source name is dynamic (`spec.proxy.trustedCA.name`), so we use `resourceapply.ApplyConfigMap()` directly in the deployment controller.

2. **Source namespace informer:** The deployment controller now watches `openshift-config` ConfigMaps via `kubeInformersForSourceNamespace`. This ensures changes to the source CA ConfigMap trigger a controller re-sync and ConfigMap re-copy.

3. **`v4-0-config-` prefix naming:** The synced ConfigMap in `openshift-authentication` uses this prefix so it's automatically included in `getConfigResourceVersions()` deployment hash tracking.

4. **Transport builder closure:** Instead of threading 4 proxy params through the IDP conversion call chain, a `transport.CARefTransportFunc` closure is built once at the top level and passed down. Leaf functions (`discoverOpenIDURLs`, `checkOIDCPasswordGrantFlow`) call the closure without knowing about proxy. This also allowed removing `cmLister` from their signatures since it was only used for transport creation.

5. **No `bindata/` changes:** The entrypoint append and volume/mount are injected dynamically in the deployment controller, not in the static YAML template. This matches the pattern used for custom router certs.

---

## Files changed

| File | Change |
|---|---|
| `pkg/controllers/common/proxy.go` | New: `GetComponentProxyConfig()`, `ResolveProxyConfig()` |
| `pkg/controllers/common/proxy_test.go` | New: unit tests |
| `pkg/controllers/deployment/deployment_controller.go` | New fields, proxy resolution, CA sync, upgradeable condition |
| `pkg/controllers/deployment/default_deployment.go` | Changed signature to accept resolved proxy strings |
| `pkg/transport/transport.go` | New: `CARefTransportFunc` type, `TransportForCARefWithProxy()`, renamed `net` → `knet` |
| `pkg/controllers/configobservation/oauth/idp_conversions.go` | Accept `CARefTransportFunc`, removed `cmLister` from leaf functions |
| `pkg/controllers/configobservation/oauth/idp_conversions_test.go` | Build transport closure, updated call sites |
| `pkg/controllers/configobservation/oauth/observe_idps.go` | Build transport closure, proxy resolution, import alias |
| `pkg/controllers/configobservation/interfaces.go` | Added lister/accessor fields |
| `pkg/controllers/configobservation/configobservercontroller/observe_config_controller.go` | New params, informer registration |
| `pkg/controllers/proxyconfig/proxyconfig_controller.go` | Component proxy validation, new fields |
| `pkg/operator/starter.go` | Updated wiring for all modified controllers |

---

## Verification

1. `go build ./...` -- compiles clean
2. `go vet ./pkg/...` -- no issues
3. `go test ./pkg/...` -- all unit tests pass
4. E2E tests (`test/e2e/`) fail locally with "no server defined" -- expected, requires a running cluster

All existing tests pass with nil proxy parameters (backward compatible).
