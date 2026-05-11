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

Pure function, no feature gate logic -- callers decide whether to pass `authProxy` based on the gate. Unit tests in `proxy_test.go` covering all 4 resolution states.

---

## Step 2: OAuth Server deployment injection (2c)

**Files:**
- `pkg/controllers/deployment/deployment_controller.go`
- `pkg/controllers/deployment/default_deployment.go`
- `pkg/operator/starter.go`

### deployment_controller.go

Add fields to `oauthServerDeploymentSyncer`:
```go
operatorAuthLister  operatorv1listers.AuthenticationLister
featureGateAccessor featuregates.FeatureGateAccess
```

Add params to `NewOAuthServerWorkloadController()`:
```go
operatorAuthLister operatorv1listers.AuthenticationLister,
featureGateAccessor featuregates.FeatureGateAccess,
operatorAuthInformer factory.Informer,
```

Register `operatorAuthInformer` in the controller's `clusterScopedInformers`.

In `Sync()`, resolve proxy:
```go
// Existing: proxyConfig, err := c.getProxyConfig()
// New: resolve component-scoped if feature gate enabled
var authProxy *operatorv1.AuthenticationProxyConfig
if featureGateEnabled {
    authOp, err := c.operatorAuthLister.Get("cluster")
    authProxy = authOp.Spec.Proxy
}
clusterProxy, _ := c.getProxyConfig()
httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(authProxy, clusterProxy)
```

Update resource version tracking to include resolved proxy values in the hash (instead of cluster proxy ResourceVersion).

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

Replace `proxyConfigToEnvVars(proxyConfig)` with direct env var construction from the string params.

### starter.go

Update deployment controller wiring (~line 272) to pass new deps:
```go
informerFactories.operatorInformer.Operator().V1().Authentications().Lister(),
featureGateAccessor,
informerFactories.operatorInformer.Operator().V1().Authentications().Informer(),
```

---

## Step 3: Trusted CA syncing and mounting (2b, Option A)

**Files:**
- `pkg/controllers/deployment/deployment_controller.go` (CA ConfigMap copy)
- `pkg/controllers/deployment/default_deployment.go` (entrypoint + volume/mount)

### ConfigMap copy in deployment controller

In `Sync()`, when `authProxy.TrustedCA.Name` is set:
1. Read source ConfigMap from `openshift-config` via kubeClient
2. Apply a copy as `v4-0-config-system-auth-proxy-ca` in `openshift-authentication` using `resourceapply.ApplyConfigMap()`
3. Apply a copy as `auth-proxy-ca` in `openshift-authentication-operator` (for the operator's own transport, Step 4)

Add `configMaps corev1client.ConfigMapsGetter` field to `oauthServerDeploymentSyncer` (use `kubeClient.CoreV1()`). Also add a ConfigMap lister for `openshift-config` namespace.

### Volume + mount in deployment controller Sync()

When CA is set, append volume and volume mount to expected deployment:
```go
Volume: v4-0-config-system-auth-proxy-ca -> ConfigMap v4-0-config-system-auth-proxy-ca (optional)
Mount: /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca
```

### Entrypoint append in default_deployment.go

Add a parameter `componentProxyCAConfigMapName string` to `getOAuthServerDeployment()`. When non-empty, inject an append block into `container.Args[0]` before the `exec` line:

```bash
if [ -s /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt ]; then
    echo "Appending component proxy CA bundle"
    cat /var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt >> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
fi
```

Insert via `strings.Replace` on the `exec oauth-server` marker in the args string.

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

Add new function:
```go
func TransportForCARefWithProxy(
    cmLister corelistersv1.ConfigMapLister,
    caConfigMapName, key string,
    httpProxy, httpsProxy, noProxy string,
    extraCAData []byte,
) (http.RoundTripper, error)
```

Implementation:
- Build transport as in `TransportForCARef()` 
- If any proxy value is non-empty, override transport.Proxy with a function built from `httpproxy.Config{HTTPProxy, HTTPSProxy, NoProxy}.ProxyFunc()`
- If `extraCAData` is non-empty, append to the CA cert pool (for component proxy CA)
- If all proxy values are empty AND the caller explicitly chose component proxy (not fallback), set `transport.Proxy = nil` to disable proxy entirely

### idp_conversions.go

Add `httpProxy, httpsProxy, noProxy string` and `proxyCAData []byte` params to:
- `discoverOpenIDURLs()` -- use `TransportForCARefWithProxy()` instead of `TransportForCARef()`
- `checkOIDCPasswordGrantFlow()` -- same change
- `convertProviderConfigToIDPData()` -- pass through
- `convertIdentityProviders()` -- pass through

### observe_idps.go

In `ObserveIdentityProviders()`, resolve proxy via the lister, pass to `convertIdentityProviders()`.

### interfaces.go

Add to `Listers` struct:
```go
OperatorAuthLister_  operatorv1listers.AuthenticationLister
FeatureGateAccessor_ featuregates.FeatureGateAccess
OpAuthConfigMapLister_ corelistersv1.ConfigMapLister  // for openshift-authentication-operator
```

Add accessor methods.

### observe_config_controller.go

Update `NewConfigObserver()` to accept:
```go
operatorAuthLister operatorv1listers.AuthenticationLister,
featureGateAccessor featuregates.FeatureGateAccess,
opAuthOperatorConfigMapInformer coreinformers.ConfigMapInformer,
```

Wire into `Listers` struct. Add informer to watched informers.

### starter.go

Update `configObserver` construction (~line 185) with new params.

---

## Step 5: Proxy validation controller (2e)

**File:** `pkg/controllers/proxyconfig/proxyconfig_controller.go`

Add fields to `proxyConfigChecker`:
```go
operatorAuthLister  operatorv1listers.AuthenticationLister
featureGateAccessor featuregates.FeatureGateAccess
clusterProxyLister  configv1listers.ProxyLister
```

Update `NewProxyConfigChecker()` signature with new params + `operatorAuthInformer`.

In `sync()`:
1. Check feature gate. If enabled, resolve component proxy via `ResolveProxyConfig()`.
2. If component proxy is configured (non-nil `spec.proxy`):
   - Build proxy functions from resolved values
   - Load component CA from `openshift-authentication-operator/auth-proxy-ca` if `TrustedCA.Name` is set
   - Test OAuth route reachability through component proxy
   - Skip cluster-wide proxy validation
3. If component proxy is nil, run existing validation.

Update wiring in `starter.go` (~line 326).

---

## Step 6: Upgradeable condition (2f)

Add logic in the deployment controller's `Sync()` (since it already has all needed listers):

When feature gate is enabled and `spec.proxy != nil`:
- Update operator status with condition `AuthenticationComponentProxyUpgradeable=False`
  - Reason: `ComponentProxyConfigured`
  - Message explaining TechPreview restriction

When feature gate is enabled and `spec.proxy == nil`:
- Set condition `AuthenticationComponentProxyUpgradeable=True`

When feature gate is disabled:
- Remove/don't set the condition

Use `v1helpers.UpdateStatus()` on the operator client, following the same pattern as other controllers that set conditions.

---

## Feature gate guard pattern

At every call site, before accessing `spec.proxy`:
```go
featureGates, err := c.featureGateAccessor.CurrentFeatureGates()
if err != nil || !featureGates.Enabled(features.FeatureGateAuthenticationComponentProxy) {
    // existing behavior, pass nil for authProxy
}
```

When the gate is off, `ResolveProxyConfig(nil, clusterProxy)` returns cluster-wide proxy values -- identical to today.

---

## Implementation order

1. **Step 1** (proxy helper) -- no deps
2. **Step 2** (deployment injection) -- depends on 1
3. **Step 3** (CA syncing + mount) -- depends on 1, 2
4. **Step 4** (operator transport) -- depends on 1, 3 (needs CA in operator namespace)
5. **Step 5** (validation) -- depends on 1
6. **Step 6** (upgradeable) -- depends on 1, 2

---

## Verification

1. `go build ./...` -- compiles
2. `go test ./pkg/controllers/common/...` -- proxy resolution tests
3. `go test ./pkg/controllers/deployment/...` -- deployment env var and CA injection tests
4. `go test ./pkg/transport/...` -- transport proxy override tests
5. `go test ./pkg/controllers/configobservation/...` -- config observer tests (nil proxy = existing behavior)
6. `go test ./pkg/controllers/proxyconfig/...` -- validation controller tests
7. `go vet ./...` and `go test ./...` -- full pass

All existing tests pass with nil proxy parameter (backward compatible).
