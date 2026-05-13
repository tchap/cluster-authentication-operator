package common

import (
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
)

// GetComponentProxyConfig returns the component-scoped proxy configuration
// from operator.openshift.io/v1 Authentication if the feature gate is enabled.
// Returns (nil, nil) when the gate is disabled or the resource is not found.
// Returns a non-nil error when feature gates cannot be read or the lister
// fails -- callers should log the error and fall back to cluster-wide proxy.
func GetComponentProxyConfig(
	featureGateAccessor featuregates.FeatureGateAccess,
	operatorAuthLister operatorv1listers.AuthenticationLister,
) (*operatorv1.AuthenticationProxyConfig, error) {
	if featureGateAccessor == nil || operatorAuthLister == nil {
		return nil, nil
	}
	featureGates, err := featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return nil, fmt.Errorf("failed to get current feature gates: %v", err)
	}
	if !featureGates.Enabled(features.FeatureGateAuthenticationComponentProxy) {
		return nil, nil
	}
	authOp, err := operatorAuthLister.Get("cluster")
	if errors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get operator.openshift.io/v1 authentication/cluster: %v", err)
	}
	return authOp.Spec.Proxy, nil
}

// ResolveProxyConfig determines the effective proxy settings for authentication
// components by applying three-way resolution:
//  1. authProxy set with values -> use component-scoped proxy (with auto-populated noProxy)
//  2. authProxy set but empty (proxy: {}) -> explicitly no proxy
//  3. authProxy nil -> fall back to cluster-wide proxy
//  4. Neither configured -> no proxy
//
// When using the component-scoped proxy, cluster-internal noProxy defaults are
// auto-appended to the user-provided noProxy value.
func ResolveProxyConfig(
	authProxy *operatorv1.AuthenticationProxyConfig,
	clusterProxy *configv1.Proxy,
) (httpProxy, httpsProxy, noProxy string) {
	if authProxy != nil {
		return authProxy.HTTPProxy, authProxy.HTTPSProxy,
			mergeNoProxy(authProxy.NoProxy)
	}
	if clusterProxy != nil {
		return clusterProxy.Status.HTTPProxy, clusterProxy.Status.HTTPSProxy, clusterProxy.Status.NoProxy
	}
	return "", "", ""
}

// mergeNoProxy appends static cluster-internal defaults to user-provided noProxy
// entries. Auth components connect to internal services via DNS names covered by
// .svc and .cluster.local, so network CIDRs and api-int hostname are not needed.
func mergeNoProxy(userNoProxy string) string {
	set := sets.NewString(
		"127.0.0.1",
		"localhost",
		".svc",
		".cluster.local",
	)

	if len(userNoProxy) > 0 {
		for _, entry := range strings.Split(userNoProxy, ",") {
			trimmed := strings.TrimSpace(entry)
			if len(trimmed) > 0 {
				set.Insert(trimmed)
			}
		}
	}

	return strings.Join(set.List(), ",")
}
