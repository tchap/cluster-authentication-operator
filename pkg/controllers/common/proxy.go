package common

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"k8s.io/apimachinery/pkg/api/errors"
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
	proxy := authOp.Spec.Proxy
	if (proxy == operatorv1.AuthenticationProxyConfig{}) {
		return nil, nil
	}
	return &proxy, nil
}

// ResolveProxyConfig determines the effective proxy settings for authentication
// components:
//  1. authProxy set with at least one URL -> use component-scoped proxy
//  2. authProxy nil or no URLs -> fall back to cluster-wide proxy
//  3. Neither configured -> no proxy
//
// When using the component-scoped proxy, static cluster-internal noProxy defaults
// are always set to prevent auth components from routing internal traffic through
// the proxy.
func ResolveProxyConfig(
	authProxy *operatorv1.AuthenticationProxyConfig,
	clusterProxy *configv1.Proxy,
) (httpProxy, httpsProxy, noProxy string) {
	if authProxy != nil && (authProxy.HTTPProxy != "" || authProxy.HTTPSProxy != "") {
		return authProxy.HTTPProxy, authProxy.HTTPSProxy, staticNoProxy
	}
	if clusterProxy != nil {
		return clusterProxy.Status.HTTPProxy, clusterProxy.Status.HTTPSProxy, clusterProxy.Status.NoProxy
	}
	return "", "", ""
}

// staticNoProxy contains cluster-internal addresses that must bypass the proxy.
// Auth components connect to internal services via DNS names covered by .svc and
// .cluster.local, so network CIDRs and api-int hostname are not needed.
const staticNoProxy = ".cluster.local,.svc,127.0.0.1,localhost"
