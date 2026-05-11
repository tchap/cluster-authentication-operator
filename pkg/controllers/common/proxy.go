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
// Returns (nil, nil) when the gate is disabled or not yet observed.
// Returns a non-nil error when the gate is enabled but the resource cannot
// be read -- callers should log the error and fall back to cluster-wide proxy.
func GetComponentProxyConfig(
	featureGateAccessor featuregates.FeatureGateAccess,
	operatorAuthLister operatorv1listers.AuthenticationLister,
) (*operatorv1.AuthenticationProxyConfig, error) {
	if featureGateAccessor == nil || operatorAuthLister == nil {
		return nil, nil
	}
	featureGates, err := featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return nil, nil
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
//  1. authProxy set with values -> use component-scoped proxy
//  2. authProxy set but empty (proxy: {}) -> explicitly no proxy
//  3. authProxy nil -> fall back to cluster-wide proxy
//  4. Neither configured -> no proxy
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
