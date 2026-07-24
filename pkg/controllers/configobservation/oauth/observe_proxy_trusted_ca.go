package oauth

import (
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

var proxyTrustedCAPath = []string{"oauthConfig", "proxyTrustedCA"}

const proxyTrustedCAFile = "/var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt"

// ObserveComponentProxyTrustedCA sets oauthConfig.proxyTrustedCA to the on-disk path of
// the component-scoped proxy trusted CA bundle when the operator-level
// Authentication CR specifies a proxy trustedCA configmap and the corresponding
// feature gate is enabled. The path points to the configmap volume mount
// managed by the deployment controller (v4-0-config-system-auth-proxy-ca).
func ObserveComponentProxyTrustedCA(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, proxyTrustedCAPath)
	}()

	listers := genericListers.(configobservation.Listers)

	existingValue, _, err := unstructured.NestedFieldCopy(existingConfig, proxyTrustedCAPath...)
	if err != nil {
		return existingConfig, []error{err}
	}

	proxy, err := listers.ProxyResolver.ResolveProxy()
	if err != nil {
		return existingConfig, []error{err}
	}

	observedConfig := map[string]interface{}{}
	var observedValue interface{}
	if len(proxy.TrustedCAName) > 0 {
		observedValue = proxyTrustedCAFile
		if err := unstructured.SetNestedField(observedConfig, proxyTrustedCAFile, proxyTrustedCAPath...); err != nil {
			return existingConfig, []error{err}
		}
	}

	if !equality.Semantic.DeepEqual(existingValue, observedValue) {
		recorder.Eventf("ObserveComponentProxyTrustedCA", "proxyTrustedCA changed from %v to %v", existingValue, observedValue)
	}

	return observedConfig, nil
}
