package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=authentications,scope=Cluster
// +kubebuilder:subresource:status
// +openshift:api-approved.openshift.io=https://github.com/openshift/api/pull/475
// +openshift:file-pattern=cvoRunLevel=0000_50,operatorName=authentication,operatorOrdering=01
// +kubebuilder:metadata:annotations=include.release.openshift.io/self-managed-high-availability=true

// Authentication provides information to configure an operator to manage authentication.
//
// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
// +openshift:compatibility-gen:level=1
type Authentication struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec AuthenticationSpec `json:"spec"`
	// +optional
	Status AuthenticationStatus `json:"status,omitempty"`
}

type AuthenticationSpec struct {
	OperatorSpec `json:",inline"`

	// proxy configures proxy settings specifically for authentication
	// components (the OAuth server and the operator itself).
	// When set, these values override the cluster-wide proxy
	// (proxy.config.openshift.io/cluster) for authentication operands only.
	// No per-field inheritance from the cluster-wide proxy occurs.
	// When omitted, the cluster-wide proxy is used, preserving
	// existing behavior.
	// +openshift:enable:FeatureGate=AuthenticationComponentProxy
	// +optional
	Proxy AuthenticationProxyConfig `json:"proxy,omitzero"`
}

// AuthenticationProxyConfig holds proxy configuration scoped to
// authentication components (the OAuth server and the cluster
// authentication operator).
// +kubebuilder:validation:XValidation:rule="has(self.httpProxy) || has(self.httpsProxy)",message="at least one of httpProxy or httpsProxy must be specified"
type AuthenticationProxyConfig struct {
	// httpProxy is the URL of the proxy for HTTP requests.
	// Authentication components will use this proxy for all
	// outbound HTTP connections to external identity providers.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="isURL(self)",message="httpProxy must be a valid URL"
	// +optional
	HTTPProxy string `json:"httpProxy,omitempty"`

	// httpsProxy is the URL of the proxy for HTTPS requests.
	// Authentication components will use this proxy for all
	// outbound HTTPS connections to external identity providers,
	// including OIDC discovery, token exchange, and user info requests.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="isURL(self)",message="httpsProxy must be a valid URL"
	// +optional
	HTTPSProxy string `json:"httpsProxy,omitempty"`

	// trustedCA is a reference to a ConfigMap in the openshift-config
	// namespace containing a CA certificate bundle under the key
	// "ca-bundle.crt". This CA bundle is appended to the system trust
	// store and used for proxy TLS connections by authentication components.
	// When omitted, only the system trust store (including any cluster-wide
	// proxy CA) is used.
	// +optional
	TrustedCA AuthenticationConfigMapReference `json:"trustedCA,omitzero"`
}

// AuthenticationConfigMapReference references a ConfigMap in the
// openshift-config namespace.
type AuthenticationConfigMapReference struct {
	// name is the metadata.name of the referenced ConfigMap.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`
}

type AuthenticationStatus struct {
	// oauthAPIServer holds status specific only to oauth-apiserver
	// +optional
	OAuthAPIServer OAuthAPIServerStatus `json:"oauthAPIServer,omitempty"`

	OperatorStatus `json:",inline"`
}

type OAuthAPIServerStatus struct {
	// latestAvailableRevision is the latest revision used as suffix of revisioned
	// secrets like encryption-config. A new revision causes a new deployment of pods.
	// +optional
	// +kubebuilder:validation:Minimum=0
	LatestAvailableRevision int32 `json:"latestAvailableRevision,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationList is a collection of items
//
// Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer).
// +openshift:compatibility-gen:level=1
type AuthenticationList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard list's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata"`

	Items []Authentication `json:"items"`
}
