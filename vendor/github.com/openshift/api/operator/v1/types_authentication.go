package v1

import (
	configv1 "github.com/openshift/api/config/v1"
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
	// When set to an empty struct (proxy: {}), authentication components
	// will not use any proxy, even if a cluster-wide proxy is configured.
	// When omitted (nil), the cluster-wide proxy is used, preserving
	// existing behavior.
	// +openshift:enable:FeatureGate=AuthenticationComponentProxy
	// +optional
	Proxy *AuthenticationProxyConfig `json:"proxy,omitempty"`
}

// AuthenticationProxyConfig holds proxy configuration scoped to
// authentication components (the OAuth server and the cluster
// authentication operator).
// +kubebuilder:validation:MinProperties=0
type AuthenticationProxyConfig struct {
	// httpProxy is the URL of the proxy for HTTP requests.
	// Authentication components will use this proxy for all
	// outbound HTTP connections to external identity providers.
	// An empty string means no HTTP proxy is used.
	// +required
	HTTPProxy *string `json:"httpProxy"`

	// httpsProxy is the URL of the proxy for HTTPS requests.
	// Authentication components will use this proxy for all
	// outbound HTTPS connections to external identity providers,
	// including OIDC discovery, token exchange, and user info requests.
	// An empty string means no HTTPS proxy is used.
	// +required
	HTTPSProxy *string `json:"httpsProxy"`

	// noProxy is a comma-separated list of hostnames and/or CIDRs and/or IPs
	// for which the proxy should not be used.
	// When set, requests to matching destinations bypass the configured
	// httpProxy and httpsProxy.
	// When omitted, no proxy bypass rules are configured for authentication
	// components (unless inherited from the cluster-wide proxy).
	// +optional
	NoProxy string `json:"noProxy,omitempty"`

	// trustedCA is a reference to a ConfigMap in the openshift-config
	// namespace containing a CA certificate bundle under the key
	// "ca-bundle.crt". This CA bundle is appended to the system trust
	// store and used for proxy TLS connections by authentication components.
	// When omitted, only the system trust store (including any cluster-wide
	// proxy CA) is used.
	// +optional
	TrustedCA configv1.ConfigMapNameReference `json:"trustedCA,omitempty"`
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
