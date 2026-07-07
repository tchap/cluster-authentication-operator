package common

import (
	"net/http"
	"net/url"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestResolveProxyConfig(t *testing.T) {
	tests := []struct {
		name           string
		authProxy      *operatorv1.AuthenticationProxyConfig
		clusterProxy   *configv1.Proxy
		wantHTTPProxy  string
		wantHTTPSProxy string
		wantNoProxy    string
	}{
		{
			name: "component proxy with values overrides cluster proxy",
			authProxy: &operatorv1.AuthenticationProxyConfig{
				HTTPProxy:  "http://component:3128",
				HTTPSProxy: "http://component:3129",
			},
			clusterProxy: &configv1.Proxy{
				Status: configv1.ProxyStatus{
					HTTPProxy:  "http://cluster:3128",
					HTTPSProxy: "http://cluster:3129",
					NoProxy:    ".cluster.local",
				},
			},
			wantHTTPProxy:  "http://component:3128",
			wantHTTPSProxy: "http://component:3129",
			wantNoProxy:    ".cluster.local,.svc,127.0.0.1,localhost",
		},
		{
			name: "component proxy with user noProxy merges with defaults",
			authProxy: &operatorv1.AuthenticationProxyConfig{
				HTTPProxy: "http://component:3128",
				NoProxy:   []string{"idp.example.com", ".corp.example.com"},
			},
			wantHTTPProxy:  "http://component:3128",
			wantHTTPSProxy: "",
			wantNoProxy:    ".cluster.local,.corp.example.com,.svc,127.0.0.1,idp.example.com,localhost",
		},
		{
			name: "component proxy with user noProxy duplicating defaults deduplicates",
			authProxy: &operatorv1.AuthenticationProxyConfig{
				HTTPProxy: "http://component:3128",
				NoProxy:   []string{".svc", "idp.example.com", "127.0.0.1"},
			},
			wantHTTPProxy:  "http://component:3128",
			wantHTTPSProxy: "",
			wantNoProxy:    ".cluster.local,.svc,127.0.0.1,idp.example.com,localhost",
		},
		{
			name:      "nil component proxy falls back to cluster proxy",
			authProxy: nil,
			clusterProxy: &configv1.Proxy{
				Status: configv1.ProxyStatus{
					HTTPProxy:  "http://cluster:3128",
					HTTPSProxy: "http://cluster:3129",
					NoProxy:    ".cluster.local",
				},
			},
			wantHTTPProxy:  "http://cluster:3128",
			wantHTTPSProxy: "http://cluster:3129",
			wantNoProxy:    ".cluster.local",
		},
		{
			name:           "neither configured returns empty",
			authProxy:      nil,
			clusterProxy:   nil,
			wantHTTPProxy:  "",
			wantHTTPSProxy: "",
			wantNoProxy:    "",
		},
		{
			name:      "nil component proxy with empty cluster proxy status",
			authProxy: nil,
			clusterProxy: &configv1.Proxy{
				Status: configv1.ProxyStatus{},
			},
			wantHTTPProxy:  "",
			wantHTTPSProxy: "",
			wantNoProxy:    "",
		},
		{
			name: "component proxy with only httpsProxy set",
			authProxy: &operatorv1.AuthenticationProxyConfig{
				HTTPSProxy: "http://component:3129",
			},
			clusterProxy: &configv1.Proxy{
				Status: configv1.ProxyStatus{
					HTTPProxy:  "http://cluster:3128",
					HTTPSProxy: "http://cluster:3129",
					NoProxy:    ".cluster.local",
				},
			},
			wantHTTPProxy:  "",
			wantHTTPSProxy: "http://component:3129",
			wantNoProxy:    ".cluster.local,.svc,127.0.0.1,localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpProxy, httpsProxy, noProxy := ResolveProxyConfig(tt.authProxy, tt.clusterProxy)
			if httpProxy != tt.wantHTTPProxy {
				t.Errorf("httpProxy = %q, want %q", httpProxy, tt.wantHTTPProxy)
			}
			if httpsProxy != tt.wantHTTPSProxy {
				t.Errorf("httpsProxy = %q, want %q", httpsProxy, tt.wantHTTPSProxy)
			}
			if noProxy != tt.wantNoProxy {
				t.Errorf("noProxy = %q, want %q", noProxy, tt.wantNoProxy)
			}
		})
	}
}

func newOperatorAuthLister(auth *operatorv1.Authentication) operatorv1listers.AuthenticationLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if auth != nil {
		_ = indexer.Add(auth)
	}
	return operatorv1listers.NewAuthenticationLister(indexer)
}

func TestComponentProxyFunc(t *testing.T) {
	httpsReq, _ := http.NewRequest("GET", "https://idp.example.com/.well-known/openid-configuration", nil)
	httpReq, _ := http.NewRequest("GET", "http://idp.example.com/callback", nil)

	tests := []struct {
		name           string
		featureGate    featuregates.FeatureGateAccess
		authLister     operatorv1listers.AuthenticationLister
		req            *http.Request
		wantNilProxy   bool
		wantProxyHost  string
	}{
		{
			name:         "nil inputs fall back to env proxy (returns nil with no env set)",
			featureGate:  nil,
			authLister:   nil,
			req:          httpsReq,
			wantNilProxy: true,
		},
		{
			name: "feature gate disabled returns env proxy (nil with no env)",
			featureGate: featuregates.NewHardcodedFeatureGateAccess(
				nil,
				[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
			),
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://should-not-be-used:3128",
					},
				},
			}),
			req:          httpsReq,
			wantNilProxy: true,
		},
		{
			name: "feature gate enabled but no proxy configured returns env proxy (nil with no env)",
			featureGate: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
				nil,
			),
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			}),
			req:          httpsReq,
			wantNilProxy: true,
		},
		{
			name: "feature gate enabled with httpsProxy configured returns proxy for https request",
			featureGate: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
				nil,
			),
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			req:           httpsReq,
			wantProxyHost: "proxy.corp.example.com:3128",
		},
		{
			name: "feature gate enabled with httpProxy configured returns proxy for http request",
			featureGate: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
				nil,
			),
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			req:           httpReq,
			wantProxyHost: "proxy.corp.example.com:3128",
		},
		{
			name: "noProxy match returns nil proxy",
			featureGate: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
				nil,
			),
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
						NoProxy:    []string{"idp.example.com"},
					},
				},
			}),
			req:          httpsReq,
			wantNilProxy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env to ensure ProxyFromEnvironment returns nil
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("HTTPS_PROXY", "")
			t.Setenv("NO_PROXY", "")

			proxyFn := ComponentProxyFunc(tt.featureGate, tt.authLister)
			proxyURL, err := proxyFn(tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantNilProxy {
				if proxyURL != nil {
					t.Errorf("expected nil proxy URL, got %v", proxyURL)
				}
				return
			}

			if proxyURL == nil {
				t.Fatalf("expected proxy URL with host %q, got nil", tt.wantProxyHost)
			}
			gotHost := proxyURL.Host
			if gotHost == "" {
				gotHost = proxyURL.Opaque
			}
			if gotHost != tt.wantProxyHost {
				t.Errorf("proxy host = %q, want %q (full URL: %v)", gotHost, tt.wantProxyHost, proxyURL)
			}
		})
	}
}

func TestComponentProxyFunc_FeatureGateError(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")

	ch := make(chan struct{})
	fga := featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, ch, nil)

	proxyFn := ComponentProxyFunc(fga, nil)
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	proxyURL, err := proxyFn(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxyURL != (*url.URL)(nil) {
		t.Errorf("expected nil proxy on feature gate error fallback, got %v", proxyURL)
	}
}
