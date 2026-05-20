package common

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
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
			wantNoProxy:    staticNoProxy,
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
			wantNoProxy:    staticNoProxy,
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
