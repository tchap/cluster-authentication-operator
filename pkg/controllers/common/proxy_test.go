package common

import (
	"strings"
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
				NoProxy:    ".local",
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
			wantNoProxy:    ".cluster.local,.local,.svc,127.0.0.1,localhost",
		},
		{
			name:      "empty component proxy means explicitly no proxy",
			authProxy: &operatorv1.AuthenticationProxyConfig{},
			clusterProxy: &configv1.Proxy{
				Status: configv1.ProxyStatus{
					HTTPProxy:  "http://cluster:3128",
					HTTPSProxy: "http://cluster:3129",
					NoProxy:    ".cluster.local",
				},
			},
			wantHTTPProxy:  "",
			wantHTTPSProxy: "",
			wantNoProxy:    ".cluster.local,.svc,127.0.0.1,localhost",
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
			name: "component proxy with partial values",
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

func TestMergeNoProxy(t *testing.T) {
	tests := []struct {
		name        string
		userNoProxy string
		want        string
	}{
		{
			name:        "static defaults only",
			userNoProxy: "",
			want:        ".cluster.local,.svc,127.0.0.1,localhost",
		},
		{
			name:        "user entries merged with defaults",
			userNoProxy: ".corp.example.com,10.0.0.0/8",
			want:        ".cluster.local,.corp.example.com,.svc,10.0.0.0/8,127.0.0.1,localhost",
		},
		{
			name:        "whitespace in user entries is trimmed",
			userNoProxy: " .corp.example.com , 10.0.0.0/8 ",
			want:        ".cluster.local,.corp.example.com,.svc,10.0.0.0/8,127.0.0.1,localhost",
		},
		{
			name:        "empty entries in user noProxy are skipped",
			userNoProxy: ".corp.example.com,,,.other",
			want:        ".cluster.local,.corp.example.com,.other,.svc,127.0.0.1,localhost",
		},
		{
			name:        "user entries that overlap with defaults are deduplicated",
			userNoProxy: ".cluster.local,localhost,.custom",
			want:        ".cluster.local,.custom,.svc,127.0.0.1,localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeNoProxy(tt.userNoProxy)
			if got != tt.want {
				t.Errorf("mergeNoProxy() = %q, want %q", got, tt.want)
			}

			entries := strings.Split(got, ",")
			seen := make(map[string]bool)
			for _, e := range entries {
				if seen[e] {
					t.Errorf("duplicate entry in noProxy: %q", e)
				}
				seen[e] = true
			}
		})
	}
}
