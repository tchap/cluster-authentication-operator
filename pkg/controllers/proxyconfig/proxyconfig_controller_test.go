package proxyconfig

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"golang.org/x/net/http/httpproxy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

func Test_isProxyConfigured(t *testing.T) {
	tests := []struct {
		name        string
		proxyConfig *httpproxy.Config
		want        bool
	}{
		{
			name: "without proxy",
		},
		{
			name: "with http proxy",
			proxyConfig: &httpproxy.Config{
				HTTPProxy: "proxy-url",
			},
			want: true,
		},
		{
			name: "with https proxy",
			proxyConfig: &httpproxy.Config{
				HTTPSProxy: "proxy-url",
			},
			want: true,
		},
		{
			name: "with http and https proxy",
			proxyConfig: &httpproxy.Config{
				HTTPProxy:  "proxy-url",
				HTTPSProxy: "proxy-url",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProxyConfigured(tt.proxyConfig); got != tt.want {
				t.Errorf("isProxyConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_proxyFunc(t *testing.T) {
	httpsProxy := "https://test.com:443"
	httpsProxyURL, err := url.Parse(httpsProxy)
	if err != nil {
		t.Fatal(err)
	}

	httpProxy := "test.com:80"
	httpProxyURL, err := url.Parse(httpProxy)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		httpsProxy string
		httpProxy  string
		req        *http.Request
		want       *url.URL
		wantErr    bool
	}{
		{
			name:       "valid https proxy with https url scheme",
			httpsProxy: httpsProxy,
			req: &http.Request{
				URL: httpsProxyURL,
			},
			want: httpsProxyURL,
		},
		{
			name:      "valid http proxy with http url scheme",
			httpProxy: httpProxy,
			req: &http.Request{
				URL: httpProxyURL,
			},
			want: httpProxyURL,
		},
		{
			name:      "valid http proxy with https url scheme",
			httpProxy: httpProxy,
			req: &http.Request{
				URL: httpsProxyURL,
			},
			want: httpProxyURL,
		},
		{
			name:       "invalid https proxy but valid http proxy",
			httpsProxy: "this-url-is-invalid%1^",
			httpProxy:  httpProxy,
			req: &http.Request{
				URL: httpsProxyURL,
			},
			want: httpProxyURL,
		},
		{
			name:       "invalid https proxy and invalid http proxy",
			httpsProxy: "this-url-is-invalid%1^",
			httpProxy:  "this-url-is-invalid%1^",
			req: &http.Request{
				URL: httpsProxyURL,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Setenv("HTTPS_PROXY", tt.httpsProxy); err != nil {
				t.Error(err)
				return
			}

			if err := os.Setenv("HTTP_PROXY", tt.httpProxy); err != nil {
				t.Error(err)
				return
			}

			got, err := proxyFunc(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("proxyFunc() got = %v, want %v", got, tt.want)
			}

			if err := os.Unsetenv("HTTPS_PROXY"); err != nil {
				t.Error(err)
				return
			}
			if err := os.Unsetenv("HTTP_PROXY"); err != nil {
				t.Error(err)
				return
			}
		})
	}
}

func Test_checkProxyConfig(t *testing.T) {
	endpoint := "https://proxy.testing.com:443"
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	goodHTTPClient := &http.Client{
		Transport: &workingHTTPRoundTripper{},
	}
	badHTTPClient := &http.Client{
		Transport: &faultyHTTPRoundTripper{},
	}
	tests := []struct {
		name               string
		noProxy            string
		clientWithProxy    *http.Client
		clientWithoutProxy *http.Client
		wantErr            error
	}{
		{
			name:            "good proxy config with endpoint not matching noProxy",
			clientWithProxy: goodHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching noProxy",
			noProxy:            "proxy.testing.com",
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching domain in noProxy",
			noProxy:            "testing.com",
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "endpoint matching noProxy is unreachable with/without proxy",
			noProxy:            "testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, "testing.com", endpoint, endpoint),
		},
		{
			name:               "endpoint matching noProxy is reachable with proxy",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    goodHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %q returned 404", endpoint, "proxy.testing.com", endpoint),
		},
		{
			name:               "endpoint not matching noProxy is reachable without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: goodHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(\"\") with error: %q returned 404", endpoint, endpoint),
		},
		{
			name:               "endpoint not matching noProxy is unreachable with/without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, endpoint, endpoint),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkProxyConfig(context.TODO(), endpointURL, tt.noProxy, tt.clientWithProxy, tt.clientWithoutProxy)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("checkProxyConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

type workingHTTPRoundTripper struct{}
type faultyHTTPRoundTripper struct{}

func (s *workingHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200}, nil
}

func (s *faultyHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 404}, nil
}

func Test_validateIdPConnectivity(t *testing.T) {
	tests := []struct {
		name           string
		idps           []configv1.IdentityProvider
		client         *http.Client
		wantEvent      bool
		wantEventParts []string
	}{
		{
			name:   "When all IdP endpoints are reachable it should not emit an event",
			client: &http.Client{Transport: &workingHTTPRoundTripper{}},
			idps: []configv1.IdentityProvider{
				{
					Name: "reachable",
					IdentityProviderConfig: configv1.IdentityProviderConfig{
						Type: configv1.IdentityProviderTypeGitLab,
						GitLab: &configv1.GitLabIdentityProvider{
							URL: "https://gitlab.example.com",
						},
					},
				},
			},
		},
		{
			name:   "When an IdP endpoint is unreachable it should emit a warning event",
			client: &http.Client{Transport: &faultyHTTPRoundTripper{}},
			idps: []configv1.IdentityProvider{
				{
					Name: "unreachable",
					IdentityProviderConfig: configv1.IdentityProviderConfig{
						Type: configv1.IdentityProviderTypeGitLab,
						GitLab: &configv1.GitLabIdentityProvider{
							URL: "https://gitlab.example.com",
						},
					},
				},
			},
			wantEvent:      true,
			wantEventParts: []string{"gitlab.example.com"},
		},
		{
			name:   "When multiple IdP endpoints are unreachable it should emit a single event listing all",
			client: &http.Client{Transport: &faultyHTTPRoundTripper{}},
			idps: []configv1.IdentityProvider{
				{
					Name: "gitlab",
					IdentityProviderConfig: configv1.IdentityProviderConfig{
						Type: configv1.IdentityProviderTypeGitLab,
						GitLab: &configv1.GitLabIdentityProvider{
							URL: "https://gitlab.example.com",
						},
					},
				},
				{
					Name: "oidc",
					IdentityProviderConfig: configv1.IdentityProviderConfig{
						Type: configv1.IdentityProviderTypeOpenID,
						OpenID: &configv1.OpenIDIdentityProvider{
							Issuer: "https://sso.example.com",
						},
					},
				},
			},
			wantEvent:      true,
			wantEventParts: []string{"gitlab.example.com", "sso.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(&configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.OAuthSpec{
					IdentityProviders: tt.idps,
				},
			}); err != nil {
				t.Fatal(err)
			}

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			p := &proxyConfigChecker{
				oauthLister: configv1listers.NewOAuthLister(indexer),
			}

			p.validateIdPConnectivity(context.Background(), recorder, tt.client, "", "", "")

			recordedEvents := recorder.Events()
			if tt.wantEvent && len(recordedEvents) == 0 {
				t.Fatal("expected a warning event but none was recorded")
			}
			if !tt.wantEvent && len(recordedEvents) > 0 {
				t.Fatalf("expected no events but got %d: %v", len(recordedEvents), recordedEvents)
			}
			if tt.wantEvent {
				if len(recordedEvents) != 1 {
					t.Fatalf("expected exactly 1 event but got %d", len(recordedEvents))
				}
				event := recordedEvents[0]
				if event.Reason != "IdPEndpointUnreachable" {
					t.Errorf("expected reason IdPEndpointUnreachable, got %q", event.Reason)
				}
				for _, part := range tt.wantEventParts {
					if !strings.Contains(event.Message, part) {
						t.Errorf("event message %q does not contain expected substring %q", event.Message, part)
					}
				}
			}
		})
	}
}
