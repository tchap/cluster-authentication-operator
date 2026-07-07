package oauth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/oauth"
)

func TestObserveComponentProxyTrustedCA(t *testing.T) {
	enabledGate := featuregates.NewHardcodedFeatureGateAccess(
		[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
		nil,
	)
	disabledGate := featuregates.NewHardcodedFeatureGateAccess(
		nil,
		[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
	)

	expectedConfig := map[string]interface{}{
		"oauthConfig": map[string]interface{}{
			"proxyTrustedCA": "/var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt",
		},
	}

	tests := []struct {
		name                string
		gate                featuregates.FeatureGateAccess
		auth                *operatorv1.Authentication
		lister              operatorv1listers.AuthenticationLister
		existingConfig      map[string]interface{}
		expected            map[string]interface{}
		expectErrorContains string
		expectEvent         bool
	}{
		{
			name:     "feature gate disabled returns empty config",
			gate:     disabledGate,
			auth:     nil,
			expected: map[string]interface{}{},
		},
		{
			name:     "no operator authentication resource returns empty config",
			gate:     enabledGate,
			auth:     nil,
			expected: map[string]interface{}{},
		},
		{
			name: "proxy configured without trustedCA returns empty config",
			gate: enabledGate,
			auth: &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "https://proxy:3128",
					},
				},
			},
			expected: map[string]interface{}{},
		},
		{
			name: "proxy configured with trustedCA sets path",
			gate: enabledGate,
			auth: &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "https://proxy:3128",
						TrustedCA: operatorv1.AuthenticationConfigMapReference{
							Name: "my-proxy-ca",
						},
					},
				},
			},
			expected:    expectedConfig,
			expectEvent: true,
		},
		{
			name: "trustedCA removed clears path",
			gate: enabledGate,
			auth: &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "https://proxy:3128",
					},
				},
			},
			existingConfig: expectedConfig,
			expected:       map[string]interface{}{},
			expectEvent:    true,
		},
		{
			name: "no change emits no event",
			gate: enabledGate,
			auth: &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "https://proxy:3128",
						TrustedCA: operatorv1.AuthenticationConfigMapReference{
							Name: "my-proxy-ca",
						},
					},
				},
			},
			existingConfig: expectedConfig,
			expected:       expectedConfig,
		},
		{
			name: "feature gate error propagates error and returns existing config",
			gate: featuregates.NewHardcodedFeatureGateAccessForTesting(
				nil, nil, make(chan struct{}), errors.New("not yet observed"),
			),
			auth:                nil,
			existingConfig:      expectedConfig,
			expected:            expectedConfig,
			expectErrorContains: "failed to get current feature gates",
		},
		{
			name:                "lister error propagates error and returns existing config",
			gate:                enabledGate,
			lister:              newErrorAuthLister(errors.New("connection refused")),
			existingConfig:      expectedConfig,
			expected:            expectedConfig,
			expectErrorContains: "failed to get operator.openshift.io/v1 authentication/cluster",
		},
		{
			name: "malformed existingConfig with non-map oauthConfig returns error",
			gate: enabledGate,
			auth: nil,
			existingConfig: map[string]interface{}{
				"oauthConfig": "not-a-map",
			},
			expected:            map[string]interface{}{"oauthConfig": "not-a-map"},
			expectErrorContains: "accessor error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLister := tt.lister
			if authLister == nil {
				indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				if tt.auth != nil {
					require.NoError(t, indexer.Add(tt.auth))
				}
				authLister = operatorv1listers.NewAuthenticationLister(indexer)
			}

			listers := configobservation.Listers{
				OperatorAuthLister:  authLister,
				FeatureGateAccessor: tt.gate,
			}

			existing := tt.existingConfig
			if existing == nil {
				existing = map[string]interface{}{}
			}

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			observed, errs := oauth.ObserveComponentProxyTrustedCA(listers, recorder, existing)

			if tt.expectErrorContains != "" {
				require.NotEmpty(t, errs)
				require.ErrorContains(t, errs[0], tt.expectErrorContains)
			} else {
				require.Empty(t, errs)
			}

			observedValue, _, _ := unstructured.NestedString(observed, "oauthConfig", "proxyTrustedCA")
			expectedValue, _, _ := unstructured.NestedString(tt.expected, "oauthConfig", "proxyTrustedCA")
			require.Equal(t, expectedValue, observedValue)

			recordedEvents := recorder.Events()
			if tt.expectEvent {
				require.Len(t, recordedEvents, 1)
				require.Equal(t, "ObserveComponentProxyTrustedCA", recordedEvents[0].Reason)
			} else {
				require.Empty(t, recordedEvents)
			}
		})
	}
}

type errorAuthLister struct {
	err error
}

func newErrorAuthLister(err error) operatorv1listers.AuthenticationLister {
	return &errorAuthLister{err}
}

func (l *errorAuthLister) List(_ labels.Selector) ([]*operatorv1.Authentication, error) {
	return nil, l.err
}

func (l *errorAuthLister) Get(_ string) (*operatorv1.Authentication, error) {
	return nil, l.err
}
