package readiness

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

type testRoundTripper struct {
	body      []byte
	status    int
	delay     time.Duration
	failErr   error
	failLeftN int
}

func (trt *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if trt.failLeftN > 0 {
		trt.failLeftN--
		return nil, trt.failErr
	}

	if trt.delay > 0 {
		select {
		case <-time.After(trt.delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	return &http.Response{
		StatusCode: trt.status,
		Body:       io.NopCloser(bytes.NewReader(trt.body)),
	}, nil
}

func Test_wellKnownReadyController_checkWellknownEndpointReady(t *testing.T) {
	tests := []struct {
		name        string
		cmOAuthData string
		rt          *testRoundTripper
		wantErr     bool
	}{
		{
			name:        "wellknown endpoint not found",
			cmOAuthData: `{"data": "some data"}`,
			rt:          &testRoundTripper{status: http.StatusNotFound},
			wantErr:     true,
		},
		{
			name:        "wellknown endpoint data is stale",
			cmOAuthData: `{"data": "new data"}`,
			rt: &testRoundTripper{
				status: http.StatusOK,
				body:   []byte(`{"data": "old data"}`),
			},
			wantErr: true,
		},
		{
			name:        "everything's fine",
			cmOAuthData: `{"data": "some data"}`,
			rt: &testRoundTripper{
				status: http.StatusOK,
				body:   []byte(`{"data": "some data"}`),
			},
		},
		{
			name:        "wellknown endpoint is intermittently unavailable",
			cmOAuthData: `{"data": "some data"}`,
			rt: &testRoundTripper{
				status:    http.StatusOK,
				body:      []byte(`{"data": "some data"}`),
				failLeftN: 2,
				failErr:   net.Error(&net.DNSError{}),
			},
		},
		{
			name:        "wellknown endpoint request always fails",
			cmOAuthData: `{"data": "some data"}`,
			rt: &testRoundTripper{
				status:    http.StatusOK,
				body:      []byte(`{"data": "some data"}`),
				failLeftN: 100,
				failErr:   net.Error(&net.DNSError{}),
			},
			wantErr: true,
		},
		{
			name:        "wellknown endpoint response takes too long",
			cmOAuthData: `{"data": "some data"}`,
			rt: &testRoundTripper{
				delay:  7 * time.Second,
				status: http.StatusOK,
				body:   []byte(`{"data": "some data"}`),
			},
			wantErr: true,
		},
		{
			name:        "wellknown endpoint response is slightly delayed",
			cmOAuthData: `{"data": "some data"}`,
			rt: &testRoundTripper{
				delay:  3 * time.Second,
				status: http.StatusOK,
				body:   []byte(`{"data": "some data"}`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-openshift",
						Namespace: "openshift-config-managed",
					},
					Data: map[string]string{
						"oauthMetadata": tt.cmOAuthData,
					},
				}

				cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				require.NoError(t, cmIndexer.Add(cm))

				c := &wellKnownReadyController{
					configMapLister: corev1listers.NewConfigMapLister(cmIndexer),
				}

				testCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if err := c.checkWellknownEndpointReady(testCtx, "127.0.0.1:443", tt.rt); (err != nil) != tt.wantErr {
					t.Errorf("wellKnownReadyController.checkWellknownEndpointReady() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		})
	}
}
