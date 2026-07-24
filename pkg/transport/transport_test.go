package transport

import (
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/cluster-authentication-operator/pkg/internal/transporttest"
)

func TestNewTransport(t *testing.T) {
	_, caPEM := transporttest.MakeSelfSignedCA(t)

	t.Run("nil caData returns transport without RootCAs", func(t *testing.T) {
		tr, err := NewTransport("", nil, nil, nil)
		require.NoError(t, err)
		require.Nil(t, transporttest.RootCAs(t, tr))
	})

	t.Run("cert without key returns error", func(t *testing.T) {
		_, err := NewTransport("", nil, []byte("cert"), nil)
		require.ErrorContains(t, err, "cert and key data must be specified together")
	})

	t.Run("key without cert returns error", func(t *testing.T) {
		_, err := NewTransport("", nil, nil, []byte("key"))
		require.ErrorContains(t, err, "cert and key data must be specified together")
	})

	t.Run("valid CA configures RootCAs", func(t *testing.T) {
		tr, err := NewTransport("", caPEM, nil, nil)
		require.NoError(t, err)
		transporttest.RequirePoolContains(t, transporttest.RootCAs(t, tr), caPEM)
	})

	t.Run("server name is propagated", func(t *testing.T) {
		tr, err := NewTransport("my-server", nil, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, tr.TLSClientConfig)
		require.Equal(t, "my-server", tr.TLSClientConfig.ServerName)
	})

	t.Run("valid cert and key pair is loaded", func(t *testing.T) {
		ca, _ := transporttest.MakeSelfSignedCA(t)

		clientCfg, err := ca.MakeClientCertificateForDuration(&user.DefaultInfo{Name: "test-client"}, time.Hour)
		require.NoError(t, err)

		certPEM, keyPEM, err := clientCfg.GetPEMBytes()
		require.NoError(t, err)

		tr, err := NewTransport("", nil, certPEM, keyPEM)
		require.NoError(t, err)
		require.NotNil(t, tr.TLSClientConfig)
		require.Len(t, tr.TLSClientConfig.Certificates, 1)

		block, _ := pem.Decode(certPEM)
		require.NotNil(t, block)
		require.Equal(t, block.Bytes, tr.TLSClientConfig.Certificates[0].Certificate[0])
	})

	t.Run("invalid cert and key pair returns error", func(t *testing.T) {
		_, err := NewTransport("", nil, []byte("bad-cert"), []byte("bad-key"))
		require.ErrorContains(t, err, "error loading x509 keypair from cert and key data")
	})
}

func TestLoadCAData(t *testing.T) {
	caData := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	tests := []struct {
		name    string
		cms     []*corev1.ConfigMap
		cmName  string
		cmKey   string
		want    []byte
		wantErr string
	}{
		{
			name: "returns Data value",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": string(caData)},
			}},
			cmName: "my-ca",
			cmKey:  "ca-bundle.crt",
			want:   caData,
		},
		{
			name: "falls back to BinaryData",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				BinaryData: map[string][]byte{"ca-bundle.crt": caData},
			}},
			cmName: "my-ca",
			cmKey:  "ca-bundle.crt",
			want:   caData,
		},
		{
			name: "Data takes precedence over BinaryData",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "from-data"},
				BinaryData: map[string][]byte{"ca-bundle.crt": []byte("from-binary")},
			}},
			cmName: "my-ca",
			cmKey:  "ca-bundle.crt",
			want:   []byte("from-data"),
		},
		{
			name:    "configmap not found",
			cmName:  "nonexistent",
			cmKey:   "ca-bundle.crt",
			wantErr: `unable to get configmap "openshift-config/nonexistent": configmap "nonexistent" not found`,
		},
		{
			name: "key missing from both Data and BinaryData",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"other-key": "value"},
			}},
			cmName:  "my-ca",
			cmKey:   "ca-bundle.crt",
			wantErr: `configmap "openshift-config/my-ca" has no CA data at key "ca-bundle.crt"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := newConfigMapLister(tt.cms...)
			got, err := LoadCAData(lister, tt.cmName, tt.cmKey)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func newConfigMapLister(cms ...*corev1.ConfigMap) corelistersv1.ConfigMapLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, cm := range cms {
		_ = indexer.Add(cm)
	}
	return corelistersv1.NewConfigMapLister(indexer)
}
