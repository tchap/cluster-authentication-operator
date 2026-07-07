package transport

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/crypto"
)

func TestTransportForCARef(t *testing.T) {
	_, caPEM := makeSelfSignedCA(t)
	_, extraPEM := makeSelfSignedCA(t)
	emptyLister := newConfigMapLister()

	ref := func(name, key string) CAReference { return CAReference{ConfigMapName: name, ConfigMapKey: key} }

	t.Run("no refs no proxy returns default transport", func(t *testing.T) {
		rt, err := TransportForCARef(emptyLister, nil, "", "", "")
		require.NoError(t, err)
		require.NotNil(t, rt)
	})

	t.Run("single CA ref is loaded into TLS root CAs", func(t *testing.T) {
		lister := newConfigMapLister(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
			Data:       map[string]string{"ca-bundle.crt": string(caPEM)},
		})

		rt, err := TransportForCARef(lister, []CAReference{ref("my-ca", "ca-bundle.crt")}, "", "", "")
		require.NoError(t, err)

		tr := unwrapTransport(t, rt)
		requirePoolContains(t, rootCAs(t, tr), caPEM)
	})

	t.Run("configmap not found returns error", func(t *testing.T) {
		_, err := TransportForCARef(emptyLister, []CAReference{ref("missing-cm", "ca-bundle.crt")}, "", "", "")
		require.ErrorContains(t, err, `"missing-cm" not found`)
	})

	t.Run("configmap with empty key returns error", func(t *testing.T) {
		lister := newConfigMapLister(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "empty-ca", Namespace: "openshift-config"},
			Data:       map[string]string{},
		})

		_, err := TransportForCARef(lister, []CAReference{ref("empty-ca", "ca-bundle.crt")}, "", "", "")
		require.ErrorContains(t, err, `has no CA data at key "ca-bundle.crt"`)
	})

	t.Run("multiple CA refs are all loaded", func(t *testing.T) {
		lister := newConfigMapLister(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "ca-1", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": string(caPEM)},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "ca-2", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": string(extraPEM)},
			},
		)

		rt, err := TransportForCARef(lister, []CAReference{
			ref("ca-1", "ca-bundle.crt"),
			ref("ca-2", "ca-bundle.crt"),
		}, "", "", "")
		require.NoError(t, err)

		tr := unwrapTransport(t, rt)
		requirePoolContains(t, rootCAs(t, tr), caPEM, extraPEM)
	})

	t.Run("BinaryData key is used when Data key is absent", func(t *testing.T) {
		lister := newConfigMapLister(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "binary-ca", Namespace: "openshift-config"},
			BinaryData: map[string][]byte{"ca-bundle.crt": caPEM},
		})

		rt, err := TransportForCARef(lister, []CAReference{ref("binary-ca", "ca-bundle.crt")}, "", "", "")
		require.NoError(t, err)

		tr := unwrapTransport(t, rt)
		requirePoolContains(t, rootCAs(t, tr), caPEM)
	})

	t.Run("HTTP proxy is set on transport", func(t *testing.T) {
		rt, err := TransportForCARef(emptyLister, nil,
			"http://proxy.example.com:8080", "", "")
		require.NoError(t, err)

		tr := unwrapTransport(t, rt)
		require.NotNil(t, tr.Proxy)

		proxyURL, err := tr.Proxy(&http.Request{URL: mustParseURL(t, "http://target.example.com")})
		require.NoError(t, err)
		require.Equal(t, "http://proxy.example.com:8080", proxyURL.String())

		proxyURL, err = tr.Proxy(&http.Request{URL: mustParseURL(t, "https://target.example.com")})
		require.NoError(t, err)
		require.Nil(t, proxyURL, "HTTPS request should not use HTTP proxy")
	})

	t.Run("HTTPS proxy is set on transport", func(t *testing.T) {
		rt, err := TransportForCARef(emptyLister, nil,
			"", "https://secure-proxy.example.com:443", "")
		require.NoError(t, err)

		tr := unwrapTransport(t, rt)
		require.NotNil(t, tr.Proxy)

		proxyURL, err := tr.Proxy(&http.Request{URL: mustParseURL(t, "https://target.example.com")})
		require.NoError(t, err)
		require.Equal(t, "https://secure-proxy.example.com:443", proxyURL.String())

		proxyURL, err = tr.Proxy(&http.Request{URL: mustParseURL(t, "http://target.example.com")})
		require.NoError(t, err)
		require.Nil(t, proxyURL, "HTTP request should not use HTTPS proxy")
	})

	t.Run("noProxy excludes matching hosts from proxy", func(t *testing.T) {
		rt, err := TransportForCARef(emptyLister, nil,
			"http://proxy.example.com:8080", "http://proxy.example.com:8080",
			"noproxy.example.com")
		require.NoError(t, err)

		tr := unwrapTransport(t, rt)
		require.NotNil(t, tr.Proxy)

		proxyURL, err := tr.Proxy(&http.Request{URL: mustParseURL(t, "http://noproxy.example.com/path")})
		require.NoError(t, err)
		require.Nil(t, proxyURL, "request matching noProxy should not be proxied")

		proxyURL, err = tr.Proxy(&http.Request{URL: mustParseURL(t, "http://other.example.com/path")})
		require.NoError(t, err)
		require.NotNil(t, proxyURL, "request not matching noProxy should be proxied")
	})

	t.Run("proxy with multiple CA refs", func(t *testing.T) {
		lister := newConfigMapLister(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "idp-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": string(caPEM)},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "proxy-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": string(extraPEM)},
			},
		)

		rt, err := TransportForCARef(lister, []CAReference{
			ref("idp-ca", "ca-bundle.crt"),
			ref("proxy-ca", "ca-bundle.crt"),
		}, "http://proxy.example.com:8080", "", "")
		require.NoError(t, err)

		tr := unwrapTransport(t, rt)
		require.NotNil(t, tr.Proxy)
		requirePoolContains(t, rootCAs(t, tr), caPEM, extraPEM)
	})
}

func TestNewTransport(t *testing.T) {
	_, caPEM := makeSelfSignedCA(t)

	t.Run("nil caData returns transport without RootCAs", func(t *testing.T) {
		tr, err := newTransport("", nil, nil, nil)
		require.NoError(t, err)
		require.Nil(t, rootCAs(t, tr))
	})

	t.Run("cert without key returns error", func(t *testing.T) {
		_, err := newTransport("", nil, []byte("cert"), nil)
		require.ErrorContains(t, err, "cert and key data must be specified together")
	})

	t.Run("key without cert returns error", func(t *testing.T) {
		_, err := newTransport("", nil, nil, []byte("key"))
		require.ErrorContains(t, err, "cert and key data must be specified together")
	})

	t.Run("valid CA configures RootCAs", func(t *testing.T) {
		tr, err := newTransport("", caPEM, nil, nil)
		require.NoError(t, err)
		requirePoolContains(t, rootCAs(t, tr), caPEM)
	})

	t.Run("server name is propagated", func(t *testing.T) {
		tr, err := newTransport("my-server", nil, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, tr.TLSClientConfig)
		require.Equal(t, "my-server", tr.TLSClientConfig.ServerName)
	})

	t.Run("valid cert and key pair is loaded", func(t *testing.T) {
		ca, _ := makeSelfSignedCA(t)

		clientCfg, err := ca.MakeClientCertificateForDuration(&user.DefaultInfo{Name: "test-client"}, time.Hour)
		require.NoError(t, err)

		certPEM, keyPEM, err := clientCfg.GetPEMBytes()
		require.NoError(t, err)

		tr, err := newTransport("", nil, certPEM, keyPEM)
		require.NoError(t, err)
		require.NotNil(t, tr.TLSClientConfig)
		require.Len(t, tr.TLSClientConfig.Certificates, 1)

		block, _ := pem.Decode(certPEM)
		require.NotNil(t, block)
		require.Equal(t, block.Bytes, tr.TLSClientConfig.Certificates[0].Certificate[0])
	})

	t.Run("invalid cert and key pair returns error", func(t *testing.T) {
		_, err := newTransport("", nil, []byte("bad-cert"), []byte("bad-key"))
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

func makeSelfSignedCA(t *testing.T) (*crypto.CA, []byte) {
	t.Helper()
	tmpDir := t.TempDir()
	ca, err := crypto.MakeSelfSignedCA(
		path.Join(tmpDir, "ca.crt"),
		path.Join(tmpDir, "ca.key"),
		"", "testCA", time.Hour*24,
	)
	require.NoError(t, err)
	certPEM, _, err := ca.Config.GetPEMBytes()
	require.NoError(t, err)
	return ca, certPEM
}

func newConfigMapLister(cms ...*corev1.ConfigMap) corelistersv1.ConfigMapLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, cm := range cms {
		_ = indexer.Add(cm)
	}
	return corelistersv1.NewConfigMapLister(indexer)
}

func unwrapTransport(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()
	type unwrapper interface {
		WrappedRoundTripper() http.RoundTripper
	}
	for {
		if tr, ok := rt.(*http.Transport); ok {
			return tr
		}
		u, ok := rt.(unwrapper)
		require.True(t, ok, "cannot unwrap %T to *http.Transport", rt)
		rt = u.WrappedRoundTripper()
	}
}

func rootCAs(t *testing.T, tr *http.Transport) *x509.CertPool {
	t.Helper()
	require.NotNil(t, tr.TLSClientConfig)
	return tr.TLSClientConfig.RootCAs
}

func requirePoolContains(t *testing.T, pool *x509.CertPool, pemData ...[]byte) {
	t.Helper()
	require.NotNil(t, pool)
	opts := x509.VerifyOptions{Roots: pool}
	for _, p := range pemData {
		cert := mustCertFromPEM(t, p)
		_, err := cert.Verify(opts)
		require.NoError(t, err)
	}
}

func mustCertFromPEM(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "no PEM block found")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u
}
