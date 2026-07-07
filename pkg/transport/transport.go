package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/net/http/httpproxy"

	knet "k8s.io/apimachinery/pkg/util/net"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	ktransport "k8s.io/client-go/transport"
)

// TODO move all this to library-go

// ProxyFunc returns the proxy URL for a given request URL.
type ProxyFunc func(reqURL *url.URL) (*url.URL, error)

// TransportFor returns an http.Transport for the given CA and client cert data (which may be empty).
func TransportFor(serverName string, caData, certData, keyData []byte) (http.RoundTripper, error) {
	if len(caData) == 0 && len(certData) == 0 && len(keyData) == 0 {
		return ktransport.DebugWrappers(http.DefaultTransport), nil
	}
	transport, err := newTransport(serverName, caData, certData, keyData)
	if err != nil {
		return nil, err
	}
	return ktransport.DebugWrappers(transport), nil
}

// CAReference identifies a CA bundle stored in a ConfigMap.
type CAReference struct {
	ConfigMapName string
	ConfigMapKey  string
}

// TransportForCARef creates an http.RoundTripper with TLS configured from
// the given CA ConfigMap references and explicit proxy settings. Each
// CAReference is loaded via the lister and appended to the trust pool.
// When httpProxy or httpsProxy is non-empty, the transport routes requests
// through the proxy. When both are empty, no proxy is used.
func TransportForCARef(
	cmLister corelistersv1.ConfigMapLister,
	caRefs []CAReference,
	httpProxy, httpsProxy, noProxy string,
) (http.RoundTripper, error) {
	var caData []byte
	for _, ref := range caRefs {
		data, err := LoadCAData(cmLister, ref.ConfigMapName, ref.ConfigMapKey)
		if err != nil {
			return nil, err
		}
		caData = append(caData, data...)
	}

	if len(caData) == 0 && len(httpProxy) == 0 && len(httpsProxy) == 0 {
		return TransportFor("", nil, nil, nil)
	}

	transport, err := newTransport("", caData, nil, nil)
	if err != nil {
		return nil, err
	}

	if len(httpProxy) > 0 || len(httpsProxy) > 0 {
		proxyCfg := httpproxy.Config{
			HTTPProxy:  httpProxy,
			HTTPSProxy: httpsProxy,
			NoProxy:    noProxy,
		}
		proxyFunc := proxyCfg.ProxyFunc()
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return proxyFunc(req.URL)
		}
	} else {
		transport.Proxy = nil
	}

	return ktransport.DebugWrappers(transport), nil
}

// LoadCAData reads CA bundle bytes from a ConfigMap in openshift-config.
// It checks Data first and falls back to BinaryData for the given key.
func LoadCAData(cmLister corelistersv1.ConfigMapLister, caConfigMapName, key string) ([]byte, error) {
	cm, err := cmLister.ConfigMaps("openshift-config").Get(caConfigMapName)
	if err != nil {
		return nil, fmt.Errorf("unable to get configmap \"%s/%s\": %w", "openshift-config", caConfigMapName, err)
	}

	caData := []byte(cm.Data[key])
	if len(caData) == 0 {
		caData = cm.BinaryData[key]
	}
	if len(caData) == 0 {
		return nil, fmt.Errorf("configmap \"%s/%s\" has no CA data at key %q", "openshift-config", caConfigMapName, key)
	}
	return caData, nil
}

// newTransport creates a fresh *http.Transport with TLS configured from the given parameters.
func newTransport(serverName string, caData, certData, keyData []byte) (*http.Transport, error) {
	if (len(certData) == 0) != (len(keyData) == 0) {
		return nil, errors.New("cert and key data must be specified together")
	}

	// copy default transport
	transport := knet.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: serverName,
		},
	})

	if len(caData) != 0 {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error loading system cert pool: %w", err)
		}

		if ok := roots.AppendCertsFromPEM(caData); !ok {
			// avoid logging data that could contain keys
			return nil, errors.New("error loading cert pool from CA data")
		}

		transport.TLSClientConfig.RootCAs = roots
	}

	if len(certData) != 0 {
		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			// avoid logging data that will contain keys
			return nil, errors.New("error loading x509 keypair from cert and key data")
		}

		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return transport, nil
}
