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

// CARefTransportFunc builds an http.RoundTripper for a given CA ConfigMap
// reference. The cmLister and any proxy settings are captured in the closure.
type CARefTransportFunc func(caConfigMapName, key string) (http.RoundTripper, error)

// TransportFor returns an http.Transport for the given ca and client cert data (which may be empty)
func TransportFor(serverName string, caData, certData, keyData []byte) (http.RoundTripper, error) {
	transport, err := transportForInner(serverName, caData, certData, keyData)
	if err != nil {
		return nil, err
	}
	return ktransport.DebugWrappers(transport), nil
}

func TransportForCARef(cmLister corelistersv1.ConfigMapLister, caConfigMapName, key string) (http.RoundTripper, error) {
	if len(caConfigMapName) == 0 {
		return TransportFor("", nil, nil, nil)
	}

	cm, err := cmLister.ConfigMaps("openshift-config").Get(caConfigMapName)
	if err != nil {
		return nil, err
	}
	caData := []byte(cm.Data[key])
	if len(caData) == 0 {
		caData = cm.BinaryData[key]
	}
	if len(caData) == 0 {
		return nil, fmt.Errorf("config map %s/%s has no ca data at key %s", "openshift-config", caConfigMapName, key)
	}
	return TransportFor("", caData, nil, nil)
}

// TransportForCARefWithProxy creates an http.RoundTripper with explicit proxy
// settings and optional extra CA data for the proxy's TLS certificate.
// When all proxy strings are empty, the transport uses no proxy at all
// (overriding http.ProxyFromEnvironment). When extraCAData is non-empty,
// it is appended to the CA cert pool used for TLS verification.
func TransportForCARefWithProxy(
	cmLister corelistersv1.ConfigMapLister,
	caConfigMapName, key string,
	httpProxy, httpsProxy, noProxy string,
	extraCAData []byte,
) (http.RoundTripper, error) {
	var caData []byte
	if len(caConfigMapName) > 0 {
		cm, err := cmLister.ConfigMaps("openshift-config").Get(caConfigMapName)
		if err != nil {
			return nil, err
		}
		caData = []byte(cm.Data[key])
		if len(caData) == 0 {
			caData = cm.BinaryData[key]
		}
		if len(caData) == 0 {
			return nil, fmt.Errorf("config map %s/%s has no ca data at key %s", "openshift-config", caConfigMapName, key)
		}
	}

	if len(extraCAData) > 0 {
		caData = append(append([]byte{}, caData...), extraCAData...)
	}

	rt, err := transportForInner("", caData, nil, nil)
	if err != nil {
		return nil, err
	}

	if t, ok := rt.(*http.Transport); ok {
		if len(httpProxy) > 0 || len(httpsProxy) > 0 {
			proxyCfg := httpproxy.Config{
				HTTPProxy:  httpProxy,
				HTTPSProxy: httpsProxy,
				NoProxy:    noProxy,
			}
			proxyFunc := proxyCfg.ProxyFunc()
			t.Proxy = func(req *http.Request) (*url.URL, error) {
				return proxyFunc(req.URL)
			}
		} else {
			t.Proxy = nil
		}
	}

	return ktransport.DebugWrappers(rt), nil
}

func transportForInner(serverName string, caData, certData, keyData []byte) (http.RoundTripper, error) {
	if len(caData) == 0 && len(certData) == 0 && len(keyData) == 0 {
		return http.DefaultTransport, nil
	}

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
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM(caData); !ok {
			// avoid logging data that could contain keys
			return nil, errors.New("error loading cert pool from ca data")
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
