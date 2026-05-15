package proxyconfig

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	v1 "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"

	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

// proxyConfigChecker reports bad proxy configurations.
type proxyConfigChecker struct {
	routeLister     v1.RouteLister
	configMapLister corev1lister.ConfigMapLister
	routeName       string
	routeNamespace  string
	caConfigMaps    map[string][]string // ns -> []configmapNames

	oauthLister         configv1listers.OAuthLister
	operatorAuthLister  operatorv1listers.AuthenticationLister
	featureGateAccessor featuregates.FeatureGateAccess

	authConfigChecker common.AuthConfigChecker

	lastIdPValidationHash string
}

func NewProxyConfigChecker(
	routeInformer routeinformer.RouteInformer,
	configMapInformers v1helpers.KubeInformersForNamespaces,
	authConfigChecker common.AuthConfigChecker,
	routeNamespace string,
	routeName string,
	caConfigMaps map[string][]string,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClient,
	oauthLister configv1listers.OAuthLister,
	operatorAuthLister operatorv1listers.AuthenticationLister,
	featureGateAccessor featuregates.FeatureGateAccess,
	operatorAuthInformer factory.Informer,
) factory.Controller {
	p := proxyConfigChecker{
		routeLister:         routeInformer.Lister(),
		configMapLister:     configMapInformers.ConfigMapLister(),
		routeName:           routeName,
		routeNamespace:      routeNamespace,
		caConfigMaps:        caConfigMaps,
		oauthLister:         oauthLister,
		operatorAuthLister:  operatorAuthLister,
		featureGateAccessor: featureGateAccessor,
		authConfigChecker:   authConfigChecker,
	}

	c := factory.New().
		WithSync(p.sync).
		WithInformers(
			routeInformer.Informer(),
		).
		WithInformers(common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...)

	if operatorAuthInformer != nil {
		c = c.WithInformers(operatorAuthInformer)
	}

	c = c.ResyncEvery(60 * time.Minute).
		WithSyncDegradedOnError(operatorClient)

	for ns, configMapNames := range caConfigMaps {
		c.WithFilteredEventsInformers(
			factory.NamesFilter(configMapNames...),
			configMapInformers.InformersFor(ns).Core().V1().ConfigMaps().Informer(),
		)
	}

	return c.ToController("ProxyConfigController", recorder.WithComponentSuffix("proxy-config-controller"))
}

// sync attempts to connect to route using configured proxy settings and reports any error.
func (p *proxyConfigChecker) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if oidcAvailable, err := p.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		return nil
	}

	// Check for component-scoped proxy first
	authProxy, proxyErr := common.GetComponentProxyConfig(p.featureGateAccessor, p.operatorAuthLister)
	if proxyErr != nil {
		klog.Warningf("failed to get component proxy config, falling back to cluster-wide proxy: %v", proxyErr)
	}
	if authProxy != nil {
		return p.validateComponentProxy(ctx, syncCtx.Recorder(), authProxy)
	}

	proxyConfig := httpproxy.FromEnvironment()
	if !isProxyConfigured(proxyConfig) {
		return nil
	}

	route, err := p.routeLister.Routes(p.routeNamespace).Get(p.routeName)
	if err != nil {
		return err
	}

	routeURL, _, err := routeapihelpers.IngressURI(route, "")
	if err != nil {
		return err
	}
	routeURL.Path = "healthz"

	clientWithProxy, clientWithoutProxy, err := p.createHTTPClients()
	if err != nil {
		return err
	}

	return checkProxyConfig(ctx, routeURL, proxyConfig.NoProxy, clientWithProxy, clientWithoutProxy)
}

func (p *proxyConfigChecker) validateComponentProxy(ctx context.Context, recorder events.Recorder, authProxy *operatorv1.AuthenticationProxyConfig) error {
	httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(authProxy, nil)
	if len(httpProxy) == 0 && len(httpsProxy) == 0 {
		klog.V(4).Info("Component proxy configured with empty values, skipping validation")
		return nil
	}

	route, err := p.routeLister.Routes(p.routeNamespace).Get(p.routeName)
	if err != nil {
		return err
	}

	routeURL, _, err := routeapihelpers.IngressURI(route, "")
	if err != nil {
		return err
	}
	routeURL.Path = "healthz"

	caPool, err := p.getCACerts()
	if err != nil {
		return err
	}

	// Load component proxy CA if configured
	if len(authProxy.TrustedCA.Name) > 0 {
		if caCM, caErr := p.configMapLister.ConfigMaps("openshift-config").Get(authProxy.TrustedCA.Name); caErr == nil {
			caPool.AppendCertsFromPEM([]byte(caCM.Data["ca-bundle.crt"]))
		}
	}

	tlsConfig := &tls.Config{RootCAs: caPool}

	componentProxyCfg := httpproxy.Config{
		HTTPProxy:  httpProxy,
		HTTPSProxy: httpsProxy,
		NoProxy:    noProxy,
	}
	proxyFn := componentProxyCfg.ProxyFunc()

	clientWithProxy := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy: func(req *http.Request) (*url.URL, error) {
				return proxyFn(req.URL)
			},
		},
	}
	clientWithoutProxy := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	if err := checkProxyConfig(ctx, routeURL, noProxy, clientWithProxy, clientWithoutProxy); err != nil {
		return err
	}

	p.validateIdPConnectivity(ctx, recorder, clientWithProxy, httpProxy, httpsProxy, noProxy)

	return nil
}

// validateIdPConnectivity tests that configured IdP endpoints are reachable through
// the component proxy. Only runs on config change (tracked by hash). Reports warnings
// for transient IdP failures instead of returning errors (which would set Degraded),
// since external IdPs can be unreachable for reasons unrelated to proxy configuration.
func (p *proxyConfigChecker) validateIdPConnectivity(ctx context.Context, recorder events.Recorder, client *http.Client, httpProxy, httpsProxy, noProxy string) {
	oauthConfig, err := p.oauthLister.Get("cluster")
	if err != nil {
		klog.V(4).Infof("unable to get oauth config for IdP validation: %v", err)
		return
	}

	idpURLs := extractIdPURLs(oauthConfig)
	if len(idpURLs) == 0 {
		return
	}

	hash := computeIdPValidationHash(httpProxy, httpsProxy, noProxy, idpURLs)
	if hash == p.lastIdPValidationHash {
		return
	}

	var unreachable []string
	for _, idpURL := range idpURLs {
		if err := isEndpointReachable(ctx, idpURL, client); err != nil {
			klog.Warningf("IdP endpoint %q is unreachable through component proxy: %v", idpURL, err)
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", idpURL, err))
		}
	}
	if len(unreachable) > 0 {
		recorder.Warningf("IdPEndpointUnreachable", "IdP endpoints unreachable through component proxy: %s", strings.Join(unreachable, "; "))
	} else {
		p.lastIdPValidationHash = hash
	}
}

// extractIdPURLs returns external URLs from configured identity providers.
func extractIdPURLs(oauthConfig *configv1.OAuth) []string {
	var urls []string
	for _, idp := range oauthConfig.Spec.IdentityProviders {
		switch {
		case idp.OpenID != nil && len(idp.OpenID.Issuer) > 0:
			issuer := strings.TrimSuffix(idp.OpenID.Issuer, "/")
			urls = append(urls, issuer+"/.well-known/openid-configuration")
		case idp.GitHub != nil && len(idp.GitHub.Hostname) > 0:
			urls = append(urls, "https://"+idp.GitHub.Hostname)
		case idp.GitLab != nil && len(idp.GitLab.URL) > 0:
			urls = append(urls, idp.GitLab.URL)
		case idp.Keystone != nil && len(idp.Keystone.URL) > 0:
			urls = append(urls, idp.Keystone.URL)
		case idp.BasicAuth != nil && len(idp.BasicAuth.URL) > 0:
			urls = append(urls, idp.BasicAuth.URL)
		}
	}
	return urls
}

func computeIdPValidationHash(httpProxy, httpsProxy, noProxy string, idpURLs []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", httpProxy, httpsProxy, noProxy)
	for _, u := range idpURLs {
		fmt.Fprintf(h, "%s\n", u)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// checkProxyConfig determines any mis-configuration in proxy settings by attempting
// to connect to endpoint directly and via proxy and comparing the results with expectations.
func checkProxyConfig(ctx context.Context, endpointURL *url.URL, noProxy string, clientWithProxy, clientWithoutProxy *http.Client) error {
	withProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL.String(), clientWithProxy) })
	withoutProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL.String(), clientWithoutProxy) })
	noProxyMatchesEndpoint := parseNoProxy(noProxy).matches(canonicalAddr(endpointURL))

	if noProxyMatchesEndpoint && withoutProxy() != nil {
		if withProxy() == nil {
			return fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %v", endpointURL.String(), noProxy, withoutProxy())
		}
		return fmt.Errorf("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%v) and without proxy(%v)", endpointURL.String(), noProxy, withProxy(), withoutProxy())
	}

	if !noProxyMatchesEndpoint && withProxy() != nil {
		if withoutProxy() == nil {
			return fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(%q) with error: %v", endpointURL.String(), noProxy, withProxy())
		}
		return fmt.Errorf("endpoint(%q) is unreachable with proxy(%v) and without proxy(%v)", endpointURL.String(), withProxy(), withoutProxy())
	}

	return nil
}

// createHTTPClients returns two http clients, one with proxy and another without proxy
func (p *proxyConfigChecker) createHTTPClients() (*http.Client, *http.Client, error) {
	caPool, err := p.getCACerts()
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs: caPool,
	}

	return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				Proxy:           proxyFunc,
			},
		}, &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}, nil
}

// getCACerts retrieves the CA bundle in openshift cluster
func (p *proxyConfigChecker) getCACerts() (*x509.CertPool, error) {
	caPool := x509.NewCertPool()

	for ns, configMaps := range p.caConfigMaps {
		for _, cmName := range configMaps {
			caCM, err := p.configMapLister.ConfigMaps(ns).Get(cmName)
			if err != nil {
				return nil, err
			}

			// In case this causes performance issues, consider caching the trusted
			// certs pool.
			// At the time of writing this comment, this should only happen once
			// every 5 minutes and the trusted-ca CM contains around 130 certs.
			if ok := caPool.AppendCertsFromPEM([]byte(caCM.Data["ca-bundle.crt"])); !ok {
				return nil, fmt.Errorf("unable to append system trust ca bundle")
			}
		}
	}

	return caPool, nil
}

// isEndpointReachable returns nil if the given endpoint can be reached using the given client
func isEndpointReachable(ctx context.Context, endpointURL string, client *http.Client) error {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second) // avoid waiting forever
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%q returned %d", endpointURL, resp.StatusCode)
	}
	return nil
}

func isProxyConfigured(proxyConfig *httpproxy.Config) bool {
	return proxyConfig != nil && (len(proxyConfig.HTTPProxy) != 0 || len(proxyConfig.HTTPSProxy) != 0)
}

// proxyFunc returns the proxy URL to be used for a given request
// when NO_PROXY is ignored.
func proxyFunc(req *http.Request) (*url.URL, error) {
	proxyConfig := httpproxy.FromEnvironment()
	if req.URL.Scheme == "https" && len(proxyConfig.HTTPSProxy) > 0 {
		proxyURL, err := url.Parse(proxyConfig.HTTPSProxy)
		if err == nil {
			return proxyURL, nil
		}
		klog.V(4).Infof("failed to parse https proxy %q", proxyConfig.HTTPSProxy)
	}

	proxyURL, err := url.Parse(proxyConfig.HTTPProxy)
	if err != nil {
		return nil, err
	}
	return proxyURL, nil
}

// newLazyChecker returns a function that calculates an error value once
// and returns that error in subsequent calls
func newLazyChecker(f func() error) func() error {
	var err error
	var once sync.Once
	return func() error {
		once.Do(func() {
			err = f()
		})
		return err
	}
}
