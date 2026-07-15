package transporttest

import (
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
)

// UnwrapTransport recursively unwraps a RoundTripper (e.g. from
// DebugWrappers) until it reaches the underlying *http.Transport.
func UnwrapTransport(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()
	type unwrapper interface {
		WrappedRoundTripper() http.RoundTripper
	}
	for {
		if tr, ok := rt.(*http.Transport); ok {
			return tr
		}
		u, ok := rt.(unwrapper)
		if !ok {
			t.Fatalf("cannot unwrap %T to *http.Transport", rt)
		}
		rt = u.WrappedRoundTripper()
	}
}

// MakeSelfSignedCA generates a self-signed CA certificate and returns
// the CA object and its PEM-encoded certificate bytes.
func MakeSelfSignedCA(t *testing.T) (*crypto.CA, []byte) {
	t.Helper()
	tmpDir := t.TempDir()
	ca, err := crypto.MakeSelfSignedCA(
		path.Join(tmpDir, "ca.crt"),
		path.Join(tmpDir, "ca.key"),
		"", "testCA", time.Hour*24,
	)
	if err != nil {
		t.Fatalf("failed to create self-signed CA: %v", err)
	}
	certPEM, _, err := ca.Config.GetPEMBytes()
	if err != nil {
		t.Fatalf("failed to get CA PEM bytes: %v", err)
	}
	return ca, certPEM
}

// MustParseURL parses a raw URL string and fails the test if it is invalid.
func MustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", rawURL, err)
	}
	return u
}
