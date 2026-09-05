package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mwServer(t *testing.T, s *signer, authorize func(*Identity, *http.Request) error) *httptest.Server {
	t.Helper()
	v := newVerifier(s, t)
	// The client gate belongs to Authorize in these tests, so leave the
	// verifier's own allowlist open: otherwise it refuses first, with a 401,
	// and the middleware's 403 path is never exercised. Both layers are
	// legitimate: a service may use either or both.
	v.ClientIDs = nil
	m := &Middleware{
		Verifier:  v,
		Authorize: authorize,
		Log:       func(string, ...any) {},
	}
	h := m.WrapFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromRequest(r)
		if id == nil {
			t.Error("handler ran without an identity in context")
		}
		_, _ = w.Write([]byte(id.ClientID))
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, token string) *http.Response {
	t.Helper()
	r, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestMiddlewarePassesVerifiedCallers(t *testing.T) {
	s := newSigner(t)
	srv := mwServer(t, s, nil)

	resp := get(t, srv, s.token(t, baseClaims()))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token = %d, want 200", resp.StatusCode)
	}
}

func TestMiddlewareRefusesMissingAndBadTokens(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	other.kid = s.kid
	srv := mwServer(t, s, nil)

	for name, tok := range map[string]string{
		"none":   "",
		"forged": other.token(t, baseClaims()),
	} {
		resp := get(t, srv, tok)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, resp.StatusCode)
		}
	}
}

// The bearer scheme must be advertised, so a client knows how to try again.
func TestMissingTokenAdvertisesBearer(t *testing.T) {
	s := newSigner(t)
	srv := mwServer(t, s, nil)
	resp := get(t, srv, "")
	defer resp.Body.Close()
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("no WWW-Authenticate header on a 401")
	}
}

// Authentication and authorization are different answers: a caller who
// proved who they are but may not proceed gets 403, not 401.
func TestRequireClientSeparates401From403(t *testing.T) {
	s := newSigner(t)
	srv := mwServer(t, s, RequireClient("herald"))

	ok := get(t, srv, s.token(t, baseClaims()))
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Errorf("permitted client = %d, want 200", ok.StatusCode)
	}

	claims := baseClaims()
	claims["client_id"] = "kfin"
	bad := get(t, srv, s.token(t, claims))
	bad.Body.Close()
	if bad.StatusCode != http.StatusForbidden {
		t.Errorf("another service's token = %d, want 403", bad.StatusCode)
	}
}

func TestRequireGroup(t *testing.T) {
	s := newSigner(t)
	srv := mwServer(t, s, RequireGroup("admins"))

	ok := get(t, srv, s.token(t, baseClaims()))
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Errorf("member = %d, want 200", ok.StatusCode)
	}

	claims := baseClaims()
	claims["groups"] = []string{"other"}
	bad := get(t, srv, s.token(t, claims))
	bad.Body.Close()
	if bad.StatusCode != http.StatusForbidden {
		t.Errorf("non-member = %d, want 403", bad.StatusCode)
	}
}
