package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ecSigner mints ES256 tokens shaped like Kanidm's at+jwt.
type ecSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newECSigner(t *testing.T, kid string) *ecSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &ecSigner{key: k, kid: kid}
}

func (s *ecSigner) jwk() map[string]any {
	pad := func(b []byte) string {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	return map[string]any{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.kid,
		"x": pad(s.key.X.Bytes()), "y": pad(s.key.Y.Bytes())}
}

func (s *ecSigner) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(header) + "." + enc(claims)
	h := sha256.Sum256([]byte(signing))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *ecSigner) token(t *testing.T, claims map[string]any) string {
	return s.sign(t, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": s.kid}, claims)
}

func kanidmClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": "https://idm.band.internal:8445/oauth2/openid/rou2", "sub": "5b0c-uuid",
		"aud": "rou2", "client_id": "rou2", "scope": "openid groups",
		"iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
	}
}

// jwksOf serves a mixed set: Authelia-style RSA beside Kanidm-style EC.
func jwksOf(t *testing.T, keys ...map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func rsaJWK(s *signer) map[string]any {
	return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid,
		"n": base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})}
}

func kanidmVerifier(url string) *Verifier {
	return &Verifier{JWKSURL: url, Issuer: "https://idm.band.internal:8445/oauth2/openid/rou2",
		ClientIDs: []string{"rou2"}, Audience: "rou2"}
}

func TestES256VerifiesBesideRS256(t *testing.T) {
	ec := newECSigner(t, "ee9fd1d7d2fe")
	rs := newSigner(t)
	srv := jwksOf(t, rsaJWK(rs), ec.jwk())

	id, err := kanidmVerifier(srv.URL).VerifyToken(context.Background(), ec.token(t, kanidmClaims()))
	if err != nil {
		t.Fatalf("ES256 at+jwt: %v", err)
	}
	if id.Subject != "5b0c-uuid" || id.ClientID != "rou2" {
		t.Fatalf("identity: %+v", id)
	}

	// The RS256 path is unchanged, from the same mixed JWKS.
	v := &Verifier{JWKSURL: srv.URL, Issuer: "https://auth.kelliher.info", ClientIDs: []string{"herald"}}
	if _, err := v.VerifyToken(context.Background(), rs.token(t, baseClaims())); err != nil {
		t.Fatalf("RS256 beside EC: %v", err)
	}
}

func TestES256Refusals(t *testing.T) {
	ec := newECSigner(t, "ec-1")
	rs := newSigner(t)
	srv := jwksOf(t, rsaJWK(rs), ec.jwk())
	v := kanidmVerifier(srv.URL)
	ctx := context.Background()

	// Positive control on this exact verifier and JWKS.
	if _, err := v.VerifyToken(ctx, ec.token(t, kanidmClaims())); err != nil {
		t.Fatalf("control: %v", err)
	}

	cases := map[string]struct {
		token string
		want  string
	}{
		// Another P-256 key claiming the published kid.
		"foreign key": {func() string {
			other := newECSigner(t, "ec-1")
			return other.token(t, kanidmClaims())
		}(), "signature"},
		// Key-type confusion, both directions.
		"ES256 on an RSA kid": {ec.sign(t, map[string]any{"alg": "ES256", "kid": rs.kid}, kanidmClaims()), "does not match an RSA key"},
		"RS256 on an EC kid":  {rs.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": ec.kid}, kanidmClaims()), "does not match an EC key"},
		"ES384":               {ec.sign(t, map[string]any{"alg": "ES384", "kid": ec.kid}, kanidmClaims()), "unsupported signing algorithm"},
		"none":                {ec.sign(t, map[string]any{"alg": "none", "kid": ec.kid}, kanidmClaims()), "unsupported signing algorithm"},
	}
	for name, c := range cases {
		_, err := v.VerifyToken(ctx, c.token)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}

	// A DER-encoded signature (crypto/ecdsa's default form) is not JWS.
	parts := strings.Split(ec.token(t, kanidmClaims()), ".")
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	der, _ := ecdsa.SignASN1(rand.Reader, ec.key, h[:])
	if _, err := v.VerifyToken(ctx, parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(der)); err == nil || !strings.Contains(err.Error(), "want 64") {
		t.Errorf("DER signature: %v", err)
	}

	// Tampered claims under a valid header and signature.
	claims := kanidmClaims()
	claims["sub"] = "someone-else"
	b, _ := json.Marshal(claims)
	if _, err := v.VerifyToken(ctx, parts[0]+"."+base64.RawURLEncoding.EncodeToString(b)+"."+parts[2]); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("tampered claims: %v", err)
	}
}

func TestJWKSDropsBadECKeys(t *testing.T) {
	good := newECSigner(t, "good")
	offCurve := good.jwk()
	offCurve["kid"] = "off"
	offCurve["y"] = offCurve["x"] // (x, x) is not on P-256
	p384 := newECSigner(t, "p384").jwk()
	p384["crv"] = "P-384"
	enc := newECSigner(t, "enc").jwk()
	enc["use"] = "enc"

	v := &Verifier{JWKSURL: jwksOf(t, good.jwk(), offCurve, p384, enc).URL}
	if err := v.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.keys["good"]; !ok {
		t.Fatal("control: the valid P-256 key must load")
	}
	for _, kid := range []string{"off", "p384", "enc"} {
		if _, ok := v.keys[kid]; ok {
			t.Errorf("%s: loaded", kid)
		}
	}
}
