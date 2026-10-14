package authz

import (
	"context"
	"testing"
)

// Audience pins a token to one service: the client_id gate alone lets a token
// minted for one service by a shared client open every service that trusts it.
func TestAudienceMustBeExactlyOurs(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)
	v.Audience = "service-a"

	cases := []struct {
		name string
		aud  any
		ok   bool
	}{
		{"exact string", "service-a", true},
		{"exact single-element array", []string{"service-a"}, true},
		{"absent", nil, false},
		{"empty string", "", false},
		{"empty array", []string{}, false},
		{"another service", "https://service-b.example", false},
		{"ours among others", []string{"service-a", "https://service-c.example"}, false},
		{"case variant", "SERVICE-A", false},
	}
	for _, c := range cases {
		claims := baseClaims()
		if c.aud != nil {
			claims["aud"] = c.aud
		}
		_, err := v.Verify(context.Background(), "Bearer "+s.token(t, claims))
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// The audience check does not replace the client_id gate: a token carrying our
// audience but minted for another client is still refused.
func TestAudienceDoesNotReplaceClientID(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)
	v.Audience = "service-a"
	claims := baseClaims()
	claims["aud"] = "service-a"
	claims["client_id"] = "kfin"
	if _, err := v.Verify(context.Background(), "Bearer "+s.token(t, claims)); err == nil {
		t.Fatal("a kfin token carrying aud service-a was accepted")
	}
}

// Unset, the verifier keeps accepting the empty aud every existing caller receives.
func TestAudienceUnsetAcceptsEmptyAud(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)
	if _, err := v.Verify(context.Background(), "Bearer "+s.token(t, baseClaims())); err != nil {
		t.Fatalf("empty aud refused with Audience unset: %v", err)
	}
}
