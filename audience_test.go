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

// A service whose own clients receive an empty aud can still pin the one client it shares
// with another service: only the scoped clients must carry the audience.
func TestAudienceScopedToSharedClients(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)
	v.ClientIDs = []string{"herald", "notifier"}
	v.Audience = "service-a"
	v.AudienceScoped = []string{"notifier"}

	tok := func(client string, aud any) string {
		c := baseClaims()
		c["client_id"] = client
		if aud != nil {
			c["aud"] = aud
		}
		return s.token(t, c)
	}
	cases := []struct {
		name   string
		client string
		aud    any
		ok     bool
	}{
		{"scoped, ours", "notifier", "service-a", true},
		{"scoped, ours as list", "notifier", []string{"service-a"}, true},
		{"scoped, absent", "notifier", nil, false},
		{"scoped, empty", "notifier", []string{}, false},
		{"scoped, another service", "notifier", "service-b", false},
		{"scoped, ours among others", "notifier", []string{"service-a", "service-b"}, false},
		{"scoped, trailing slash", "notifier", "service-a/", false},
		{"unscoped, empty aud", "herald", nil, true},
		{"unscoped, another service", "herald", "service-b", true},
	}
	for _, c := range cases {
		_, err := v.Verify(context.Background(), "Bearer "+tok(c.client, c.aud))
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// Naming a client to scope without saying which audience it must carry fails closed.
func TestScopedClientWithoutAudienceIsRefused(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(s, t)
	v.ClientIDs = []string{"herald", "notifier"}
	v.AudienceScoped = []string{"notifier"}
	for _, aud := range []any{"service-a", "", []string{""}} {
		c := baseClaims()
		c["client_id"] = "notifier"
		c["aud"] = aud
		if _, err := v.Verify(context.Background(), "Bearer "+s.token(t, c)); err == nil {
			t.Errorf("a scoped client carrying aud %q was accepted with no Audience configured", aud)
		}
	}
}
