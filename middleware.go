package authz

import (
	"context"
	"errors"
	"log"
	"net/http"
)

// HTTP middleware over Verifier, so a service wires authentication in one
// line rather than reimplementing the same twenty.

type ctxKey int

const identityKey ctxKey = 0

// Middleware verifies the bearer token on every request it wraps and places
// the caller's Identity in the request context.
//
// Deny is the default at every level: no token, an unverifiable token, or a
// caller the Authorize function refuses all end the request here.
type Middleware struct {
	Verifier *Verifier

	// Authorize decides whether a verified caller may proceed. Nil means
	// authentication only: any valid token passes, which is rarely what you
	// want beyond a read-only endpoint.
	Authorize func(*Identity, *http.Request) error

	// Log receives one line per refusal. Nil uses the standard logger.
	// Refusals are worth logging: with agents you cannot prevent misuse,
	// only notice it quickly.
	Log func(format string, args ...any)
}

// ErrForbidden marks an Authorize failure as a 403 rather than a 401. The
// distinction matters to the caller: 401 means "authenticate differently",
// 403 means "you are known and this is not yours".
var ErrForbidden = errors.New("forbidden")

func (m *Middleware) logf(format string, args ...any) {
	if m.Log != nil {
		m.Log(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Wrap returns a handler that authenticates, authorizes, then delegates.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := m.Verifier.Verify(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			if errors.Is(err, ErrNoToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
			}
			m.logf("authn refused from %s: %v", r.RemoteAddr, err)
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if m.Authorize != nil {
			if err := m.Authorize(id, r); err != nil {
				code := http.StatusForbidden
				if !errors.Is(err, ErrForbidden) {
					code = http.StatusUnauthorized
				}
				m.logf("authz refused %s (client %s): %v", id.Subject, id.ClientID, err)
				writeErr(w, code, err.Error())
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// WrapFunc is Wrap for a HandlerFunc.
func (m *Middleware) WrapFunc(next http.HandlerFunc) http.HandlerFunc {
	h := m.Wrap(next)
	return h.ServeHTTP
}

// WithIdentity stores an identity in a context.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// FromContext retrieves the verified identity, or nil.
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

// FromRequest retrieves the verified identity from a request, or nil.
func FromRequest(r *http.Request) *Identity { return FromContext(r.Context()) }

// RequireClient builds an Authorize function permitting only the named OIDC
// clients. This is the machine-identity gate: a client_credentials token has
// no user, so client_id is the only thing that distinguishes one service's
// token from another's.
func RequireClient(clients ...string) func(*Identity, *http.Request) error {
	allowed := map[string]bool{}
	for _, c := range clients {
		allowed[c] = true
	}
	return func(id *Identity, _ *http.Request) error {
		if id.ClientID == "" {
			return errors.New("token carries no client_id")
		}
		if !allowed[id.ClientID] {
			return ErrForbidden
		}
		return nil
	}
}

// RequireGroup builds an Authorize function requiring an lldap group. This is
// the human gate: it cannot work for a machine caller, whose token carries
// no groups at all.
func RequireGroup(group string) func(*Identity, *http.Request) error {
	return func(id *Identity, _ *http.Request) error {
		if !id.HasGroup(group) {
			return ErrForbidden
		}
		return nil
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":` + quote(msg) + "}\n"))
}

// quote is a minimal JSON string escaper: enough for error text, without
// pulling encoding/json into the hot path of a refusal.
func quote(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if r < 0x20 {
				continue
			}
			out = append(out, string(r)...)
		}
	}
	return string(append(out, '"'))
}
