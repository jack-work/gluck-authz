# gluck-authz

Verify Authelia-issued JWTs. One implementation, for every Go service on the
estate.

## Why every service must do this itself

Backends bind loopback, so Caddy is the only route to them. Caddy strips
client `Remote-*` headers, then either forward-auths a browser session to
Authelia, or — when the request carries `Authorization: Bearer` — **passes it
straight through, unexamined**.

So on the bearer path nothing upstream has validated anything. A service that
doesn't verify is unauthenticated to any caller who sends a bearer header.

## Use

```go
mw := &authz.Middleware{
    Verifier:  &authz.Verifier{
        JWKSURL: "http://127.0.0.1:9091/jwks.json",
        Issuer:  "https://auth.kelliher.info",
    },
    Authorize: authz.RequireClient("kcal-notify", "herald"),
}
http.Handle("/v1/", mw.Wrap(api))
```

Inside a handler: `authz.FromRequest(r)` → `*Identity` with `Subject`,
`ClientID`, `Username`, `Groups`, `Scopes`.

## What it checks

- **Signature** against JWKS, **RS256/RS512 only**. Refusing to switch on the
  token's own `alg` is what closes the `alg: none` and HMAC-confusion
  families: the token must not choose how it is checked.
- **Issuer**, **exp/nbf** with 60s skew.
- **`client_id`**, optionally — *not* audience. Authelia issues access tokens
  with an empty `aud` (verified against a live token, not assumed), so an
  `aud` check would either reject everything or, written permissively, pass
  everything: a control that looks real and does nothing.
- An unknown `kid` refetches JWKS at most once a minute, so a bogus token
  cannot be turned into a request amplifier against Authelia.

## Machines vs people

`RequireGroup` works for humans. It **cannot** work for a service: a
`client_credentials` token has no `preferred_username` and no groups. Use
`RequireClient` for machine callers — `client_id` is the only thing that
distinguishes one service's token from another's.
