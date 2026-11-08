# grantry

OAuth 2.1 authorization server building blocks for Rust web apps and MCP servers.

grantry holds the protocol rules. Your app keeps storage, users, login, consent screens and audit, and plugs them in through four traits.

What it does:

- the authorization code flow with PKCE (S256 only), resource indicators (RFC 8707) and exact redirect matching, with any port allowed on loopback (RFC 8252 §7.3);
- refresh tokens that rotate, where presenting a rotated one revokes the grant;
- single-use codes, where a second exchange revokes the grant;
- audience-bound JWT access tokens: grantry's claims plus your own, signed with your key;
- client identification by Client ID Metadata Document, with dynamic registration (RFC 7591) as the fallback;
- authorization server metadata (RFC 8414) and protected resource metadata (RFC 9728);
- optional axum routes (`axum` feature).

Not yet: confidential clients.

## Ports

| Trait | You provide | Called |
|---|---|---|
| `OAuthStore` | clients, the document cache, pending authorizations, codes, grants, refresh tokens | every flow; methods marked *atomic* are race guards |
| `Subjects<S>` | the user decision: still there? still allowed? what claims? | every token issue (code exchange and refresh) |
| `Events<S>` | audit and tracing | grant created, grant revoked |
| `MetadataFetcher` | HTTP under your egress policy (no internal addresses, no redirects) | resolving a metadata-document client |

`S` is your subject type: whom a grant is for, such as a user id or a user in a tenant.

`memory::MemoryStore` implements `OAuthStore` in memory for tests. The `client-fetch` feature adds `ReqwestFetcher`, which has no egress policy of its own.

## Example host

```rust
use std::sync::Arc;
use grantry::{Config, ScopeSpec, Server, Signer, Recheck, Subjects, store::{Grant, BackendError, NoEvents}};
use grantry::memory::MemoryStore;

struct Users;

#[async_trait::async_trait]
impl Subjects<String> for Users {
    async fn recheck(&self, grant: &Grant<String>) -> Result<Recheck, BackendError> {
        // Look the user up; Recheck::Revoke("user_removed".into()) ends the grant.
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), grant.subject.clone().into());
        Ok(Recheck::Allow(claims))
    }
}

let server = Server::new(
    Config {
        resource: "https://app.example/mcp".into(),
        token_kind: "mcp".into(),
        scopes: ScopeSpec::new(&["read", "write", "offline_access"], &["read"], "offline_access"),
        signer: Signer::hmac_base64(jsonwebtoken::Algorithm::HS256, SECRET_BASE64)?,
        access_token_secs: 900,
        code_ttl: chrono::Duration::seconds(60),
        pending_ttl: chrono::Duration::minutes(10),
        grant_lifetime: chrono::Duration::days(90),
        documents: Default::default(),
    },
    Arc::new(MemoryStore::default()),
    Arc::new(Users),
    Arc::new(NoEvents),
    Arc::new(grantry::client::ReqwestFetcher::new()?),
);

// GET /authorize: validate and store, then send the browser to your login and consent page.
let pending = server.authorize(raw_query).await?;
// Your consent page, once the user has said yes:
let approved = server.approve(pending.id, &user_id, None).await?;
// redirect the browser to approved.redirect
// POST /token:
let tokens = server.exchange_code(&form, form.get("client_id").map(String::as_str), None).await?;
// Your resource server:
let claims = server.verify(bearer)?;
```

With the `axum` feature, `grantry::routes::router(server, routes)` mounts the metadata, authorize, token and register endpoints. Your consent page still calls `approve` and `deny`. Layer rate limiting on top of the router.

## Provenance

This crate was extracted from the OAuth authorization server for MCP clients in [FlowDrop](https://github.com/factorial-io/flowdrop-rs) (flowdrop-rs `main` at `31e3618f`). Factorial GmbH wrote that code and relicenses it here under MPL-2.0. flowdrop-rs pins its token shape with a golden test, and grantry reproduces it (`token::tests::golden_claims`).

## License

[MPL-2.0](LICENSE).
