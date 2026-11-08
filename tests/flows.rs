// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The flows against the in-memory store: every refusal of the code and
//! refresh state machines, consent binding, client identification.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Duration;
use grantry::client::{DocumentPolicy, FetchError, Fetched, MetadataFetcher};
use grantry::memory::MemoryStore;
use grantry::server::{ApproveError, AuthorizeError, PageError, TokenError, TokenResponse};
use grantry::store::{BackendError, Events, Grant, OAuthStore};
use grantry::{Config, Recheck, ScopeSpec, Server, Signer, Subjects};
use jsonwebtoken::Algorithm;
use serde_json::{Map, json};
use sha2::{Digest, Sha256};
use url::Url;

const RESOURCE: &str = "https://app.example/mcp";
const CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-and-some-more";
const DOC_URL: &str = "https://claude.ai/oauth/claude-code-client-metadata";

type User = &'static str;

/// Allows everyone but `revoked` users, adding `pid`.
#[derive(Default)]
struct Users {
    revoked: Mutex<Vec<User>>,
}

#[async_trait]
impl Subjects<User> for Users {
    async fn recheck(&self, grant: &Grant<User>) -> Result<Recheck, BackendError> {
        if self.revoked.lock().unwrap().contains(&grant.subject) {
            return Ok(Recheck::Revoke("user_removed".into()));
        }
        let mut extra = Map::new();
        extra.insert("pid".into(), json!(grant.subject));
        Ok(Recheck::Allow(extra))
    }
}

/// Records revocations.
#[derive(Default)]
struct Log(Mutex<Vec<String>>);

#[async_trait]
impl Events<User> for Log {
    async fn grant_revoked(&self, _grant: &Grant<User>, reason: &str, client_ip: Option<&str>) {
        self.0
            .lock()
            .unwrap()
            .push(format!("{reason}@{}", client_ip.unwrap_or("-")));
    }
}

/// Serves Claude Code's metadata document; counts fetches.
#[derive(Default)]
struct Documents(Mutex<u32>);

#[async_trait]
impl MetadataFetcher for Documents {
    async fn fetch(&self, url: &Url, _limit: usize) -> Result<Fetched, FetchError> {
        *self.0.lock().unwrap() += 1;
        let doc = json!({
            "client_id": url.as_str(),
            "client_name": "Claude Code",
            "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none",
        });
        Ok(Fetched {
            body: serde_json::to_vec(&doc).unwrap().into(),
            cache_control: Some("max-age=3600".into()),
        })
    }
}

struct Fixture {
    server: Server<User>,
    store: Arc<MemoryStore<User>>,
    users: Arc<Users>,
    log: Arc<Log>,
    documents: Arc<Documents>,
}

fn fixture() -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let users = Arc::new(Users::default());
    let log = Arc::new(Log::default());
    let documents = Arc::new(Documents::default());
    let config = Config {
        resource: RESOURCE.into(),
        token_kind: "mcp".into(),
        scopes: ScopeSpec::new(
            &["read", "write", "offline_access"],
            &["read", "write"],
            "offline_access",
        ),
        signer: Signer::hmac_base64(Algorithm::HS512, "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0")
            .unwrap(),
        access_token_secs: 900,
        code_ttl: Duration::seconds(60),
        pending_ttl: Duration::seconds(600),
        grant_lifetime: Duration::days(90),
        documents: DocumentPolicy {
            timeout: StdDuration::from_secs(1),
            ..DocumentPolicy::default()
        },
    };
    let server = Server::new(
        config,
        store.clone(),
        users.clone(),
        log.clone(),
        documents.clone(),
    );
    Fixture {
        server,
        store,
        users,
        log,
        documents,
    }
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

fn query(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn authorize_query(client_id: &str, redirect: &str, scope: &str) -> String {
    query(&[
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("code_challenge", &challenge()),
        ("code_challenge_method", "S256"),
        ("resource", RESOURCE),
        ("scope", scope),
        ("state", "xyz"),
    ])
}

fn param(url: &str, name: &str) -> Option<String> {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn form(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn exchange_form(code: &str) -> HashMap<String, String> {
    form(&[
        ("code", code),
        ("redirect_uri", CALLBACK),
        ("code_verifier", VERIFIER),
    ])
}

async fn register(f: &Fixture) -> String {
    let doc = json!({"client_name": "Claude", "redirect_uris": [CALLBACK]});
    f.server
        .register(doc.as_object().unwrap())
        .await
        .unwrap()
        .client_id
}

/// Register, authorize, approve as `user`; `(client_id, code)`.
async fn code_for(f: &Fixture, user: User, scope: &str) -> (String, String) {
    let client_id = register(f).await;
    let pending = f
        .server
        .authorize(&authorize_query(&client_id, CALLBACK, scope))
        .await
        .unwrap();
    let approved = f.server.approve(pending.id, &user, None).await.unwrap();
    assert_eq!(param(&approved.redirect, "state").as_deref(), Some("xyz"));
    (client_id, param(&approved.redirect, "code").unwrap())
}

/// A full connection with `offline_access`.
async fn connect(f: &Fixture, user: User) -> (String, TokenResponse) {
    let (client_id, code) = code_for(f, user, "read offline_access").await;
    let tokens = f
        .server
        .exchange_code(&exchange_form(&code), Some(&client_id), None)
        .await
        .unwrap();
    (client_id, tokens)
}

fn invalid_grant(r: Result<TokenResponse, TokenError>) -> bool {
    matches!(r, Err(TokenError::InvalidGrant))
}

async fn grant_of(f: &Fixture, tokens: &TokenResponse) -> Grant<User> {
    let claims = f.server.verify(&tokens.access_token).unwrap();
    let id = claims["grant_id"].as_str().unwrap().parse().unwrap();
    f.store.find_grant(id).await.unwrap().unwrap()
}

// --- Authorization request ------------------------------------------------------

#[tokio::test]
async fn unknown_client_or_unregistered_redirect_is_a_page() {
    let f = fixture();
    let page = |r: Result<_, AuthorizeError>| match r {
        Err(AuthorizeError::Page(p)) => p,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        page(f.server.authorize("client_id=a&client_id=b").await),
        PageError::DuplicateParameter
    ));
    assert!(matches!(
        page(f.server.authorize("response_type=code").await),
        PageError::NoClient
    ));
    assert!(matches!(
        page(
            f.server
                .authorize(&authorize_query("nope", CALLBACK, "read"))
                .await
        ),
        PageError::UnknownClient(_)
    ));
    let client_id = register(&f).await;
    assert!(matches!(
        page(
            f.server
                .authorize(&authorize_query(
                    &client_id,
                    "https://claude.ai/other",
                    "read"
                ))
                .await
        ),
        PageError::UnregisteredRedirect
    ));
}

#[tokio::test]
async fn invalid_requests_redirect_with_the_error() {
    let f = fixture();
    let client_id = register(&f).await;
    let redirected = |r: Result<_, AuthorizeError>| match r {
        Err(AuthorizeError::Redirect(to)) => (param(&to, "error").unwrap(), param(&to, "state")),
        other => panic!("{other:?}"),
    };
    let base = authorize_query(&client_id, CALLBACK, "read");
    let cases = [
        (base.replace("S256", "plain"), "invalid_request"),
        (
            base.replace("app.example", "other.example"),
            "invalid_target",
        ),
        (base.replace("scope=read", "scope=admin"), "invalid_scope"),
        (
            base.replace("response_type=code", "response_type=token"),
            "unsupported_response_type",
        ),
    ];
    for (query, error) in cases {
        let (got, state) = redirected(f.server.authorize(&query).await);
        assert_eq!(got, error, "{query}");
        assert_eq!(state.as_deref(), Some("xyz"));
    }
}

#[tokio::test]
async fn metadata_document_identifies_and_is_cached() {
    let f = fixture();
    let pending = f
        .server
        .authorize(&authorize_query(
            DOC_URL,
            "http://localhost:33418/callback",
            "read",
        ))
        .await
        .unwrap();
    assert_eq!(pending.client_name, "Claude Code");
    assert!(pending.loopback_only);
    // Another loopback port matches; a different path does not.
    f.server
        .authorize(&authorize_query(
            DOC_URL,
            "http://localhost:9/callback",
            "read",
        ))
        .await
        .unwrap();
    assert!(matches!(
        f.server
            .authorize(&authorize_query(
                DOC_URL,
                "http://localhost:9/other",
                "read"
            ))
            .await,
        Err(AuthorizeError::Page(PageError::UnregisteredRedirect))
    ));
    assert_eq!(
        *f.documents.0.lock().unwrap(),
        1,
        "cached after the first fetch"
    );
}

// --- Consent ------------------------------------------------------------------------

#[tokio::test]
async fn pending_binds_to_the_first_subject() {
    let f = fixture();
    let client_id = register(&f).await;
    let pending = f
        .server
        .authorize(&authorize_query(&client_id, CALLBACK, "read write"))
        .await
        .unwrap();
    assert!(
        f.server
            .pending(pending.id, &"alice")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        f.server
            .pending(pending.id, &"bob")
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        f.server.approve(pending.id, &"bob", None).await,
        Err(ApproveError::NotFound)
    ));
    assert!(f.server.deny(pending.id, &"bob").await.unwrap().is_none());

    // A refused narrowing leaves it pending; a subset is approved.
    assert!(matches!(
        f.server
            .approve(pending.id, &"alice", Some(&["offline_access".into()]))
            .await,
        Err(ApproveError::InvalidScope)
    ));
    let approved = f
        .server
        .approve(pending.id, &"alice", Some(&["read".into()]))
        .await
        .unwrap();
    assert_eq!(approved.grant.scope, "read");
    assert!(matches!(
        f.server.approve(pending.id, &"alice", None).await,
        Err(ApproveError::NotFound)
    ));
}

#[tokio::test]
async fn deny_and_expiry() {
    let f = fixture();
    let client_id = register(&f).await;
    let q = authorize_query(&client_id, CALLBACK, "read");
    let pending = f.server.authorize(&q).await.unwrap();
    let denied = f.server.deny(pending.id, &"alice").await.unwrap().unwrap();
    assert_eq!(
        param(&denied.redirect, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(param(&denied.redirect, "state").as_deref(), Some("xyz"));
    assert!(f.server.deny(pending.id, &"alice").await.unwrap().is_none());

    let pending = f.server.authorize(&q).await.unwrap();
    f.store.age(Duration::seconds(601));
    assert!(
        f.server
            .pending(pending.id, &"alice")
            .await
            .unwrap()
            .is_none()
    );
}

// --- Code exchange ------------------------------------------------------------------

#[tokio::test]
async fn exchange_issues_audience_bound_tokens() {
    let f = fixture();
    let (client_id, tokens) = connect(&f, "alice").await;
    assert_eq!(tokens.expires_in, 900);
    assert_eq!(tokens.scope, "read offline_access");
    assert!(tokens.refresh_token.is_some());
    let claims = f.server.verify(&tokens.access_token).unwrap();
    assert_eq!(claims["aud"], RESOURCE);
    assert_eq!(claims["kind"], "mcp");
    assert_eq!(claims["pid"], "alice");
    assert_eq!(claims["client_id"], client_id.as_str());

    let (client_id, code) = code_for(&f, "alice", "read").await;
    let tokens = f
        .server
        .exchange_code(&exchange_form(&code), Some(&client_id), None)
        .await
        .unwrap();
    assert!(
        tokens.refresh_token.is_none(),
        "no offline_access, no refresh token"
    );
}

#[tokio::test]
async fn code_refusals() {
    let f = fixture();
    let (client_id, code) = code_for(&f, "alice", "read").await;
    let exchange = |form: HashMap<String, String>, client: &str| {
        let (server, client) = (f.server.clone(), client.to_string());
        async move { server.exchange_code(&form, Some(&client), None).await }
    };

    let mut missing = exchange_form(&code);
    missing.remove("code_verifier");
    assert!(matches!(
        exchange(missing, &client_id).await,
        Err(TokenError::InvalidRequest(_))
    ));
    assert!(invalid_grant(
        exchange(exchange_form("bogus"), &client_id).await
    ));
    assert!(invalid_grant(
        exchange(exchange_form(&code), "other-client").await
    ));
    let mut other_redirect = exchange_form(&code);
    other_redirect.insert("redirect_uri".into(), "https://claude.ai/other".into());
    assert!(invalid_grant(exchange(other_redirect, &client_id).await));
    let mut wrong_verifier = exchange_form(&code);
    wrong_verifier.insert("code_verifier".into(), VERIFIER.replace('d', "e"));
    assert!(invalid_grant(exchange(wrong_verifier, &client_id).await));
    let mut wrong_resource = exchange_form(&code);
    wrong_resource.insert("resource".into(), "https://other.example/mcp".into());
    assert!(invalid_grant(exchange(wrong_resource, &client_id).await));

    // None of the refusals used the code up.
    assert!(exchange(exchange_form(&code), &client_id).await.is_ok());
}

#[tokio::test]
async fn code_reuse_revokes_the_grant() {
    let f = fixture();
    let (client_id, code) = code_for(&f, "alice", "read offline_access").await;
    let first = f
        .server
        .exchange_code(&exchange_form(&code), Some(&client_id), None)
        .await
        .unwrap();
    assert!(invalid_grant(
        f.server
            .exchange_code(&exchange_form(&code), Some(&client_id), Some("10.0.0.1"))
            .await
    ));
    let grant = grant_of(&f, &first).await;
    assert_eq!(grant.revoke_reason.as_deref(), Some("code_reuse"));
    assert_eq!(*f.log.0.lock().unwrap(), ["code_reuse@10.0.0.1"]);
    // The first exchange's refresh token dies with the grant.
    let refresh = form(&[("refresh_token", first.refresh_token.as_deref().unwrap())]);
    assert!(invalid_grant(
        f.server.refresh(&refresh, Some(&client_id), None).await
    ));
}

#[tokio::test]
async fn expired_code_is_refused() {
    let f = fixture();
    let (client_id, code) = code_for(&f, "alice", "read").await;
    f.store.age(Duration::seconds(61));
    assert!(invalid_grant(
        f.server
            .exchange_code(&exchange_form(&code), Some(&client_id), None)
            .await
    ));
}

// --- Refresh --------------------------------------------------------------------------

#[tokio::test]
async fn refresh_rotates_and_reuse_revokes() {
    let f = fixture();
    let (client_id, tokens) = connect(&f, "alice").await;
    let first = tokens.refresh_token.unwrap();
    let refresh = |token: &str, client: &str| {
        let (server, form, client) = (
            f.server.clone(),
            form(&[("refresh_token", token)]),
            client.to_string(),
        );
        async move { server.refresh(&form, Some(&client), None).await }
    };

    assert!(matches!(
        f.server.refresh(&form(&[]), Some(&client_id), None).await,
        Err(TokenError::InvalidRequest(_))
    ));
    assert!(invalid_grant(refresh(&first, "other-client").await));
    let second = refresh(&first, &client_id).await.unwrap();
    let next = second.refresh_token.clone().unwrap();
    assert_ne!(next, first);
    assert_eq!(second.scope, "read offline_access");
    assert!(grant_of(&f, &second).await.last_refreshed_at.is_some());

    // The rotated token again: the grant is revoked, the new one dies too.
    assert!(invalid_grant(refresh(&first, &client_id).await));
    assert_eq!(
        grant_of(&f, &second).await.revoke_reason.as_deref(),
        Some("refresh_reuse")
    );
    assert!(invalid_grant(refresh(&next, &client_id).await));
}

/// A host format: refresh tokens carry the host's prefix, codes stay
/// grantry's, and the flows look them up by hash as before.
struct Prefixed;

impl grantry::token::TokenFormat for Prefixed {
    fn mint(&self, kind: grantry::token::Opaque) -> String {
        match kind {
            grantry::token::Opaque::RefreshToken => {
                format!("host_rt_{}", grantry::token::random_token())
            }
            _ => grantry::token::random_token(),
        }
    }
}

#[tokio::test]
async fn a_host_token_format_shapes_refresh_tokens() {
    let mut f = fixture();
    f.server = f.server.with_token_format(Arc::new(Prefixed));
    let (client_id, tokens) = connect(&f, "alice").await;
    let first = tokens.refresh_token.unwrap();
    assert!(first.starts_with("host_rt_"), "{first}");

    let second = f
        .server
        .refresh(&form(&[("refresh_token", &first)]), Some(&client_id), None)
        .await
        .unwrap();
    assert!(second.refresh_token.unwrap().starts_with("host_rt_"));
    assert!(invalid_grant(
        f.server
            .refresh(&form(&[("refresh_token", &first)]), Some(&client_id), None)
            .await
    ));
}

#[tokio::test]
async fn an_idle_refresh_token_expires_without_revoking_the_grant() {
    let mut f = fixture();
    f.server = f.server.with_refresh_idle(Duration::hours(1));
    let (client_id, tokens) = connect(&f, "alice").await;
    let fresh = tokens.refresh_token.clone().unwrap();
    let refreshed = f
        .server
        .refresh(&form(&[("refresh_token", &fresh)]), Some(&client_id), None)
        .await
        .unwrap();

    // The same grant, with an idle lifetime its newest token has outlived.
    let idle = f.server.clone().with_refresh_idle(Duration::zero());
    let next = refreshed.refresh_token.clone().unwrap();
    assert!(invalid_grant(
        idle.refresh(&form(&[("refresh_token", &next)]), Some(&client_id), None)
            .await
    ));
    // Expiry is not theft: the grant lives, and the token still refreshes
    // where the idle lifetime has not run out.
    assert!(grant_of(&f, &refreshed).await.revoked_at.is_none());
    assert!(
        f.server
            .refresh(&form(&[("refresh_token", &next)]), Some(&client_id), None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn refresh_rechecks_the_subject() {
    let f = fixture();
    let (client_id, tokens) = connect(&f, "alice").await;
    f.users.revoked.lock().unwrap().push("alice");
    let refresh = form(&[("refresh_token", tokens.refresh_token.as_deref().unwrap())]);
    assert!(invalid_grant(
        f.server.refresh(&refresh, Some(&client_id), None).await
    ));
    assert_eq!(
        grant_of(&f, &tokens).await.revoke_reason.as_deref(),
        Some("user_removed")
    );
    // A refused refresh rotated nothing.
    f.users.revoked.lock().unwrap().clear();
    assert!(invalid_grant(
        f.server.refresh(&refresh, Some(&client_id), None).await
    ));
}

#[tokio::test]
async fn grant_lifetime_is_absolute() {
    let f = fixture();
    let (client_id, tokens) = connect(&f, "alice").await;
    f.store.age(Duration::days(91));
    let refresh = form(&[("refresh_token", tokens.refresh_token.as_deref().unwrap())]);
    assert!(invalid_grant(
        f.server.refresh(&refresh, Some(&client_id), None).await
    ));
}

#[tokio::test]
async fn revoke_is_recorded_once() {
    let f = fixture();
    let (_, tokens) = connect(&f, "alice").await;
    let grant = grant_of(&f, &tokens).await;
    assert!(f.server.revoke(&grant, "user", None).await.unwrap());
    assert!(!f.server.revoke(&grant, "user", None).await.unwrap());
    assert_eq!(f.log.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn registration_and_sweep() {
    let f = fixture();
    let refused = f
        .server
        .register(
            json!({"redirect_uris": ["http://example.com/cb"]})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("invalid_redirect_uri"),
        "{refused}"
    );

    let registered = f
        .server
        .register(json!({"redirect_uris": [CALLBACK]}).as_object().unwrap())
        .await
        .unwrap();
    let body = serde_json::to_value(&registered).unwrap();
    assert_eq!(body["client_name"], "claude.ai");
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(body["response_types"], json!(["code"]));

    // A client that never got a grant is swept after a week.
    let (_, _) = connect(&f, "alice").await;
    f.store.age(Duration::days(8));
    f.store.sweep().await.unwrap();
    assert!(
        f.store
            .use_client(&registered.client_id)
            .await
            .unwrap()
            .is_none()
    );
}
