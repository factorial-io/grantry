// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The axum routes end to end against the in-memory store: register,
//! authorize, approve (the host's consent step), token and refresh.

#![cfg(feature = "axum")]

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Duration;
use grantry::client::{DocumentPolicy, FetchError, Fetched, MetadataFetcher};
use grantry::memory::MemoryStore;
use grantry::metadata::AuthorizationServerMetadata;
use grantry::routes::{Routes, router};
use grantry::store::{BackendError, Grant, NoEvents};
use grantry::{Config, Recheck, ScopeSpec, Server, Signer, Subjects};
use http_body_util::BodyExt;
use jsonwebtoken::Algorithm;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;

const ISSUER: &str = "https://app.example";
const CALLBACK: &str = "http://127.0.0.1/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-and-some-more";

struct Everyone;

#[async_trait]
impl Subjects<String> for Everyone {
    async fn recheck(&self, grant: &Grant<String>) -> Result<Recheck, BackendError> {
        let mut extra = Map::new();
        extra.insert("sub".into(), json!(grant.subject));
        Ok(Recheck::Allow(extra))
    }
}

struct NoFetch;

#[async_trait]
impl MetadataFetcher for NoFetch {
    async fn fetch(&self, _: &Url, _: usize) -> Result<Fetched, FetchError> {
        Err(FetchError("offline".into()))
    }
}

fn server() -> Server<String> {
    let scopes = ScopeSpec::new(&["read", "offline_access"], &["read"], "offline_access");
    Server::new(
        Config {
            resource: format!("{ISSUER}/mcp"),
            token_kind: "mcp".into(),
            scopes,
            signer: Signer::hmac_base64(Algorithm::HS256, "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0")
                .unwrap(),
            access_token_secs: 300,
            code_ttl: Duration::seconds(60),
            pending_ttl: Duration::seconds(600),
            grant_lifetime: Duration::days(30),
            documents: DocumentPolicy::default(),
        },
        Arc::new(MemoryStore::default()),
        Arc::new(Everyone),
        Arc::new(NoEvents),
        Arc::new(NoFetch),
    )
}

fn app(server: Server<String>) -> Router {
    let scopes = server.config.scopes.known.clone();
    router(
        server,
        Routes {
            metadata: AuthorizationServerMetadata::new(
                ISSUER,
                "/oauth/authorize",
                "/oauth/token",
                Some("/oauth/register"),
                &scopes,
            ),
            authorize_path: "/oauth/authorize".into(),
            token_path: "/oauth/token".into(),
            register_path: Some("/oauth/register".into()),
            consent_url: Arc::new(|id| format!("/consent/{id}")),
            other_grant: None,
        },
    )
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, String, Value) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, location, body)
}

fn form(path: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn param(url: &str, name: &str) -> String {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .unwrap()
        .1
        .into_owned()
}

#[tokio::test]
async fn authorize_approve_token_refresh() {
    let server = server();
    let app = app(server.clone());

    let (status, _, meta) = call(
        &app,
        Request::get("/.well-known/oauth-authorization-server")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(meta["token_endpoint"], "https://app.example/oauth/token");

    let (status, _, registered) = call(
        &app,
        Request::post("/oauth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"client_name": "CLI", "redirect_uris": [CALLBACK]}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = registered["client_id"].as_str().unwrap().to_string();

    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "http://127.0.0.1:4711/callback"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", "https://app.example/mcp"),
            ("scope", "read offline_access"),
        ])
        .finish();
    let (status, location, _) = call(
        &app,
        Request::get(format!("/oauth/authorize?{query}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let pending = location.strip_prefix("/consent/").unwrap().parse().unwrap();

    // The host's consent page approves.
    let approved = server
        .approve(pending, &"alice".to_string(), None)
        .await
        .unwrap();
    let code = param(&approved.redirect, "code");

    let (status, _, tokens) = call(
        &app,
        form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
                ("redirect_uri", "http://127.0.0.1:4711/callback"),
                ("code_verifier", VERIFIER),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let claims = server
        .verify(tokens["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["sub"], "alice");

    let refresh = tokens["refresh_token"].as_str().unwrap();
    let (status, _, refreshed) = call(
        &app,
        form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_ne!(refreshed["refresh_token"], tokens["refresh_token"]);

    // Reuse of the rotated token.
    let (status, _, refused) = call(
        &app,
        form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refused["error"], "invalid_grant");
}

#[tokio::test]
async fn refusals_are_rfc_bodies() {
    let app = app(server());
    let (status, _, body) = call(
        &app,
        form("/oauth/token", &[("grant_type", "client_credentials")]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_grant_type");

    let (_, _, body) = call(
        &app,
        form("/oauth/token", &[("grant_type", "a"), ("grant_type", "b")]),
    )
    .await;
    assert_eq!(body["error"], "invalid_request");

    let (status, _, _) = call(
        &app,
        Request::get("/oauth/authorize?client_id=unknown")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
