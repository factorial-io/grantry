// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! axum routes for the protocol endpoints: RFC 8414 metadata, authorize,
//! token and register. Refusals are RFC 6749 §5.2 bodies
//! (`error`, `error_description`).
//!
//! The host keeps the rest: its login and consent pages (which call
//! [`Server::approve`] / [`Server::deny`]), rate limiting and client-address
//! extraction as layers around this router, and any grant grantry does not
//! handle through [`Routes::other_grant`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{MethodRouter, get, post};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::metadata::AuthorizationServerMetadata;
use crate::request::parse_query;
use crate::server::{AuthorizeError, RegisterError, Server, TokenError};

/// A handler for a `grant_type` grantry does not handle: the parsed form and
/// the request headers.
pub type GrantHook = Arc<
    dyn Fn(HashMap<String, String>, HeaderMap) -> Pin<Box<dyn Future<Output = Response> + Send>>
        + Send
        + Sync,
>;

/// What the router needs beyond the [`Server`].
#[derive(Clone)]
pub struct Routes {
    /// Served at `/.well-known/oauth-authorization-server`; its endpoint URLs
    /// should name the paths below.
    pub metadata: AuthorizationServerMetadata,
    pub authorize_path: String,
    pub token_path: String,
    /// `None` turns dynamic registration off.
    pub register_path: Option<String>,
    /// Where the browser goes after a valid authorization request: the
    /// host's login-then-consent page for this pending id.
    pub consent_url: Arc<dyn Fn(Uuid) -> String + Send + Sync>,
    /// Grants other than `authorization_code` and `refresh_token`; without
    /// it they are `unsupported_grant_type`.
    pub other_grant: Option<GrantHook>,
}

struct AppState<S> {
    server: Server<S>,
    routes: Routes,
}

/// The router. Merge or nest it into the host's.
pub fn router<S>(server: Server<S>, routes: Routes) -> Router
where
    S: Clone + PartialEq + Send + Sync + 'static,
{
    endpoints(server, routes).router()
}

/// Each endpoint on its own, for a host that layers one of them (rate
/// limiting `register`, say): change a field, then call
/// [`Endpoints::router`].
///
/// ```ignore
/// let mut endpoints = grantry::routes::endpoints(server, routes);
/// endpoints.register = endpoints.register.map(|(path, r)| (path, r.layer(limiter)));
/// let app = endpoints.router();
/// ```
pub struct Endpoints {
    /// `GET /.well-known/oauth-authorization-server`.
    pub metadata: MethodRouter,
    /// `GET` at [`Routes::authorize_path`].
    pub authorize: (String, MethodRouter),
    /// `POST` at [`Routes::token_path`].
    pub token: (String, MethodRouter),
    /// `POST` at [`Routes::register_path`], if registration is on.
    pub register: Option<(String, MethodRouter)>,
}

impl Endpoints {
    /// The endpoints mounted at their paths.
    pub fn router(self) -> Router {
        let mut router = Router::new()
            .route("/.well-known/oauth-authorization-server", self.metadata)
            .route(&self.authorize.0, self.authorize.1)
            .route(&self.token.0, self.token.1);
        if let Some((path, register)) = self.register {
            router = router.route(&path, register);
        }
        router
    }
}

/// The endpoints [`router`] mounts, not yet mounted.
pub fn endpoints<S>(server: Server<S>, routes: Routes) -> Endpoints
where
    S: Clone + PartialEq + Send + Sync + 'static,
{
    let (authorize_path, token_path, register_path) = (
        routes.authorize_path.clone(),
        routes.token_path.clone(),
        routes.register_path.clone(),
    );
    let state = Arc::new(AppState { server, routes });
    Endpoints {
        metadata: get(metadata::<S>).with_state(state.clone()),
        authorize: (
            authorize_path,
            get(authorize::<S>).with_state(state.clone()),
        ),
        token: (token_path, post(token::<S>).with_state(state.clone())),
        register: register_path.map(|path| (path, post(register::<S>).with_state(state))),
    }
}

/// An RFC 6749 §5.2 refusal.
pub fn refusal(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

fn internal() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn metadata<S>(State(state): State<Arc<AppState<S>>>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        axum::Json(&state.routes.metadata),
    )
        .into_response()
}

async fn authorize<S>(State(state): State<Arc<AppState<S>>>, RawQuery(query): RawQuery) -> Response
where
    S: Clone + PartialEq + Send + Sync + 'static,
{
    match state.server.authorize(&query.unwrap_or_default()).await {
        Ok(pending) => Redirect::to(&(state.routes.consent_url)(pending.id)).into_response(),
        Err(AuthorizeError::Redirect(to)) => Redirect::to(&to).into_response(),
        Err(AuthorizeError::Page(page)) => (
            StatusCode::BAD_REQUEST,
            [(header::CACHE_CONTROL, "no-store")],
            Html(format!(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorization error</title></head>\
                 <body><h1>This connection request cannot be completed</h1><p>{}</p></body></html>",
                page.message()
            )),
        )
            .into_response(),
        Err(AuthorizeError::Backend(_)) => internal(),
    }
}

async fn token<S>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: Clone + PartialEq + Send + Sync + 'static,
{
    let invalid = |d| refusal(StatusCode::BAD_REQUEST, "invalid_request", d);
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return invalid("The request must be application/x-www-form-urlencoded.");
    }
    let Ok(form) = parse_query(&String::from_utf8_lossy(&body)) else {
        return invalid("A parameter was sent more than once.");
    };
    let client_id = form.get("client_id").cloned();
    let result = match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            state
                .server
                .exchange_code(&form, client_id.as_deref(), None)
                .await
        }
        Some("refresh_token") => {
            let (Some(token), Some(client_id)) = (form.get("refresh_token"), client_id) else {
                return invalid("refresh_token and client_id are required.");
            };
            state
                .server
                .refresh(token, &client_id, None)
                .await
                .map(|(_, tokens)| tokens)
        }
        Some(_) => {
            return match &state.routes.other_grant {
                Some(hook) => hook(form, headers).await,
                None => refusal(
                    StatusCode::BAD_REQUEST,
                    "unsupported_grant_type",
                    "Supported grants: authorization_code, refresh_token.",
                ),
            };
        }
        None => return invalid("grant_type is required."),
    };
    match result {
        Ok(tokens) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            axum::Json(tokens),
        )
            .into_response(),
        Err(TokenError::Backend(_)) => internal(),
        Err(e) => refusal(
            StatusCode::BAD_REQUEST,
            e.code().unwrap_or("server_error"),
            e.description(),
        ),
    }
}

async fn register<S>(State(state): State<Arc<AppState<S>>>, body: Bytes) -> Response
where
    S: Clone + PartialEq + Send + Sync + 'static,
{
    let Ok(Value::Object(doc)) = serde_json::from_slice::<Value>(&body) else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "The body must be a JSON object.",
        );
    };
    match state.server.register(&doc).await {
        Ok(registered) => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            axum::Json(registered),
        )
            .into_response(),
        Err(RegisterError::Invalid(e)) => {
            refusal(StatusCode::BAD_REQUEST, e.code(), e.description())
        }
        Err(RegisterError::Backend(_)) => internal(),
    }
}
