// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The flows of the authorization server over the host's ports.
//!
//! Consent and login stay in the host: [`Server::authorize`] validates and
//! stores the request; the host sends the browser to its login and consent
//! pages and finishes with [`Server::approve`] or [`Server::deny`].

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Duration, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;
use uuid::Uuid;

use crate::client::{
    self, Client, ClientError, DocumentPolicy, MetadataFetcher, client_from_document, document_url,
};
use crate::device::{self, DEVICE_TTL_SECS, Device, POLL_INTERVAL, Poll, USER_CODE_ATTEMPTS};
use crate::redirect::with_params;
use crate::request::{self, Registration, RegistrationError};
use crate::scope::ScopeSpec;
use crate::store::{
    BackendError, Events, Grant, NewDevice, NewGrant, NewPending, OAuthStore, Pending, Recheck,
    RegisteredClient, Subjects, reason,
};
use crate::token::{
    self, AccessClaims, Base64Url, Opaque, Signer, TokenFormat, VerifyError, hash_token,
};

/// What the flows need to know.
#[derive(Debug, Clone)]
pub struct Config {
    /// The protected resource (RFC 8707): what an authorization request must
    /// name and every access token's `aud`.
    pub resource: String,
    /// The `kind` claim of an access token.
    pub token_kind: String,
    pub scopes: ScopeSpec,
    pub signer: Signer,
    /// Access token lifetime, in seconds.
    pub access_token_secs: u64,
    /// How long an authorization code may be exchanged.
    pub code_ttl: Duration,
    /// How long a pending authorization waits for consent.
    pub pending_ttl: Duration,
    /// A grant's absolute lifetime; no refresh extends it.
    pub grant_lifetime: Duration,
    pub documents: DocumentPolicy,
}

/// The authorization server: the flows over a store, the subject check, the
/// event hook and the metadata fetcher. Cheap to clone.
pub struct Server<S> {
    pub config: Config,
    store: Arc<dyn OAuthStore<Subject = S>>,
    subjects: Arc<dyn Subjects<S>>,
    events: Arc<dyn Events<S>>,
    fetcher: Arc<dyn MetadataFetcher>,
    tokens: Arc<dyn TokenFormat>,
    refresh_idle: Option<Duration>,
}

impl<S> Clone for Server<S> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            store: Arc::clone(&self.store),
            subjects: Arc::clone(&self.subjects),
            events: Arc::clone(&self.events),
            fetcher: Arc::clone(&self.fetcher),
            tokens: Arc::clone(&self.tokens),
            refresh_idle: self.refresh_idle,
        }
    }
}

/// The config and settings; the ports are left out.
impl<S> std::fmt::Debug for Server<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("refresh_idle", &self.refresh_idle)
            .finish_non_exhaustive()
    }
}

/// An error page: shown when the redirect URI is not (yet) trusted, so the
/// error must not go back to the client.
#[derive(Debug, thiserror::Error)]
pub enum PageError {
    #[error("duplicate parameter")]
    DuplicateParameter,
    #[error("no client_id")]
    NoClient,
    #[error("unresolvable client: {0}")]
    UnknownClient(ClientError),
    #[error("redirect URI not registered for the client")]
    UnregisteredRedirect,
}

impl PageError {
    /// A message for the page. Constant: nothing from the request is echoed.
    pub fn message(&self) -> &'static str {
        match self {
            Self::DuplicateParameter => "A request parameter was sent more than once.",
            Self::NoClient => "The request names no client.",
            Self::UnknownClient(_) => "The application could not be identified.",
            Self::UnregisteredRedirect => {
                "The application's redirect address is not registered for it."
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    /// Show an error page (400).
    #[error(transparent)]
    Page(PageError),
    /// Redirect to this URL: the client's redirect URI carrying `error` and
    /// `state` (RFC 6749 §4.1.2.1).
    #[error("redirect with error to {0}")]
    Redirect(String),
    #[error(transparent)]
    Backend(BackendError),
}

#[derive(Debug, thiserror::Error)]
pub enum ApproveError {
    /// Unknown, expired, already taken, or bound to another subject.
    #[error("no such pending authorization")]
    NotFound,
    /// The kept scopes are empty or not a subset of the requested ones. The
    /// request stays pending.
    #[error("invalid scope")]
    InvalidScope,
    #[error(transparent)]
    Backend(BackendError),
}

/// An approved authorization.
#[derive(Debug, Clone)]
pub struct Approved<S> {
    pub grant: Grant<S>,
    /// The client's redirect URI carrying `code` and `state`.
    pub redirect: String,
}

/// A denied authorization.
#[derive(Debug, Clone)]
pub struct Denied<S> {
    pub pending: Pending<S>,
    /// The client's redirect URI carrying `error=access_denied` and `state`.
    pub redirect: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error(transparent)]
    Invalid(RegistrationError),
    #[error(transparent)]
    Backend(BackendError),
}

/// The RFC 7591 §3.2.1 registration response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    pub client_id_issued_at: i64,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: [&'static str; 1],
    pub token_endpoint_auth_method: &'static str,
}

impl RegistrationResponse {
    fn new(client: RegisteredClient, registration: Registration) -> Self {
        Self {
            client_id: client.id,
            client_id_issued_at: client.created_at.timestamp(),
            client_name: client.name,
            redirect_uris: registration.redirect_uris,
            grant_types: registration.grant_types,
            response_types: ["code"],
            token_endpoint_auth_method: "none",
        }
    }
}

/// A token endpoint refusal (RFC 6749 §5.2).
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("invalid_request: {0}")]
    InvalidRequest(&'static str),
    /// The code or refresh token is invalid, expired, revoked or bound to
    /// another client. One answer for all, by design.
    #[error("invalid_grant")]
    InvalidGrant,
    #[error(transparent)]
    Backend(BackendError),
}

impl TokenError {
    /// The RFC 6749 §5.2 error code; `None` for a backend failure (500).
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::InvalidRequest(_) => Some("invalid_request"),
            Self::InvalidGrant => Some("invalid_grant"),
            Self::Backend(_) => None,
        }
    }

    /// The human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidRequest(d) => d,
            Self::InvalidGrant => {
                "The authorization code or refresh token is invalid, expired, revoked or was issued to another client."
            }
            Self::Backend(_) => "Internal error.",
        }
    }
}

impl From<BackendError> for TokenError {
    fn from(e: BackendError) -> Self {
        Self::Backend(e)
    }
}

/// The token response of the code and refresh grants (RFC 6749 §5.1). Send
/// it with `Cache-Control: no-store`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// A started device authorization (RFC 8628 §3.2), less the verification
/// URIs, which are the host's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedDevice<S> {
    /// For the client only; stored as its hash.
    pub device_code: String,
    pub device: Device<S>,
}

impl<S> StartedDevice<S> {
    /// `expires_in`, in seconds.
    pub fn expires_in(&self) -> i64 {
        (self.device.expires_at - self.device.created_at).num_seconds()
    }
}

/// A device token request that issued nothing (RFC 8628 §3.5).
#[derive(Debug, thiserror::Error)]
pub enum PollError {
    #[error("authorization_pending")]
    Pending,
    /// Polled too fast; the interval is now `interval` seconds.
    #[error("slow_down")]
    SlowDown { interval: u32 },
    #[error("access_denied")]
    Denied,
    #[error("expired_token")]
    Expired,
    /// An unknown, redeemed or foreign device code, or a refused subject.
    #[error(transparent)]
    Token(#[from] TokenError),
}

impl PollError {
    /// The RFC 8628 §3.5 / RFC 6749 §5.2 error code; `None` for a backend
    /// failure (500).
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Pending => Some("authorization_pending"),
            Self::SlowDown { .. } => Some("slow_down"),
            Self::Denied => Some("access_denied"),
            Self::Expired => Some("expired_token"),
            Self::Token(e) => e.code(),
        }
    }

    /// The human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Pending => "The authorization request is still pending.",
            Self::SlowDown { .. } => "Polling too fast; wait longer between requests.",
            Self::Denied => "The authorization request was denied.",
            Self::Expired => "The device code has expired.",
            Self::Token(e) => e.description(),
        }
    }
}

/// Why [`Server::verify_active`] refused an access token. Answer all but
/// `Backend` with 401 `invalid_token` (RFC 6750 §3.1).
#[derive(Debug, thiserror::Error)]
pub enum ActiveError {
    #[error(transparent)]
    Invalid(#[from] VerifyError),
    /// The token verifies, but its grant is unknown, revoked or expired.
    #[error("grant is not active")]
    Inactive,
    #[error(transparent)]
    Backend(BackendError),
}

impl From<BackendError> for PollError {
    fn from(e: BackendError) -> Self {
        Self::Token(TokenError::Backend(e))
    }
}

impl<S: Clone + PartialEq + Send + Sync + 'static> Server<S> {
    pub fn new(
        config: Config,
        store: Arc<dyn OAuthStore<Subject = S>>,
        subjects: Arc<dyn Subjects<S>>,
        events: Arc<dyn Events<S>>,
        fetcher: Arc<dyn MetadataFetcher>,
    ) -> Self {
        Self {
            config,
            store,
            subjects,
            events,
            fetcher,
            tokens: Arc::new(Base64Url),
            refresh_idle: None,
        }
    }

    /// A refresh token not used within `idle` of its issue no longer
    /// refreshes, however long its grant has left: the session ends when its
    /// holder stops using it. Without this, only the grant's absolute
    /// lifetime ends it.
    #[must_use]
    pub fn with_refresh_idle(mut self, idle: Duration) -> Self {
        self.refresh_idle = Some(idle);
        self
    }

    /// Mint codes and refresh tokens in the host's format instead of
    /// [`Base64Url`].
    #[must_use]
    pub fn with_token_format(mut self, tokens: Arc<dyn TokenFormat>) -> Self {
        self.tokens = tokens;
        self
    }

    /// The store, for the host's own queries (connection lists, sweeps).
    pub fn store(&self) -> &Arc<dyn OAuthStore<Subject = S>> {
        &self.store
    }

    // --- Clients -------------------------------------------------------------

    /// Resolve `client_id`. An HTTPS URL is a metadata document, fetched
    /// unless a cached copy is fresh; anything else must be a registered
    /// client.
    pub async fn resolve_client(&self, client_id: &str) -> Result<Client, ClientError> {
        if let Some(url) = document_url(client_id, &self.config.documents) {
            let document = self.document(&url).await?;
            return client_from_document(client_id, &url, &document);
        }
        // A URL that is not a usable document URL is not a registration id
        // either.
        if Url::parse(client_id).is_ok() {
            return Err(ClientError::Unknown);
        }
        let row = self
            .store
            .use_client(client_id)
            .await
            .map_err(ClientError::Backend)?
            .ok_or(ClientError::Unknown)?;
        Ok(Client {
            id: row.id,
            name: row.name,
            redirect_uris: row.redirect_uris,
        })
    }

    async fn document(&self, url: &Url) -> Result<Value, ClientError> {
        if let Some(cached) = self
            .store
            .cached_document(url.as_str())
            .await
            .map_err(ClientError::Backend)?
        {
            return Ok(cached);
        }
        let (document, ttl) =
            client::fetch_document(self.fetcher.as_ref(), url, &self.config.documents).await?;
        if !ttl.is_zero() {
            let expires = Utc::now() + Duration::from_std(ttl).unwrap_or_else(|_| Duration::zero());
            self.store
                .store_document(url.as_str(), document.clone(), expires)
                .await
                .map_err(ClientError::Backend)?;
        }
        Ok(document)
    }

    /// Register a public client (RFC 7591) from its metadata `doc`. Rate
    /// limiting is the host's.
    pub async fn register(
        &self,
        doc: &Map<String, Value>,
    ) -> Result<RegistrationResponse, RegisterError> {
        let registration = request::check_registration(doc).map_err(RegisterError::Invalid)?;
        let client = self
            .store
            .insert_client(
                Uuid::new_v4().to_string(),
                registration.name.clone(),
                &registration.redirect_uris,
            )
            .await
            .map_err(RegisterError::Backend)?;
        Ok(RegistrationResponse::new(client, registration))
    }

    // --- Authorization ---------------------------------------------------------

    /// Validate an authorization request (its raw query) and store it as
    /// pending. Before the redirect URI is trusted, an error is a page; after,
    /// it goes back to the client.
    pub async fn authorize(&self, query: &str) -> Result<Pending<S>, AuthorizeError> {
        let page = |e| Err(AuthorizeError::Page(e));
        let Ok(params) = request::parse_query(query) else {
            return page(PageError::DuplicateParameter);
        };
        let get = |k: &str| params.get(k).map(String::as_str);
        let Some(client_id) = get("client_id") else {
            return page(PageError::NoClient);
        };
        let client = match self.resolve_client(client_id).await {
            Ok(client) => client,
            Err(ClientError::Backend(e)) => return Err(AuthorizeError::Backend(e)),
            Err(e) => return page(PageError::UnknownClient(e)),
        };
        let Some(redirect_uri) = get("redirect_uri").filter(|r| client.matches_redirect(r)) else {
            return page(PageError::UnregisteredRedirect);
        };

        // From here on errors go back to the client.
        let state = get("state");
        let checked = match request::check_authorization_request(
            &params,
            &self.config.resource,
            &self.config.scopes,
        ) {
            Ok(checked) => checked,
            Err(error) => {
                let mut params = vec![("error", error)];
                if let Some(state) = state {
                    params.push(("state", state));
                }
                let to = with_params(redirect_uri, &params).unwrap_or_default();
                return Err(AuthorizeError::Redirect(to));
            }
        };
        self.store
            .insert_pending(NewPending {
                client_id: client.id.clone(),
                client_name: client.name.clone(),
                loopback_only: client.loopback_only(),
                redirect_uri: redirect_uri.to_string(),
                scope: checked.scope,
                state: state.map(str::to_owned),
                code_challenge: checked.code_challenge.to_string(),
                resource: self.config.resource.clone(),
                ttl: self.config.pending_ttl,
            })
            .await
            .map_err(AuthorizeError::Backend)
    }

    /// The pending authorization `id` as `subject` sees it; the first subject
    /// to ask binds it.
    pub async fn pending(&self, id: Uuid, subject: &S) -> Result<Option<Pending<S>>, BackendError> {
        self.store.claim_pending(id, subject).await
    }

    /// Approve pending authorization `id` for `subject`: create the grant and
    /// a one-time code. `kept`, when given, narrows the grant to a subset of
    /// the requested scopes; a refused narrowing leaves the request pending.
    pub async fn approve(
        &self,
        id: Uuid,
        subject: &S,
        kept: Option<&[String]>,
    ) -> Result<Approved<S>, ApproveError> {
        let requested = self
            .store
            .claim_pending(id, subject)
            .await
            .map_err(ApproveError::Backend)?
            .ok_or(ApproveError::NotFound)?;
        let scope = self
            .config
            .scopes
            .approved(&requested.scope, kept)
            .ok_or(ApproveError::InvalidScope)?;
        let mut row = self
            .store
            .take_pending(id, subject)
            .await
            .map_err(ApproveError::Backend)?
            .ok_or(ApproveError::NotFound)?;
        row.scope = scope;
        let code = self.tokens.mint(Opaque::Code);
        let grant = self
            .store
            .create_grant_with_code(
                &row,
                subject,
                self.config.grant_lifetime,
                hash_token(&code),
                self.config.code_ttl,
            )
            .await
            .map_err(ApproveError::Backend)?;
        self.events.grant_created(&grant).await;
        let mut params = vec![("code", code.as_str())];
        if let Some(state) = row.state.as_deref() {
            params.push(("state", state));
        }
        let redirect = with_params(&row.redirect_uri, &params).unwrap_or_default();
        Ok(Approved { grant, redirect })
    }

    /// Deny pending authorization `id`; `None` when there is nothing to deny.
    pub async fn deny(&self, id: Uuid, subject: &S) -> Result<Option<Denied<S>>, BackendError> {
        let Some(pending) = self.store.take_pending(id, subject).await? else {
            return Ok(None);
        };
        let mut params = vec![("error", "access_denied")];
        if let Some(state) = pending.state.as_deref() {
            params.push(("state", state));
        }
        let redirect = with_params(&pending.redirect_uri, &params).unwrap_or_default();
        Ok(Some(Denied { pending, redirect }))
    }

    // --- Token endpoint ----------------------------------------------------------

    /// `grant_type=authorization_code` (RFC 6749 §4.1.3, RFC 7636 §4.5).
    /// `form` is the parsed body; `client_id` the public client's id, from the
    /// form or the host's client authentication. A second exchange of one code
    /// revokes the grant.
    pub async fn exchange_code(
        &self,
        form: &HashMap<String, String>,
        client_id: Option<&str>,
        client_ip: Option<&str>,
    ) -> Result<TokenResponse, TokenError> {
        let (Some(code), Some(client_id), Some(redirect_uri), Some(verifier)) = (
            form.get("code"),
            client_id,
            form.get("redirect_uri"),
            form.get("code_verifier"),
        ) else {
            return Err(TokenError::InvalidRequest(
                "code, client_id, redirect_uri and code_verifier are required.",
            ));
        };
        let row = self
            .store
            .find_code(&hash_token(code))
            .await?
            .ok_or(TokenError::InvalidGrant)?;
        let bound = row.client_id == client_id
            && row.redirect_uri == *redirect_uri
            && form.get("resource").is_none_or(|r| *r == row.resource)
            && row.expires_at > Utc::now()
            && crate::pkce::pkce_matches(verifier, &row.code_challenge);
        if !bound {
            return Err(TokenError::InvalidGrant);
        }
        let grant = self
            .store
            .find_grant(row.grant_id)
            .await?
            .ok_or(TokenError::InvalidGrant)?;
        if !self.store.use_code(row.id).await? {
            // A second exchange: whoever holds the code is not to be trusted,
            // and neither are the tokens the first exchange issued.
            self.revoke(&grant, reason::CODE_REUSE, client_ip).await?;
            return Err(TokenError::InvalidGrant);
        }
        if !grant.is_active(Utc::now()) {
            return Err(TokenError::InvalidGrant);
        }
        self.tokens_for(&grant, client_ip).await
    }

    /// `grant_type=refresh_token` (RFC 6749 §6), rotating (OAuth 2.1
    /// §4.3.1): every refresh issues a new refresh token; presenting a rotated
    /// one revokes the grant. The grant, as in [`Self::issue_grant`], and the
    /// tokens.
    pub async fn refresh(
        &self,
        form: &HashMap<String, String>,
        client_id: Option<&str>,
        client_ip: Option<&str>,
    ) -> Result<(Grant<S>, TokenResponse), TokenError> {
        let (Some(presented), Some(client_id)) = (form.get("refresh_token"), client_id) else {
            return Err(TokenError::InvalidRequest(
                "refresh_token and client_id are required.",
            ));
        };
        let token = self
            .store
            .find_refresh_token(&hash_token(presented))
            .await?
            .ok_or(TokenError::InvalidGrant)?;
        let grant = self
            .store
            .find_grant(token.grant_id)
            .await?
            .ok_or(TokenError::InvalidGrant)?;
        if grant.client_id != client_id {
            return Err(TokenError::InvalidGrant);
        }
        if token.rotated_at.is_some() {
            self.revoke(&grant, reason::REFRESH_REUSE, client_ip)
                .await?;
            return Err(TokenError::InvalidGrant);
        }
        let now = Utc::now();
        // Idle expiry after the reuse check, as with the grant's own: a
        // stolen token presented late is still worth revoking the grant for.
        let idle_over = self
            .refresh_idle
            .is_some_and(|idle| now >= token.issued_at + idle);
        if idle_over || !grant.is_active(now) {
            return Err(TokenError::InvalidGrant);
        }
        // Checks before rotation, so a refused refresh leaves nothing behind.
        let access_token = self.issue(&grant, client_ip).await?;
        let next = self.tokens.mint(Opaque::RefreshToken);
        if !self
            .store
            .rotate_refresh_token(&token, &grant, hash_token(&next))
            .await?
        {
            // Rotated concurrently: two holders of one token.
            self.revoke(&grant, reason::REFRESH_REUSE, client_ip)
                .await?;
            return Err(TokenError::InvalidGrant);
        }
        let response = self.response(access_token, &grant, Some(next));
        Ok((grant, response))
    }

    /// Create a grant for `subject`, whom the host has already authenticated
    /// (a browser login after its identity provider, say), and issue its
    /// tokens: the authorization-code flow without the redirect. `scope` is
    /// checked against the known scopes; empty means the default scope. A
    /// refresh token comes with an offline scope, as in [`Self::exchange_code`].
    pub async fn issue_grant(
        &self,
        subject: &S,
        client_id: &str,
        client_name: &str,
        scope: &str,
    ) -> Result<(Grant<S>, TokenResponse), TokenError> {
        let scope = self.requested_scope(scope)?;
        let grant = self
            .store
            .create_grant(NewGrant {
                subject: subject.clone(),
                client_id: client_id.to_owned(),
                client_name: client_name.to_owned(),
                scope,
                lifetime: self.config.grant_lifetime,
            })
            .await?;
        self.events.grant_created(&grant).await;
        let response = self.tokens_for(&grant, None).await?;
        Ok((grant, response))
    }

    // --- Device authorization grant (RFC 8628) -------------------------------

    /// Start a device authorization (RFC 8628 §3.1) for `client_id`, which the
    /// host has already accepted: a device client is public and usually one
    /// the host ships. `scope` as in [`Self::issue_grant`].
    pub async fn start_device(
        &self,
        client_id: &str,
        client_name: &str,
        scope: &str,
    ) -> Result<StartedDevice<S>, TokenError> {
        let scope = self.requested_scope(scope)?;
        let device_code = self.tokens.mint(Opaque::DeviceCode);
        for _ in 0..USER_CODE_ATTEMPTS {
            let new = NewDevice {
                client_id: client_id.to_owned(),
                client_name: device::client_name(client_name),
                scope: scope.clone(),
                device_code_hash: hash_token(&device_code),
                user_code: device::generate_user_code(),
                interval_seconds: POLL_INTERVAL,
                ttl: Duration::seconds(DEVICE_TTL_SECS),
            };
            if let Some(device) = self.store.insert_device(new).await? {
                return Ok(StartedDevice {
                    device_code,
                    device,
                });
            }
        }
        Err(TokenError::Backend("no free user code".into()))
    }

    /// The device authorization a person typed `user_code` for, while it can
    /// still be decided: for the host's verification page. `None` for a
    /// malformed, unknown, decided or expired code.
    pub async fn device(
        &self,
        user_code: &str,
        subject: &S,
    ) -> Result<Option<Device<S>>, BackendError> {
        let Some(code) = device::normalize_user_code(user_code) else {
            return Ok(None);
        };
        let found = self.store.device_by_user_code(&code, subject).await?;
        Ok(found.filter(|d| device::decidable(d, Utc::now())))
    }

    /// Approve the device authorization for `user_code` as `subject`; the
    /// client's next poll gets the tokens. `None` when there was nothing to
    /// approve.
    pub async fn approve_device(
        &self,
        user_code: &str,
        subject: &S,
    ) -> Result<Option<Device<S>>, BackendError> {
        self.decide_device(user_code, subject, true).await
    }

    /// Deny the device authorization for `user_code`; the client's next poll
    /// gets `access_denied`. `None` when there was nothing to deny.
    pub async fn deny_device(
        &self,
        user_code: &str,
        subject: &S,
    ) -> Result<Option<Device<S>>, BackendError> {
        self.decide_device(user_code, subject, false).await
    }

    async fn decide_device(
        &self,
        user_code: &str,
        subject: &S,
        approve: bool,
    ) -> Result<Option<Device<S>>, BackendError> {
        let Some(found) = self.device(user_code, subject).await? else {
            return Ok(None);
        };
        let decided = self.store.decide_device(found.id, subject, approve).await?;
        Ok(decided.then_some(found))
    }

    /// `grant_type=urn:ietf:params:oauth:grant-type:device_code` (RFC 8628
    /// §3.4). Polling faster than the interval raises it (`slow_down`); an
    /// approved authorization is redeemed once, through the subject check.
    /// The new grant, as in [`Self::issue_grant`], and its tokens.
    pub async fn poll_device(
        &self,
        device_code: &str,
        client_id: &str,
        client_ip: Option<&str>,
    ) -> Result<(Grant<S>, TokenResponse), PollError> {
        let found = self
            .store
            .find_device(&hash_token(device_code))
            .await?
            .filter(|d| d.client_id == client_id)
            .ok_or(TokenError::InvalidGrant)?;
        let now = Utc::now();
        match device::judge_poll(&found, now) {
            Poll::Pending => {
                self.store
                    .record_poll(found.id, now, found.interval_seconds)
                    .await?;
                Err(PollError::Pending)
            }
            Poll::SlowDown { interval } => {
                self.store.record_poll(found.id, now, interval).await?;
                Err(PollError::SlowDown { interval })
            }
            Poll::Denied => Err(PollError::Denied),
            Poll::Expired => Err(PollError::Expired),
            Poll::Redeemed => Err(TokenError::InvalidGrant.into()),
            Poll::Redeem => {
                let subject = found.subject.ok_or(TokenError::InvalidGrant)?;
                let grant = self
                    .store
                    .redeem_device(
                        found.id,
                        NewGrant {
                            subject,
                            client_id: found.client_id,
                            client_name: found.client_name,
                            scope: found.scope,
                            lifetime: self.config.grant_lifetime,
                        },
                    )
                    .await?
                    // Redeemed concurrently.
                    .ok_or(TokenError::InvalidGrant)?;
                self.events.grant_created(&grant).await;
                let response = self.tokens_for(&grant, client_ip).await?;
                Ok((grant, response))
            }
        }
    }

    /// `scope` checked against the known scopes, canonical; empty means the
    /// default scope.
    fn requested_scope(&self, scope: &str) -> Result<String, TokenError> {
        if scope.trim().is_empty() {
            return Ok(self.config.scopes.default_scope());
        }
        let parsed = self
            .config
            .scopes
            .parse(scope)
            .map_err(|_| TokenError::InvalidRequest("Unknown scope."))?;
        Ok(self.config.scopes.join(&parsed))
    }

    /// The access token for `grant`, and a refresh token with an offline
    /// scope.
    async fn tokens_for(
        &self,
        grant: &Grant<S>,
        client_ip: Option<&str>,
    ) -> Result<TokenResponse, TokenError> {
        let access_token = self.issue(grant, client_ip).await?;
        let refresh_token = if self.config.scopes.is_offline(&grant.scope) {
            let token = self.tokens.mint(Opaque::RefreshToken);
            self.store
                .insert_refresh_token(grant, hash_token(&token))
                .await?;
            Some(token)
        } else {
            None
        };
        Ok(self.response(access_token, grant, refresh_token))
    }

    /// Run the subject check for `grant` and mint its access token, revoking
    /// the grant when the check fails.
    async fn issue(&self, grant: &Grant<S>, client_ip: Option<&str>) -> Result<String, TokenError> {
        let extra = match self.subjects.recheck(grant).await? {
            Recheck::Allow(extra) => extra,
            Recheck::Revoke(why) => {
                self.revoke(grant, &why, client_ip).await?;
                return Err(TokenError::InvalidGrant);
            }
        };
        let grant_id = grant.id.to_string();
        let claims = AccessClaims {
            resource: &self.config.resource,
            kind: &self.config.token_kind,
            scope: &grant.scope,
            client_id: &grant.client_id,
            grant_id: &grant_id,
        };
        token::mint(
            &self.config.signer,
            Utc::now(),
            self.config.access_token_secs,
            &claims,
            extra,
        )
        .map_err(|e| TokenError::Backend(Box::new(e)))
    }

    fn response(
        &self,
        access_token: String,
        grant: &Grant<S>,
        refresh_token: Option<String>,
    ) -> TokenResponse {
        TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: self.config.access_token_secs,
            scope: grant.scope.clone(),
            refresh_token,
        }
    }

    /// Revoke `grant` for `why`; if this call revoked it, tell [`Events`].
    /// `false` when it was already revoked.
    pub async fn revoke(
        &self,
        grant: &Grant<S>,
        why: &str,
        client_ip: Option<&str>,
    ) -> Result<bool, BackendError> {
        if !self.store.revoke_grant(grant.id, why).await? {
            return Ok(false);
        }
        self.events.grant_revoked(grant, why, client_ip).await;
        Ok(true)
    }

    /// Verify an access token's signature, expiry, audience and kind; its
    /// claims. Whether its grant is still live is the caller's next question:
    /// [`Self::verify_active`] answers both.
    pub fn verify(&self, token: &str) -> Result<Map<String, Value>, VerifyError> {
        token::verify(
            &self.config.signer,
            token,
            &self.config.resource,
            &self.config.token_kind,
        )
    }

    /// [`Self::verify`], with the claims read as the host's type `T`
    /// ([`token::verify_as`]).
    pub fn verify_as<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T, VerifyError> {
        token::verify_as(
            &self.config.signer,
            token,
            &self.config.resource,
            &self.config.token_kind,
        )
    }

    /// [`Self::verify`], then the token's grant, which must still be active:
    /// a revoked or expired grant ends its access tokens before they expire.
    /// The grant and the claims.
    pub async fn verify_active(
        &self,
        token: &str,
    ) -> Result<(Grant<S>, Map<String, Value>), ActiveError> {
        let claims = self.verify(token)?;
        let Some(id) = claims
            .get("grant_id")
            .and_then(Value::as_str)
            .and_then(|id| id.parse().ok())
        else {
            return Err(ActiveError::Inactive);
        };
        match self.store.find_grant(id).await {
            Ok(Some(grant)) if grant.is_active(Utc::now()) => Ok((grant, claims)),
            Ok(_) => Err(ActiveError::Inactive),
            Err(e) => Err(ActiveError::Backend(e)),
        }
    }
}
