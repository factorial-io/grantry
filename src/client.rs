// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Client identification: a Client ID Metadata Document for an HTTPS
//! `client_id` URL, otherwise a dynamic registration (RFC 7591). Both resolve
//! to one [`Client`].
//!
//! Fetching goes through [`MetadataFetcher`], so the host applies its own
//! egress policy (no internal addresses, no redirects). grantry keeps the
//! document rules, the size cap, the timeout and the cache policy.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use url::Url;

use crate::redirect::{is_loopback, redirect_matches, registrable_redirect};
use crate::store::BackendError;

/// Largest metadata document accepted.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// An identified client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
}

impl Client {
    /// Whether `requested` matches a registered redirect URI.
    pub fn matches_redirect(&self, requested: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| redirect_matches(registered, requested))
    }

    /// Every registered redirect URI is a loopback address: any local program
    /// can receive this client's codes.
    pub fn loopback_only(&self) -> bool {
        self.redirect_uris.iter().all(|u| is_loopback(u))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("unknown client")]
    Unknown,
    #[error("client metadata document refused: {0}")]
    Refused(String),
    #[error(transparent)]
    Backend(BackendError),
}

/// How metadata documents are fetched and cached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentPolicy {
    /// Accept `http` document URLs (development only).
    pub allow_insecure: bool,
    /// For the whole fetch.
    pub timeout: Duration,
    /// Cap on the `Cache-Control: max-age` a document is cached for.
    pub cache_max: Duration,
}

impl Default for DocumentPolicy {
    fn default() -> Self {
        Self {
            allow_insecure: false,
            timeout: Duration::from_secs(5),
            cache_max: Duration::from_secs(86_400),
        }
    }
}

/// A fetched document.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub body: Bytes,
    pub cache_control: Option<String>,
}

/// Why a fetch failed: a description for logs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FetchError(pub String);

/// Fetches a metadata document. Implementations apply the host's egress
/// policy, follow no redirects, refuse a non-success status and stop
/// reading past `limit` bytes. grantry enforces the timeout around the call.
#[async_trait]
pub trait MetadataFetcher: Send + Sync {
    async fn fetch(&self, url: &Url, limit: usize) -> Result<Fetched, FetchError>;
}

/// The metadata document URL `client_id` names, if it is one: an `https`
/// URL (or `http` when insecure documents are allowed) with a path, no
/// credentials and no fragment, at most 2048 characters.
pub fn document_url(client_id: &str, policy: &DocumentPolicy) -> Option<Url> {
    if client_id.len() > 2048 {
        return None;
    }
    let url = Url::parse(client_id).ok()?;
    let scheme_ok = url.scheme() == "https" || (policy.allow_insecure && url.scheme() == "http");
    (scheme_ok
        && url.host_str().is_some()
        && url.path() != "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

/// Validate a document against the URL it came from.
pub fn client_from_document(
    client_id: &str,
    url: &Url,
    document: &Value,
) -> Result<Client, ClientError> {
    let refused = |why: &str| ClientError::Refused(why.to_string());
    if document.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(refused("client_id does not equal the document URL"));
    }
    if let Some(method) = document.get("token_endpoint_auth_method")
        && method.as_str() != Some("none")
    {
        return Err(refused(
            "only public clients (auth method none) are supported",
        ));
    }
    let redirect_uris: Vec<String> = document
        .get("redirect_uris")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    if redirect_uris.is_empty() || !redirect_uris.iter().all(|u| registrable_redirect(u)) {
        return Err(refused("redirect_uris missing or not registrable"));
    }
    let name = document
        .get("client_name")
        .and_then(Value::as_str)
        .map(|n| n.chars().take(255).collect::<String>())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| url.host_str().unwrap_or_default().to_string());
    Ok(Client {
        id: client_id.to_string(),
        name,
        redirect_uris,
    })
}

/// `max-age` from a `Cache-Control` value; zero for `no-store`, `no-cache`
/// or no `max-age`.
pub fn max_age(cache_control: Option<&str>) -> Duration {
    let Some(value) = cache_control else {
        return Duration::ZERO;
    };
    let mut age = None;
    for directive in value.split(',').map(str::trim) {
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return Duration::ZERO;
        }
        if let Some(n) = lower.strip_prefix("max-age=") {
            age = n.trim_matches('"').parse::<u64>().ok();
        }
    }
    Duration::from_secs(age.unwrap_or(0))
}

/// Fetch a metadata document within `policy.timeout` and at most
/// [`MAX_DOCUMENT_BYTES`]. Returns the JSON and how long it may be cached
/// (`max-age`, capped by `policy.cache_max`).
pub async fn fetch_document(
    fetcher: &dyn MetadataFetcher,
    url: &Url,
    policy: &DocumentPolicy,
) -> Result<(Value, Duration), ClientError> {
    let fetched = tokio::time::timeout(policy.timeout, fetcher.fetch(url, MAX_DOCUMENT_BYTES))
        .await
        .map_err(|_| ClientError::Refused("timed out".into()))?
        .map_err(|e| ClientError::Refused(e.0))?;
    if fetched.body.len() > MAX_DOCUMENT_BYTES {
        return Err(ClientError::Refused("document too large".into()));
    }
    let document: Value = serde_json::from_slice(&fetched.body)
        .map_err(|_| ClientError::Refused("not JSON".into()))?;
    let ttl = max_age(fetched.cache_control.as_deref()).min(policy.cache_max);
    Ok((document, ttl))
}

/// A [`MetadataFetcher`] over reqwest: no redirects, no egress policy beyond
/// that. Hosts that must keep documents off internal addresses wrap their own
/// client instead.
#[cfg(feature = "client-fetch")]
#[derive(Debug, Clone)]
pub struct ReqwestFetcher(pub reqwest::Client);

#[cfg(feature = "client-fetch")]
impl ReqwestFetcher {
    /// A client that follows no redirects.
    pub fn new() -> Result<Self, reqwest::Error> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(Self)
    }
}

#[cfg(feature = "client-fetch")]
#[async_trait]
impl MetadataFetcher for ReqwestFetcher {
    async fn fetch(&self, url: &Url, limit: usize) -> Result<Fetched, FetchError> {
        let failed = |what: &str, e: reqwest::Error| FetchError(format!("{what}: {e}"));
        let mut response = self
            .0
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| failed("fetch failed", e))?;
        if !response.status().is_success() {
            return Err(FetchError(format!("status {}", response.status())));
        }
        let cache_control = response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| failed("read failed", e))?
        {
            if body.len() + chunk.len() > limit {
                return Err(FetchError("document too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Fetched {
            body: body.into(),
            cache_control,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// Serves one canned answer, optionally after a delay.
    pub(crate) struct Canned {
        pub answer: Result<Fetched, FetchError>,
        pub delay: Duration,
    }

    impl Canned {
        pub(crate) fn json(doc: Value, cache_control: Option<&str>) -> Self {
            Self {
                answer: Ok(Fetched {
                    body: serde_json::to_vec(&doc).unwrap().into(),
                    cache_control: cache_control.map(str::to_owned),
                }),
                delay: Duration::ZERO,
            }
        }
    }

    #[async_trait]
    impl MetadataFetcher for Canned {
        async fn fetch(&self, _url: &Url, _limit: usize) -> Result<Fetched, FetchError> {
            tokio::time::sleep(self.delay).await;
            self.answer.clone()
        }
    }

    #[test]
    fn loopback_only_clients() {
        let client = |uris: &[&str]| Client {
            id: "x".into(),
            name: "x".into(),
            redirect_uris: uris.iter().map(ToString::to_string).collect(),
        };
        assert!(
            client(&["http://localhost/callback", "http://127.0.0.1/callback"]).loopback_only()
        );
        assert!(!client(&["https://claude.ai/api/mcp/auth_callback"]).loopback_only());
    }

    #[test]
    fn cache_control_parsing() {
        assert_eq!(max_age(None), Duration::ZERO);
        assert_eq!(
            max_age(Some("public, max-age=3600")),
            Duration::from_secs(3600)
        );
        assert_eq!(max_age(Some("max-age=60, no-store")), Duration::ZERO);
        assert_eq!(max_age(Some("no-cache")), Duration::ZERO);
    }

    #[test]
    fn document_urls() {
        let strict = DocumentPolicy::default();
        assert!(
            document_url(
                "https://claude.ai/oauth/claude-code-client-metadata",
                &strict
            )
            .is_some()
        );
        assert!(document_url("https://claude.ai/", &strict).is_none());
        assert!(document_url("http://claude.ai/x", &strict).is_none());
        assert!(document_url("https://u:p@claude.ai/x", &strict).is_none());
        assert!(document_url("3f2b9c1e-uuid", &strict).is_none());
        assert!(
            document_url(&format!("https://a.example/{}", "x".repeat(2048)), &strict).is_none()
        );
        let insecure = DocumentPolicy {
            allow_insecure: true,
            ..DocumentPolicy::default()
        };
        assert!(document_url("http://claude.ai/x", &insecure).is_some());
    }

    #[test]
    fn document_must_name_its_own_url() {
        let url = Url::parse("https://app.example/client.json").unwrap();
        let ok = json!({
            "client_id": url.as_str(),
            "client_name": "App",
            "redirect_uris": ["https://app.example/cb"],
        });
        assert_eq!(
            client_from_document(url.as_str(), &url, &ok).unwrap().name,
            "App"
        );

        let mut other = ok.clone();
        other["client_id"] = "https://evil.example/client.json".into();
        assert!(client_from_document(url.as_str(), &url, &other).is_err());

        let mut no_redirects = ok.clone();
        no_redirects["redirect_uris"] = json!([]);
        assert!(client_from_document(url.as_str(), &url, &no_redirects).is_err());

        let mut confidential = ok;
        confidential["token_endpoint_auth_method"] = "client_secret_basic".into();
        assert!(client_from_document(url.as_str(), &url, &confidential).is_err());
    }

    fn url() -> Url {
        Url::parse("https://app.example/client.json").unwrap()
    }

    #[tokio::test]
    async fn invalid_document_is_refused() {
        let fetcher = Canned {
            answer: Ok(Fetched {
                body: Bytes::from_static(b"<html>"),
                cache_control: None,
            }),
            delay: Duration::ZERO,
        };
        let err = fetch_document(&fetcher, &url(), &DocumentPolicy::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not JSON"), "{err}");
    }

    #[tokio::test]
    async fn oversized_document_is_refused() {
        let fetcher = Canned {
            answer: Ok(Fetched {
                body: vec![b' '; MAX_DOCUMENT_BYTES + 1].into(),
                cache_control: None,
            }),
            delay: Duration::ZERO,
        };
        let err = fetch_document(&fetcher, &url(), &DocumentPolicy::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn cache_lifetime_is_capped() {
        let fetcher = Canned::json(json!({}), Some("max-age=999999"));
        let policy = DocumentPolicy {
            cache_max: Duration::from_secs(60),
            ..DocumentPolicy::default()
        };
        let (_, ttl) = fetch_document(&fetcher, &url(), &policy).await.unwrap();
        assert_eq!(ttl, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn slow_fetch_times_out() {
        let mut fetcher = Canned::json(json!({}), None);
        fetcher.delay = Duration::from_secs(10);
        let policy = DocumentPolicy {
            timeout: Duration::from_millis(50),
            ..DocumentPolicy::default()
        };
        let err = fetch_document(&fetcher, &url(), &policy).await.unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
