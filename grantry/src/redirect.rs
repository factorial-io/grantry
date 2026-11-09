// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Redirect URIs: which may be registered, and exact matching with any port
//! on loopback (RFC 8252 §7.3).

use url::Url;

/// `http://localhost…` or `http://127.0.0.1…`.
fn loopback_url(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
}

/// Whether `uri` is a loopback redirect URI.
pub fn is_loopback(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|u| loopback_url(&u))
}

/// Whether `uri` may be registered as a redirect URI: absolute HTTPS, or
/// plain HTTP to `localhost` / `127.0.0.1` (RFC 8252 §7.3); never a fragment.
pub fn registrable_redirect(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|u| {
        u.fragment().is_none()
            && u.host_str().is_some()
            && (u.scheme() == "https" || loopback_url(&u))
    })
}

/// Exact string match, plus RFC 8252 §7.3: a registered loopback URI matches
/// a request URI that differs only in its port.
pub fn redirect_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(mut reg), Ok(mut req)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    if !loopback_url(&reg) || !loopback_url(&req) {
        return false;
    }
    // Setting the port cannot fail for an http URL with a host.
    let _ = reg.set_port(None);
    let _ = req.set_port(None);
    reg == req
}

/// `redirect_uri` with `params` appended to its query. `None` when
/// `redirect_uri` is not a URL, which a validated one always is.
pub fn with_params(redirect_uri: &str, params: &[(&str, &str)]) -> Option<String> {
    let mut url = Url::parse(redirect_uri).ok()?;
    {
        let mut query = url.query_pairs_mut();
        for (k, v) in params {
            query.append_pair(k, v);
        }
    }
    Some(url.into())
}

/// The host of a URI, or empty when it has none.
pub fn host_of(uri: &str) -> String {
    Url::parse(uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_matching() {
        let hosted = "https://claude.ai/api/mcp/auth_callback";
        assert!(redirect_matches(hosted, hosted));
        assert!(!redirect_matches(hosted, "https://claude.ai/api/mcp/other"));
        assert!(!redirect_matches(
            hosted,
            "https://claude.ai:8443/api/mcp/auth_callback"
        ));

        let local = "http://localhost/callback";
        assert!(redirect_matches(local, "http://localhost:3118/callback"));
        assert!(!redirect_matches(local, "http://localhost:3118/other"));
        assert!(!redirect_matches(local, "http://127.0.0.1:3118/callback"));
        assert!(redirect_matches(
            "http://127.0.0.1:1/callback",
            "http://127.0.0.1:9/callback"
        ));
        // Only loopback hosts are port-agnostic.
        assert!(!redirect_matches(
            "http://example.com/callback",
            "http://example.com:81/callback"
        ));
    }

    #[test]
    fn registrable_redirects() {
        assert!(registrable_redirect(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(registrable_redirect("http://localhost/callback"));
        assert!(registrable_redirect("http://127.0.0.1:33418/cb"));
        assert!(!registrable_redirect("http://example.com/callback"));
        assert!(!registrable_redirect("https://claude.ai/cb#frag"));
        assert!(!registrable_redirect("not a url"));
        assert!(!registrable_redirect("javascript:alert(1)"));
    }

    #[test]
    fn params_are_appended() {
        assert_eq!(
            with_params(
                "https://a.example/cb?x=1",
                &[("code", "c d"), ("state", "s")]
            )
            .unwrap(),
            "https://a.example/cb?x=1&code=c+d&state=s"
        );
        assert_eq!(host_of("http://localhost:3000/cb"), "localhost");
        assert_eq!(host_of("nope"), "");
    }
}
