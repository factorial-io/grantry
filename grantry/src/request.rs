// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Validation of the requests an authorization server accepts: the
//! authorization request (RFC 6749 §3.1, §4.1.1, RFC 7636 §4.3, RFC 8707)
//! and the dynamic client registration (RFC 7591 §2, §3.2.2). Pure: no
//! framework types.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::pkce::is_s256_challenge;
use crate::redirect::{host_of, registrable_redirect};
use crate::scope::ScopeSpec;

/// A parameter appeared twice (RFC 6749 §3.1, §3.2).
#[derive(Debug, PartialEq, Eq)]
pub struct DuplicateParameter;

/// Parse a query or form body; every parameter at most once.
pub fn parse_query(query: &str) -> Result<HashMap<String, String>, DuplicateParameter> {
    let mut params = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(DuplicateParameter);
        }
    }
    Ok(params)
}

/// What a valid authorization request asks for, once its client and redirect
/// URI are trusted.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizationRequest<'a> {
    pub code_challenge: &'a str,
    /// The canonical scope string.
    pub scope: String,
}

/// Check the parts of an authorization request whose errors go back to the
/// client's redirect URI. `Err` is the RFC 6749 §4.1.2.1 error code.
///
/// `resource` is the protected resource's URL (RFC 8707): the request must
/// name it exactly. No `scope` means the default scopes; a scope string that
/// names an unknown scope, or none, is refused.
pub fn check_authorization_request<'a>(
    params: &'a HashMap<String, String>,
    resource: &str,
    scopes: &ScopeSpec,
) -> Result<AuthorizationRequest<'a>, &'static str> {
    let get = |k: &str| params.get(k).map(String::as_str);
    if get("response_type") != Some("code") {
        return Err("unsupported_response_type");
    }
    let Some(code_challenge) = get("code_challenge")
        .filter(|c| get("code_challenge_method") == Some("S256") && is_s256_challenge(c))
    else {
        return Err("invalid_request");
    };
    if get("resource") != Some(resource) {
        return Err("invalid_target");
    }
    let scope = match get("scope").map(|s| scopes.parse(s)) {
        None => scopes.default_scope(),
        Some(Ok(parsed)) if !parsed.is_empty() => scopes.join(&parsed),
        Some(_) => return Err("invalid_scope"),
    };
    Ok(AuthorizationRequest {
        code_challenge,
        scope,
    })
}

/// Why a registration was refused (RFC 7591 §3.2.2), with the description.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    #[error("invalid_client_metadata: {0}")]
    InvalidClientMetadata(&'static str),
    #[error("invalid_redirect_uri: {0}")]
    InvalidRedirectUri(&'static str),
}

impl RegistrationError {
    /// The RFC 7591 §3.2.2 error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidClientMetadata(_) => "invalid_client_metadata",
            Self::InvalidRedirectUri(_) => "invalid_redirect_uri",
        }
    }

    /// The human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidClientMetadata(d) | Self::InvalidRedirectUri(d) => d,
        }
    }
}

/// A registration this server accepts: a public client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
}

/// Check a client registration document. Only public clients
/// (`token_endpoint_auth_method: none`), the code flow with optional refresh,
/// and one to ten registrable redirect URIs are accepted. The name defaults to
/// the first redirect URI's host and is cut to 255 characters.
pub fn check_registration(doc: &Map<String, Value>) -> Result<Registration, RegistrationError> {
    use RegistrationError::{InvalidClientMetadata, InvalidRedirectUri};

    if let Some(method) = doc.get("token_endpoint_auth_method")
        && method.as_str() != Some("none")
    {
        return Err(InvalidClientMetadata(
            "Only public clients are supported: token_endpoint_auth_method must be none.",
        ));
    }
    let strings = |key: &str| -> Option<Result<Vec<String>, ()>> {
        doc.get(key)
            .map(|v| serde_json::from_value::<Vec<String>>(v.clone()).map_err(|_| ()))
    };
    let grant_types = match strings("grant_types") {
        None => vec!["authorization_code".to_string()],
        Some(Ok(types))
            if !types.is_empty()
                && types
                    .iter()
                    .all(|t| t == "authorization_code" || t == "refresh_token") =>
        {
            types
        }
        Some(_) => {
            return Err(InvalidClientMetadata(
                "Only the authorization_code and refresh_token grant types are supported.",
            ));
        }
    };
    if !matches!(strings("response_types"), None | Some(Ok(_)))
        || strings("response_types")
            .and_then(Result::ok)
            .is_some_and(|r| r != ["code"])
    {
        return Err(InvalidClientMetadata(
            "Only the code response type is supported.",
        ));
    }
    let redirect_uris = match strings("redirect_uris") {
        Some(Ok(uris)) if !uris.is_empty() && uris.len() <= 10 => uris,
        _ => {
            return Err(InvalidRedirectUri(
                "redirect_uris must list one to ten URIs.",
            ));
        }
    };
    if !redirect_uris.iter().all(|u| registrable_redirect(u)) {
        return Err(InvalidRedirectUri(
            "Redirect URIs must be HTTPS, or HTTP to localhost or 127.0.0.1.",
        ));
    }
    let name = doc
        .get("client_name")
        .and_then(Value::as_str)
        .map(|n| n.trim().chars().take(255).collect::<String>())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| host_of(&redirect_uris[0]));
    Ok(Registration {
        name,
        redirect_uris,
        grant_types,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::mcp;
    use serde_json::json;

    fn doc(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn duplicate_parameter_is_refused() {
        assert_eq!(parse_query("a=1&a=2"), Err(DuplicateParameter));
        assert_eq!(parse_query("a=1&b=2").unwrap().len(), 2);
    }

    #[test]
    fn authorization_request_errors_in_rfc_order() {
        let resource = "https://x/mcp";
        let spec = mcp();
        let params = |q: &str| parse_query(q).unwrap();
        assert_eq!(
            check_authorization_request(&params("response_type=token"), resource, &spec),
            Err("unsupported_response_type")
        );
        assert_eq!(
            check_authorization_request(&params("response_type=code"), resource, &spec),
            Err("invalid_request")
        );
        let challenge = "a".repeat(43);
        let plain =
            format!("response_type=code&code_challenge={challenge}&code_challenge_method=plain");
        assert_eq!(
            check_authorization_request(&params(&plain), resource, &spec),
            Err("invalid_request")
        );
        let base =
            format!("response_type=code&code_challenge={challenge}&code_challenge_method=S256");
        assert_eq!(
            check_authorization_request(&params(&base), resource, &spec),
            Err("invalid_target")
        );
        let with_resource = format!("{base}&resource=https%3A%2F%2Fx%2Fmcp");
        let ok = params(&with_resource);
        let ok = check_authorization_request(&ok, resource, &spec).unwrap();
        assert_eq!(ok.scope, "read write run delete");
        for scope in ["nope", "%20"] {
            assert_eq!(
                check_authorization_request(
                    &params(&format!("{with_resource}&scope={scope}")),
                    resource,
                    &spec
                ),
                Err("invalid_scope"),
                "{scope}"
            );
        }
        let narrowed = params(&format!("{with_resource}&scope=run+read"));
        assert_eq!(
            check_authorization_request(&narrowed, resource, &spec)
                .unwrap()
                .scope,
            "read run"
        );
    }

    #[test]
    fn registration_rules() {
        assert_eq!(
            check_registration(&doc(json!({"redirect_uris": []}))),
            Err(RegistrationError::InvalidRedirectUri(
                "redirect_uris must list one to ten URIs."
            ))
        );
        assert!(matches!(
            check_registration(&doc(json!({
                "redirect_uris": ["http://localhost/cb"],
                "token_endpoint_auth_method": "client_secret_basic"
            }))),
            Err(RegistrationError::InvalidClientMetadata(_))
        ));
        assert!(matches!(
            check_registration(&doc(json!({
                "redirect_uris": ["http://localhost/cb"],
                "grant_types": ["client_credentials"]
            }))),
            Err(RegistrationError::InvalidClientMetadata(_))
        ));
        assert!(matches!(
            check_registration(&doc(json!({
                "redirect_uris": ["http://localhost/cb"],
                "response_types": ["token"]
            }))),
            Err(RegistrationError::InvalidClientMetadata(_))
        ));
        assert!(matches!(
            check_registration(&doc(json!({"redirect_uris": ["http://example.com/cb"]}))),
            Err(RegistrationError::InvalidRedirectUri(_))
        ));
        let ok = check_registration(&doc(json!({"redirect_uris": ["http://localhost:3000/cb"]})))
            .unwrap();
        assert_eq!(ok.name, "localhost");
        assert_eq!(ok.grant_types, ["authorization_code"]);
    }
}
