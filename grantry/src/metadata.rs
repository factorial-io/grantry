// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Discovery documents: authorization server metadata (RFC 8414) and
//! protected resource metadata (RFC 9728). Build them from configuration
//! only, never from the request's `Host`, so no header steers the issuer.

use serde::Serialize;

/// RFC 8414 authorization server metadata. Serialises in field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).
    pub client_id_metadata_document_supported: bool,
    pub scopes_supported: Vec<String>,
}

impl AuthorizationServerMetadata {
    /// What grantry's flows support at `issuer`, with the endpoints at the
    /// given paths: the code flow with S256, refresh, public clients,
    /// metadata documents and registration. Add a grant or an auth method
    /// the host handles itself to the lists.
    pub fn new(
        issuer: &str,
        authorize_path: &str,
        token_path: &str,
        register_path: Option<&str>,
        scopes: &[String],
    ) -> Self {
        let strings = |s: &[&str]| s.iter().map(ToString::to_string).collect();
        Self {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{issuer}{authorize_path}"),
            token_endpoint: format!("{issuer}{token_path}"),
            registration_endpoint: register_path.map(|p| format!("{issuer}{p}")),
            response_types_supported: strings(&["code"]),
            grant_types_supported: strings(&["authorization_code", "refresh_token"]),
            code_challenge_methods_supported: strings(&["S256"]),
            token_endpoint_auth_methods_supported: strings(&["none"]),
            client_id_metadata_document_supported: true,
            scopes_supported: scopes.to_vec(),
        }
    }
}

/// RFC 9728 protected resource metadata. Serialises in field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
}

impl ProtectedResourceMetadata {
    /// `resource`, protected by the authorization server `issuer`; bearer
    /// tokens in the `Authorization` header only.
    pub fn new(resource: &str, issuer: &str, scopes: &[String], name: Option<&str>) -> Self {
        Self {
            resource: resource.to_string(),
            authorization_servers: vec![issuer.to_string()],
            scopes_supported: scopes.to_vec(),
            bearer_methods_supported: vec!["header".to_string()],
            resource_name: name.map(str::to_owned),
        }
    }

    /// The `WWW-Authenticate` value of a `401` (RFC 9728 §5.1), pointing at
    /// the metadata at `metadata_url`; with `error="invalid_token"` when a
    /// token was sent.
    pub fn challenge(metadata_url: &str, token_sent: bool) -> String {
        let mut value = format!("Bearer resource_metadata=\"{metadata_url}\"");
        if token_sent {
            value.push_str(", error=\"invalid_token\"");
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The documents flowdrop-rs serves today (its `well_known` and
    /// `oauth_api` tests), with its client-credentials grant added by the host.
    #[test]
    fn flowdrop_documents() {
        let base = "https://flowdrop.example";
        let scopes: Vec<String> = ["read", "write", "run", "delete", "offline_access"]
            .map(String::from)
            .to_vec();
        let mut server = AuthorizationServerMetadata::new(
            base,
            "/api/auth/authorize",
            "/api/auth/token",
            Some("/api/auth/register"),
            &scopes,
        );
        server
            .grant_types_supported
            .push("client_credentials".into());
        server
            .token_endpoint_auth_methods_supported
            .extend(["client_secret_basic".into(), "client_secret_post".into()]);
        // Key order is part of the document as served.
        assert_eq!(
            serde_json::to_string(&server).unwrap(),
            concat!(
                r#"{"issuer":"https://flowdrop.example","#,
                r#""authorization_endpoint":"https://flowdrop.example/api/auth/authorize","#,
                r#""token_endpoint":"https://flowdrop.example/api/auth/token","#,
                r#""registration_endpoint":"https://flowdrop.example/api/auth/register","#,
                r#""response_types_supported":["code"],"#,
                r#""grant_types_supported":["authorization_code","refresh_token","client_credentials"],"#,
                r#""code_challenge_methods_supported":["S256"],"#,
                r#""token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"#,
                r#""client_id_metadata_document_supported":true,"#,
                r#""scopes_supported":["read","write","run","delete","offline_access"]}"#,
            )
        );

        let resource = ProtectedResourceMetadata::new(
            "https://flowdrop.example/mcp",
            base,
            &scopes,
            Some("FlowDrop"),
        );
        assert_eq!(
            serde_json::to_value(&resource).unwrap(),
            json!({
                "resource": "https://flowdrop.example/mcp",
                "authorization_servers": [base],
                "scopes_supported": scopes,
                "bearer_methods_supported": ["header"],
                "resource_name": "FlowDrop",
            })
        );
        assert_eq!(
            ProtectedResourceMetadata::challenge(
                "https://x/.well-known/oauth-protected-resource/mcp",
                true
            ),
            "Bearer resource_metadata=\"https://x/.well-known/oauth-protected-resource/mcp\", error=\"invalid_token\""
        );
    }
}
