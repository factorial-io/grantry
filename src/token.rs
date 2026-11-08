// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tokens: opaque codes and refresh tokens (random, stored as a hash), and
//! audience-bound JWT access tokens.
//!
//! An access token carries grantry's claims (`aud`, `exp`, `kind`, `scope`,
//! `client_id`, `grant_id`) plus the app's own, which [`crate::Subjects`]
//! returns on every issue (a user id, a tenant, a role, ...). The signing key
//! and algorithm come from the app.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// 32 random bytes, base64url: an authorization code or refresh token.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// Which opaque token the server is minting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Opaque {
    /// An authorization code.
    Code,
    /// A refresh token.
    RefreshToken,
    /// A device code (RFC 8628 §3.2).
    DeviceCode,
}

/// How the server mints its opaque tokens, for a host whose tokens have a
/// recognisable shape (a prefix secret scanners match, say). Whatever it
/// mints is stored and looked up only as [`hash_token`], so it must be
/// high-entropy; the shape is the host's.
pub trait TokenFormat: Send + Sync {
    fn mint(&self, kind: Opaque) -> String;
}

/// The default format: [`random_token`] for every kind.
#[derive(Debug, Default, Clone, Copy)]
pub struct Base64Url;

impl TokenFormat for Base64Url {
    fn mint(&self, _kind: Opaque) -> String {
        random_token()
    }
}

/// How a code or refresh token is stored and looked up: SHA-256, hex. The
/// tokens are high-entropy and single-purpose, so a slow hash buys nothing.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// The key and algorithm access tokens are signed and verified with.
///
/// Only HMAC (`HS256`, `HS384`, `HS512`) is supported: grantry signs through
/// its own HMAC-only `jsonwebtoken` crypto provider, so it does not pull in
/// the RSA and elliptic-curve crates. Any other algorithm makes [`mint`] and
/// [`verify`] fail with `InvalidAlgorithm`.
///
/// `jsonwebtoken` keeps one crypto provider per process. grantry installs
/// its provider on first use unless one is already installed or resolved.
/// A host that also uses `jsonwebtoken` 11 with RSA, EC or EdDSA keys must
/// install a full provider at startup, before grantry's first token, e.g.
/// `jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default()`
/// (which also covers HMAC).
#[derive(Clone)]
pub struct Signer {
    pub algorithm: Algorithm,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Signer {
    /// An HMAC signer over the raw bytes of `secret`, for a host whose secret
    /// is configured as a plain string rather than base64.
    pub fn hmac(algorithm: Algorithm, secret: &[u8]) -> Self {
        Self {
            algorithm,
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }

    /// An HMAC signer over a base64-encoded secret.
    pub fn hmac_base64(
        algorithm: Algorithm,
        secret: &str,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        Ok(Self {
            algorithm,
            encoding: EncodingKey::from_base64_secret(secret)?,
            decoding: DecodingKey::from_base64_secret(secret)?,
        })
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// What grantry puts into an access token.
#[derive(Debug, Clone)]
pub struct AccessClaims<'a> {
    /// `aud`: the protected resource.
    pub resource: &'a str,
    /// `kind`: tells this token apart from the app's other tokens.
    pub kind: &'a str,
    pub scope: &'a str,
    pub client_id: &'a str,
    pub grant_id: &'a str,
}

/// Sign an access token valid for `lifetime_secs` from `now`. `extra` are the
/// app's claims; grantry's own claims win over an `extra` claim of the same
/// name.
pub fn mint(
    signer: &Signer,
    now: DateTime<Utc>,
    lifetime_secs: u64,
    claims: &AccessClaims<'_>,
    extra: Map<String, Value>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = u64::try_from(now.timestamp())
        .unwrap_or(0)
        .saturating_add(lifetime_secs);
    let mut all = extra;
    all.insert("exp".into(), json!(exp));
    all.insert("kind".into(), json!(claims.kind));
    all.insert("scope".into(), json!(claims.scope));
    all.insert("client_id".into(), json!(claims.client_id));
    all.insert("grant_id".into(), json!(claims.grant_id));
    all.insert("aud".into(), json!(claims.resource));
    hmac_provider::install();
    jsonwebtoken::encode(&Header::new(signer.algorithm), &all, &signer.encoding)
}

/// Why a token does not verify.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("token does not verify: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("token is not of kind `{0}`")]
    Kind(String),
    /// The token verified, but its claims are not the shape asked for
    /// ([`verify_as`]).
    #[error("token claims do not match: {0}")]
    Claims(#[from] serde_json::Error),
}

/// Verify `token`'s signature, expiry (no leeway), audience (`resource`,
/// required) and `kind`; return all its claims. Whether the grant is still
/// live is the caller's question.
pub fn verify(
    signer: &Signer,
    token: &str,
    resource: &str,
    kind: &str,
) -> Result<Map<String, Value>, VerifyError> {
    let mut validation = Validation::new(signer.algorithm);
    validation.leeway = 0;
    validation.set_audience(&[resource]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    hmac_provider::install();
    let claims =
        jsonwebtoken::decode::<Map<String, Value>>(token, &signer.decoding, &validation)?.claims;
    if claims.get("kind").and_then(Value::as_str) != Some(kind) {
        return Err(VerifyError::Kind(kind.to_string()));
    }
    Ok(claims)
}

/// [`verify`], then the claims as the host's own type `T`. grantry's claims
/// sit beside the host's in one object, so `T` reads the ones it names and
/// ignores the rest unless it denies unknown fields.
pub fn verify_as<T: serde::de::DeserializeOwned>(
    signer: &Signer,
    token: &str,
    resource: &str,
    kind: &str,
) -> Result<T, VerifyError> {
    let claims = verify(signer, token, resource, kind)?;
    Ok(serde_json::from_value(Value::Object(claims))?)
}

/// HS256/384/512 for `jsonwebtoken` on `hmac` + `sha2`, in place of its
/// `rust_crypto` feature, which also brings `rsa` and the elliptic-curve
/// crates (and their advisories) that grantry never uses (#33).
mod hmac_provider {
    use hmac::{Hmac, Mac};
    use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
    use jsonwebtoken::errors::{ErrorKind, Result};
    use jsonwebtoken::signature::{self, Signer, Verifier};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
    use sha2::{Sha256, Sha384, Sha512};

    static PROVIDER: CryptoProvider = CryptoProvider {
        signer_factory,
        verifier_factory,
        // ponytail: no JWK support; grantry never builds keys from JWKs.
        key_utils: KeyUtils::new_unimplemented(),
    };

    /// Make grantry's provider the process default, unless the host already
    /// installed one or `jsonwebtoken` already resolved its own.
    pub(super) fn install() {
        let _ = PROVIDER.install_default();
    }

    enum Key {
        Hs256(Hmac<Sha256>),
        Hs384(Hmac<Sha384>),
        Hs512(Hmac<Sha512>),
    }

    impl Key {
        fn new(algorithm: Algorithm, secret: &[u8]) -> Result<Self> {
            let invalid = |_| ErrorKind::InvalidKeyFormat;
            Ok(match algorithm {
                Algorithm::HS256 => Self::Hs256(Mac::new_from_slice(secret).map_err(invalid)?),
                Algorithm::HS384 => Self::Hs384(Mac::new_from_slice(secret).map_err(invalid)?),
                Algorithm::HS512 => Self::Hs512(Mac::new_from_slice(secret).map_err(invalid)?),
                _ => return Err(ErrorKind::InvalidAlgorithm.into()),
            })
        }

        fn algorithm(&self) -> Algorithm {
            match self {
                Self::Hs256(_) => Algorithm::HS256,
                Self::Hs384(_) => Algorithm::HS384,
                Self::Hs512(_) => Algorithm::HS512,
            }
        }

        fn mac(&self, msg: &[u8]) -> Vec<u8> {
            fn run<M: Mac + Clone>(mac: &M, msg: &[u8]) -> Vec<u8> {
                let mut mac = mac.clone();
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }
            match self {
                Self::Hs256(m) => run(m, msg),
                Self::Hs384(m) => run(m, msg),
                Self::Hs512(m) => run(m, msg),
            }
        }
    }

    impl Signer<Vec<u8>> for Key {
        fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
            Ok(self.mac(msg))
        }
    }

    impl Verifier<Vec<u8>> for Key {
        fn verify(&self, msg: &[u8], sig: &Vec<u8>) -> std::result::Result<(), signature::Error> {
            fn run<M: Mac + Clone>(mac: &M, msg: &[u8], sig: &[u8]) -> bool {
                let mut mac = mac.clone();
                mac.update(msg);
                mac.verify_slice(sig).is_ok() // constant time
            }
            let ok = match self {
                Self::Hs256(m) => run(m, msg, sig),
                Self::Hs384(m) => run(m, msg, sig),
                Self::Hs512(m) => run(m, msg, sig),
            };
            ok.then_some(()).ok_or_else(signature::Error::new)
        }
    }

    impl JwtSigner for Key {
        fn algorithm(&self) -> Algorithm {
            Key::algorithm(self)
        }
    }

    impl JwtVerifier for Key {
        fn algorithm(&self) -> Algorithm {
            Key::algorithm(self)
        }
    }

    fn signer_factory(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
        Ok(Box::new(Key::new(*algorithm, key.as_bytes())?))
    }

    fn verifier_factory(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
        Ok(Box::new(Key::new(*algorithm, key.try_get_as_bytes()?)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "dGVzdC1zZWNyZXQta2V5LWZvci1mbG93ZHJvcC10ZXN0cw==";
    const RESOURCE: &str = "https://flowdrop.example/mcp";

    fn signer() -> Signer {
        Signer::hmac_base64(Algorithm::HS512, SECRET).unwrap()
    }

    fn claims() -> AccessClaims<'static> {
        AccessClaims {
            resource: RESOURCE,
            kind: "mcp",
            scope: "read run offline_access",
            client_id: "client-1",
            grant_id: "6d1c4a5e-0000-4000-8000-000000000001",
        }
    }

    fn segment(token: &str, n: usize) -> Value {
        let part = token.split('.').nth(n).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    /// The claims flowdrop-rs mints today (its `oauth_token_golden` test),
    /// from fixed inputs.
    #[test]
    fn golden_claims() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let extra = json!({
            "pid": "5f0e8a52-0000-4000-8000-000000000002",
            "tenant_id": "0b7c1d2e-0000-4000-8000-000000000003",
            "role": "user",
            "tv": 0,
        });
        let token = mint(
            &signer(),
            now,
            900,
            &claims(),
            extra.as_object().unwrap().clone(),
        )
        .unwrap();
        assert_eq!(segment(&token, 0), json!({"typ": "JWT", "alg": "HS512"}));
        assert_eq!(
            segment(&token, 1),
            json!({
                "pid": "5f0e8a52-0000-4000-8000-000000000002",
                "exp": 1_800_000_900,
                "tenant_id": "0b7c1d2e-0000-4000-8000-000000000003",
                "role": "user",
                "kind": "mcp",
                "scope": "read run offline_access",
                "client_id": "client-1",
                "grant_id": "6d1c4a5e-0000-4000-8000-000000000001",
                "aud": RESOURCE,
                "tv": 0,
            })
        );
    }

    #[test]
    fn grantry_claims_win_over_extra() {
        let extra = json!({"aud": "https://evil.example", "kind": "session"});
        let token = mint(
            &signer(),
            Utc::now(),
            60,
            &claims(),
            extra.as_object().unwrap().clone(),
        )
        .unwrap();
        let verified = verify(&signer(), &token, RESOURCE, "mcp").unwrap();
        assert_eq!(verified["aud"], RESOURCE);
    }

    #[test]
    fn only_a_token_of_this_kind_for_this_resource_verifies() {
        let ok = mint(&signer(), Utc::now(), 60, &claims(), Map::new()).unwrap();
        assert!(verify(&signer(), &ok, RESOURCE, "mcp").is_ok());
        assert!(matches!(
            verify(&signer(), &ok, "https://other.example/mcp", "mcp"),
            Err(VerifyError::Jwt(_))
        ));
        assert!(matches!(
            verify(&signer(), &ok, RESOURCE, "session"),
            Err(VerifyError::Kind(_))
        ));
        let other = Signer::hmac_base64(
            Algorithm::HS512,
            "YW5vdGhlci13cy1zZWNyZXQtZm9yLXRoZXNlLXRlc3Rz",
        )
        .unwrap();
        assert!(verify(&other, &ok, RESOURCE, "mcp").is_err());

        let expired = mint(
            &signer(),
            Utc::now() - chrono::Duration::seconds(120),
            60,
            &claims(),
            Map::new(),
        )
        .unwrap();
        assert!(matches!(
            verify(&signer(), &expired, RESOURCE, "mcp"),
            Err(VerifyError::Jwt(_))
        ));
    }

    /// A host's own claims (here Fons's session payload) come back typed,
    /// beside grantry's, from a signer over a raw secret.
    #[test]
    fn host_claims_verify_as_the_hosts_type() {
        #[derive(Debug, PartialEq, serde::Deserialize)]
        struct HostClaims {
            sub: String,
            workspace_id: String,
            role: String,
            tv: i32,
            exp: u64,
            sid: String,
        }
        let raw = Signer::hmac(Algorithm::HS256, b"a-plain-string-secret");
        let extra = json!({
            "sub": "user-1",
            "workspace_id": "ws-1",
            "role": "admin",
            "tv": 3,
            "sid": "6d1c4a5e-0000-4000-8000-000000000001",
        });
        let fresh = mint(
            &raw,
            Utc::now(),
            900,
            &claims(),
            extra.as_object().unwrap().clone(),
        )
        .unwrap();
        assert_eq!(segment(&fresh, 0), json!({"typ": "JWT", "alg": "HS256"}));
        let typed: HostClaims = verify_as(&raw, &fresh, RESOURCE, "mcp").unwrap();
        assert_eq!(typed.sub, "user-1");
        assert_eq!(typed.workspace_id, "ws-1");
        assert_eq!(typed.role, "admin");
        assert_eq!(typed.tv, 3);
        assert_eq!(typed.sid, "6d1c4a5e-0000-4000-8000-000000000001");

        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Missing {
            person_id: String,
        }
        assert!(matches!(
            verify_as::<Missing>(&raw, &fresh, RESOURCE, "mcp"),
            Err(VerifyError::Claims(_))
        ));
        // Same bytes, base64-encoded, is the same key.
        let b64 = Signer::hmac_base64(
            Algorithm::HS256,
            &base64::engine::general_purpose::STANDARD.encode(b"a-plain-string-secret"),
        )
        .unwrap();
        assert!(verify(&b64, &fresh, RESOURCE, "mcp").is_ok());
    }

    /// The exact bytes an HS256 token had before grantry brought its own
    /// HMAC provider (#33): tokens already out there must keep verifying.
    #[test]
    fn hs256_token_bytes_are_stable() {
        const KNOWN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2Zsb3dkcm9wLmV4YW1wbGUvbWNwIiwiY2xpZW50X2lkIjoiY2xpZW50LTEiLCJleHAiOjQwMDAwMDA5MDAsImdyYW50X2lkIjoiNmQxYzRhNWUtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxIiwia2luZCI6Im1jcCIsInNjb3BlIjoicmVhZCBydW4gb2ZmbGluZV9hY2Nlc3MifQ.XDdCjL5b4ASk17C4toRVn1O76zcTAEj6LYaOdTtRbXU";
        let raw = Signer::hmac(Algorithm::HS256, b"a-plain-string-secret");
        // Far enough ahead that the token has not expired when the test runs.
        let now = DateTime::from_timestamp(4_000_000_000, 0).unwrap();
        let token = mint(&raw, now, 900, &claims(), Map::new()).unwrap();
        assert_eq!(token, KNOWN);
        assert!(verify(&raw, KNOWN, RESOURCE, "mcp").is_ok());
    }

    /// grantry's provider signs HMAC only; anything else is an error, not a
    /// panic.
    #[test]
    fn non_hmac_algorithms_fail_cleanly() {
        for alg in [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA] {
            let s = Signer::hmac(alg, b"a-plain-string-secret");
            assert!(mint(&s, Utc::now(), 60, &claims(), Map::new()).is_err());
            let hs = mint(&signer(), Utc::now(), 60, &claims(), Map::new()).unwrap();
            assert!(verify(&s, &hs, RESOURCE, "mcp").is_err());
        }
    }

    #[test]
    fn opaque_tokens_are_random_and_hashed() {
        let (a, b) = (random_token(), random_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert_eq!(hash_token(&a).len(), 64);
        assert_eq!(hash_token(&a), hash_token(&a));
    }
}
