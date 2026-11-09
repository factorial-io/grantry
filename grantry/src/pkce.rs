// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! PKCE with S256 only (RFC 7636; OAuth 2.1 drops `plain`).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Whether `challenge` has the shape of an S256 challenge: 43 base64url
/// characters (a SHA-256 digest).
pub fn is_s256_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// RFC 7636 §4.6 with S256: `BASE64URL(SHA256(verifier)) == challenge`,
/// compared in constant time. A verifier outside RFC 7636 §4.1's shape (43–128
/// unreserved characters) never matches.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let shaped = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    shaped & bool::from(computed.as_bytes().ct_eq(challenge.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(is_s256_challenge(challenge));
        assert!(pkce_matches(verifier, challenge));
        assert!(!pkce_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl",
            challenge
        ));
        // The plain method (verifier == challenge) never passes.
        assert!(!pkce_matches(challenge, challenge));
        assert!(!pkce_matches("short", challenge));
    }
}
