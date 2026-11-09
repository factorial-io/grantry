// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Checks of the [`OAuthStore`] contract, for store implementations to run
//! in their own tests (`conformance` feature). Each function panics on the
//! first broken rule.
//!
//! The checks need no clock control: they reach expiry by passing a
//! negative TTL or lifetime, so the row is stored already expired. They write
//! fresh random ids and hashes, so they can share a database with other data,
//! but they leave their rows behind.
//!
//! The *atomic* methods are raced by running two calls concurrently on one
//! task (`tokio::join!`), which interleaves them at every `.await`. That
//! catches a check-then-write split across round trips, not a race inside a
//! single backend call.
//!
//! ```ignore
//! #[tokio::test]
//! async fn conforms() {
//!     let store = MyStore::connect(...).await?;
//!     grantry::conformance::check_core(&store, "alice".into(), "bob".into()).await;
//!     grantry::conformance::check_issued_grants(&store, "alice".into()).await;
//!     grantry::conformance::check_devices(&store, "alice".into()).await;
//! }
//! ```

use std::fmt::Debug;

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::device::DeviceStatus;
use crate::store::{NewDevice, NewGrant, NewPending, OAuthStore};

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

fn pending(client_id: &str, ttl: Duration) -> NewPending {
    NewPending {
        client_id: client_id.into(),
        client_name: "Conformance".into(),
        loopback_only: false,
        redirect_uri: "https://client.example/cb".into(),
        scope: "read offline_access".into(),
        state: Some("st".into()),
        code_challenge: "challenge".into(),
        resource: "https://app.example/mcp".into(),
        ttl,
    }
}

fn new_grant<S>(subject: S, lifetime: Duration) -> NewGrant<S> {
    NewGrant {
        subject,
        client_id: unique("client"),
        client_name: "Conformance".into(),
        scope: "read".into(),
        lifetime,
    }
}

fn device(user_code: &str, ttl: Duration) -> NewDevice {
    NewDevice {
        client_id: "conformance-cli".into(),
        client_name: "Conformance CLI".into(),
        scope: "read".into(),
        device_code_hash: unique("device"),
        user_code: user_code.into(),
        interval_seconds: 5,
        ttl,
    }
}

/// A user code no other check (or earlier run) uses: `XXXX-XXXX` from the
/// device alphabet.
fn user_code() -> String {
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let bytes = Uuid::new_v4().into_bytes();
    let mut code: String = bytes[..8]
        .iter()
        .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
        .collect();
    code.insert(4, '-');
    code
}

fn exactly_one(results: [bool; 2], what: &str) {
    assert_eq!(
        results.iter().filter(|ok| **ok).count(),
        1,
        "{what}: two concurrent calls must have exactly one winner, got {results:?}"
    );
}

/// Clients, documents, pending authorizations, grants with codes,
/// revocation and refresh tokens. `alice` and `bob` must differ.
pub async fn check_core<St>(store: &St, alice: St::Subject, bob: St::Subject)
where
    St: OAuthStore,
    St::Subject: Debug,
{
    assert_ne!(alice, bob, "check_core needs two different subjects");
    let now = Utc::now();

    // Clients.
    let client_id = unique("client");
    let uris = vec!["https://client.example/cb".to_string()];
    let client = store
        .insert_client(client_id.clone(), "Conformance".into(), &uris)
        .await
        .expect("insert_client");
    assert_eq!(client.id, client_id);
    let used = store
        .use_client(&client_id)
        .await
        .expect("use_client")
        .expect("a registered client is found");
    assert_eq!(
        (used.id.as_str(), used.name.as_str()),
        (client_id.as_str(), "Conformance")
    );
    assert_eq!(used.redirect_uris, uris);
    assert!(
        store
            .use_client(&unique("unknown"))
            .await
            .expect("use_client")
            .is_none()
    );

    // Metadata documents.
    let url = format!("https://client.example/{}", Uuid::new_v4());
    let doc = json!({"client_id": url, "redirect_uris": ["https://client.example/cb"]});
    assert!(store.cached_document(&url).await.expect("cached").is_none());
    store
        .store_document(&url, doc.clone(), now + Duration::hours(1))
        .await
        .expect("store_document");
    assert_eq!(
        store.cached_document(&url).await.expect("cached"),
        Some(doc.clone())
    );
    store
        .store_document(&url, doc, now - Duration::seconds(1))
        .await
        .expect("store_document");
    assert!(
        store.cached_document(&url).await.expect("cached").is_none(),
        "an expired document is not served"
    );

    // Pending authorizations: binding and single use.
    let p = store
        .insert_pending(pending(&client_id, Duration::minutes(10)))
        .await
        .expect("insert_pending");
    assert_eq!(p.subject, None);
    assert_eq!(p.expires_at - p.created_at, Duration::minutes(10));
    let claimed = store
        .claim_pending(p.id, &alice)
        .await
        .expect("claim")
        .expect("the first claim binds");
    assert_eq!(claimed.subject.as_ref(), Some(&alice));
    assert_eq!(
        (claimed.client_id.as_str(), claimed.state.as_deref()),
        (client_id.as_str(), Some("st"))
    );
    assert!(
        store
            .claim_pending(p.id, &bob)
            .await
            .expect("claim")
            .is_none(),
        "a bound request is invisible to another subject"
    );
    assert!(
        store
            .claim_pending(p.id, &alice)
            .await
            .expect("claim")
            .is_some()
    );
    assert!(
        store
            .take_pending(p.id, &bob)
            .await
            .expect("take")
            .is_none()
    );
    let taken = store
        .take_pending(p.id, &alice)
        .await
        .expect("take")
        .expect("the binder takes it");
    assert_eq!(taken.id, p.id);
    assert!(
        store
            .take_pending(p.id, &alice)
            .await
            .expect("take")
            .is_none(),
        "single use"
    );
    assert!(
        store
            .claim_pending(Uuid::new_v4(), &alice)
            .await
            .expect("claim")
            .is_none()
    );

    // An unbound request can be taken directly, once, under a race.
    let p = store
        .insert_pending(pending(&client_id, Duration::minutes(10)))
        .await
        .expect("insert_pending");
    let (a, b) = tokio::join!(
        store.take_pending(p.id, &alice),
        store.take_pending(p.id, &alice)
    );
    exactly_one(
        [a.expect("take").is_some(), b.expect("take").is_some()],
        "take_pending",
    );

    // Two subjects racing to bind: one wins.
    let p = store
        .insert_pending(pending(&client_id, Duration::minutes(10)))
        .await
        .expect("insert_pending");
    let (a, b) = tokio::join!(
        store.claim_pending(p.id, &alice),
        store.claim_pending(p.id, &bob)
    );
    exactly_one(
        [a.expect("claim").is_some(), b.expect("claim").is_some()],
        "claim_pending",
    );

    // Expired requests are neither claimed nor taken.
    let expired = store
        .insert_pending(pending(&client_id, Duration::seconds(-1)))
        .await
        .expect("insert_pending");
    assert!(
        store
            .claim_pending(expired.id, &alice)
            .await
            .expect("claim")
            .is_none()
    );
    assert!(
        store
            .take_pending(expired.id, &alice)
            .await
            .expect("take")
            .is_none()
    );

    // A grant and its code.
    let p = store
        .insert_pending(pending(&client_id, Duration::minutes(10)))
        .await
        .expect("insert_pending");
    let approved = store
        .take_pending(p.id, &alice)
        .await
        .expect("take")
        .expect("taken");
    let code_hash = unique("code");
    let grant = store
        .create_grant_with_code(
            &approved,
            &alice,
            Duration::days(90),
            code_hash.clone(),
            Duration::minutes(1),
        )
        .await
        .expect("create_grant_with_code");
    assert_eq!(grant.subject, alice);
    assert_eq!(
        (grant.client_id.as_str(), grant.scope.as_str()),
        (client_id.as_str(), "read offline_access")
    );
    assert_eq!(grant.redirect_uri, approved.redirect_uri);
    assert!(grant.is_active(Utc::now()));
    let found = store
        .find_grant(grant.id)
        .await
        .expect("find_grant")
        .expect("the grant is stored");
    assert_eq!(
        (found.id, &found.subject, found.revoked_at),
        (grant.id, &alice, None)
    );
    assert!(
        store
            .find_grant(Uuid::new_v4())
            .await
            .expect("find_grant")
            .is_none()
    );

    let code = store
        .find_code(&code_hash)
        .await
        .expect("find_code")
        .expect("the code is stored");
    assert_eq!(code.grant_id, grant.id);
    assert_eq!(code.code_challenge, approved.code_challenge);
    assert_eq!(code.resource, approved.resource);
    assert_eq!(code.redirect_uri, approved.redirect_uri);
    assert!(code.expires_at > Utc::now() && code.used_at.is_none());
    assert!(
        store
            .find_code(&unique("code"))
            .await
            .expect("find_code")
            .is_none()
    );
    let (a, b) = tokio::join!(store.use_code(code.id), store.use_code(code.id));
    exactly_one([a.expect("use_code"), b.expect("use_code")], "use_code");
    assert!(!store.use_code(code.id).await.expect("use_code"));
    let used = store
        .find_code(&code_hash)
        .await
        .expect("find_code")
        .expect("a used code is still found");
    assert!(used.used_at.is_some());

    // Refresh tokens.
    let first = unique("refresh");
    store
        .insert_refresh_token(&grant, first.clone())
        .await
        .expect("insert_refresh_token");
    let token = store
        .find_refresh_token(&first)
        .await
        .expect("find_refresh_token")
        .expect("stored");
    assert_eq!((token.grant_id, token.rotated_at), (grant.id, None));
    let (second, third) = (unique("refresh"), unique("refresh"));
    let (a, b) = tokio::join!(
        store.rotate_refresh_token(&token, &grant, second.clone()),
        store.rotate_refresh_token(&token, &grant, third.clone()),
    );
    let (a, b) = (a.expect("rotate"), b.expect("rotate"));
    exactly_one([a, b], "rotate_refresh_token");
    let successor = if a { &second } else { &third };
    let loser = if a { &third } else { &second };
    assert!(
        store
            .find_refresh_token(loser)
            .await
            .expect("find")
            .is_none(),
        "a lost rotation inserts nothing"
    );
    let next = store
        .find_refresh_token(successor)
        .await
        .expect("find")
        .expect("the successor is stored");
    assert_eq!((next.grant_id, next.rotated_at), (grant.id, None));
    assert_ne!(next.id, token.id);
    let old = store
        .find_refresh_token(&first)
        .await
        .expect("find")
        .expect("a rotated token is still found");
    assert!(old.rotated_at.is_some());
    let refreshed = store
        .find_grant(grant.id)
        .await
        .expect("find_grant")
        .expect("stored");
    assert!(refreshed.last_refreshed_at.is_some());

    // Revocation, once.
    let (a, b) = tokio::join!(
        store.revoke_grant(grant.id, "conformance"),
        store.revoke_grant(grant.id, "conformance"),
    );
    exactly_one([a.expect("revoke"), b.expect("revoke")], "revoke_grant");
    let revoked = store
        .find_grant(grant.id)
        .await
        .expect("find_grant")
        .expect("a revoked grant is kept");
    assert!(revoked.revoked_at.is_some());
    assert_eq!(revoked.revoke_reason.as_deref(), Some("conformance"));
    assert!(!revoked.is_active(Utc::now()));
    assert!(
        !store
            .revoke_grant(Uuid::new_v4(), "conformance")
            .await
            .expect("revoke")
    );
    assert!(
        store
            .find_refresh_token(&first)
            .await
            .expect("find")
            .is_some(),
        "refresh tokens of a revoked grant stay, for the reuse check"
    );

    store.sweep().await.expect("sweep");
}

/// [`OAuthStore::create_grant`], for stores whose host calls
/// [`crate::Server::issue_grant`].
pub async fn check_issued_grants<St>(store: &St, subject: St::Subject)
where
    St: OAuthStore,
    St::Subject: Debug,
{
    let new = new_grant(subject.clone(), Duration::days(30));
    let client_id = new.client_id.clone();
    let grant = store.create_grant(new).await.expect("create_grant");
    assert_eq!(grant.subject, subject);
    assert_eq!(
        (
            grant.client_id.as_str(),
            grant.scope.as_str(),
            grant.redirect_uri.as_str()
        ),
        (client_id.as_str(), "read", "")
    );
    assert_eq!(grant.expires_at - grant.created_at, Duration::days(30));
    let found = store
        .find_grant(grant.id)
        .await
        .expect("find_grant")
        .expect("stored");
    assert_eq!((found.id, found.subject), (grant.id, subject));

    let token = unique("refresh");
    store
        .insert_refresh_token(&grant, token.clone())
        .await
        .expect("insert_refresh_token");
    assert!(
        store
            .find_refresh_token(&token)
            .await
            .expect("find")
            .is_some()
    );
}

/// The device authorization grant (RFC 8628), for stores whose host offers
/// device login.
pub async fn check_devices<St>(store: &St, subject: St::Subject)
where
    St: OAuthStore,
    St::Subject: Debug,
{
    let code = user_code();
    let new = device(&code, Duration::minutes(10));
    let hash = new.device_code_hash.clone();
    let d = store
        .insert_device(new)
        .await
        .expect("insert_device")
        .expect("a free user code is taken");
    assert_eq!(d.status, DeviceStatus::Pending);
    assert_eq!(
        (d.user_code.as_str(), d.interval_seconds, d.subject.as_ref()),
        (code.as_str(), 5, None)
    );
    assert_eq!(d.expires_at - d.created_at, Duration::minutes(10));
    assert!(
        store
            .insert_device(device(&code, Duration::minutes(10)))
            .await
            .expect("insert_device")
            .is_none(),
        "a live user code is not reused"
    );

    // Two inserts racing for a fresh user code: one wins.
    let raced = user_code();
    let (a, b) = tokio::join!(
        store.insert_device(device(&raced, Duration::minutes(10))),
        store.insert_device(device(&raced, Duration::minutes(10))),
    );
    exactly_one(
        [
            a.expect("insert_device").is_some(),
            b.expect("insert_device").is_some(),
        ],
        "insert_device",
    );

    let found = store
        .find_device(&hash)
        .await
        .expect("find_device")
        .expect("stored");
    assert_eq!(found.id, d.id);
    assert!(
        store
            .find_device(&unique("device"))
            .await
            .expect("find_device")
            .is_none()
    );
    let by_code = store
        .device_by_user_code(&code, &subject)
        .await
        .expect("device_by_user_code")
        .expect("found by user code");
    assert_eq!(by_code.id, d.id);

    // Nothing to redeem before approval.
    assert!(
        store
            .redeem_device(d.id, new_grant(subject.clone(), Duration::days(1)))
            .await
            .expect("redeem")
            .is_none()
    );

    let (a, b) = tokio::join!(
        store.decide_device(d.id, &subject, true),
        store.decide_device(d.id, &subject, false),
    );
    let approved = a.expect("decide");
    exactly_one([approved, b.expect("decide")], "decide_device");
    let decided = store
        .find_device(&hash)
        .await
        .expect("find_device")
        .expect("stored");
    assert_eq!(decided.subject.as_ref(), Some(&subject));
    assert!(
        !store
            .decide_device(d.id, &subject, true)
            .await
            .expect("decide")
    );

    let at = Utc::now();
    store.record_poll(d.id, at, 10).await.expect("record_poll");
    let polled = store
        .find_device(&hash)
        .await
        .expect("find_device")
        .expect("stored");
    assert_eq!(polled.interval_seconds, 10);
    let last = polled.last_polled_at.expect("the poll is recorded");
    assert!(
        last <= at && at - last < Duration::seconds(1),
        "a poll time is kept, truncated at most to whole seconds, never rounded up"
    );

    if approved {
        assert_eq!(decided.status, DeviceStatus::Approved);
        let (a, b) = tokio::join!(
            store.redeem_device(d.id, new_grant(subject.clone(), Duration::days(1))),
            store.redeem_device(d.id, new_grant(subject.clone(), Duration::days(1))),
        );
        let (a, b) = (a.expect("redeem"), b.expect("redeem"));
        exactly_one([a.is_some(), b.is_some()], "redeem_device");
        let grant = a.or(b).expect("one redemption");
        assert_eq!(grant.subject, subject);
        assert!(
            store
                .find_grant(grant.id)
                .await
                .expect("find_grant")
                .is_some()
        );
        let redeemed = store
            .find_device(&hash)
            .await
            .expect("find_device")
            .expect("stored");
        assert_eq!(redeemed.status, DeviceStatus::Redeemed);
    } else {
        assert_eq!(decided.status, DeviceStatus::Denied);
        assert!(
            store
                .redeem_device(d.id, new_grant(subject.clone(), Duration::days(1)))
                .await
                .expect("redeem")
                .is_none()
        );
    }

    // An expired authorization frees its user code and is not decided.
    let stale = user_code();
    let expired = store
        .insert_device(device(&stale, Duration::seconds(-1)))
        .await
        .expect("insert_device")
        .expect("inserted");
    assert!(
        !store
            .decide_device(expired.id, &subject, true)
            .await
            .expect("decide")
    );
    assert!(
        store
            .device_by_user_code(&stale, &subject)
            .await
            .expect("device_by_user_code")
            .is_none()
    );
    assert!(
        store
            .insert_device(device(&stale, Duration::minutes(10)))
            .await
            .expect("insert_device")
            .is_some(),
        "an expired authorization's user code is free again"
    );
}
