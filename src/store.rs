// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The ports the host implements: [`OAuthStore`], [`Subjects`] and
//! [`Events`], and the rows they exchange.
//!
//! A *subject* is whoever a grant is for, in the host's terms: a user id, or a
//! user in a tenant. grantry only stores and compares it.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::device::Device;

/// A storage, lookup or other host failure. Never taken for a refusal: the
/// flows pass it up untouched.
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// A dynamically registered public client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredClient {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// A validated authorization request, before login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPending {
    pub client_id: String,
    pub client_name: String,
    /// Every registered redirect URI is loopback: any local program can
    /// receive the codes. Consent pages warn about it.
    pub loopback_only: bool,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub resource: String,
    pub ttl: Duration,
}

/// A stored authorization request. `subject` is set by the first
/// [`OAuthStore::claim_pending`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending<S> {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub loopback_only: bool,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub resource: String,
    pub subject: Option<S>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A grant: one approved connection of one client for one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant<S> {
    pub id: Uuid,
    pub subject: S,
    pub client_id: String,
    /// The name the subject consented to.
    pub client_name: String,
    pub redirect_uri: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    /// The absolute lifetime: no refresh extends it.
    pub expires_at: DateTime<Utc>,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
}

impl<S> Grant<S> {
    /// Not revoked and not past its absolute lifetime.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A grant the host creates for a subject it has already authenticated
/// ([`crate::Server::issue_grant`]): no authorization request, no code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant<S> {
    pub subject: S,
    pub client_id: String,
    pub client_name: String,
    /// The canonical scope string.
    pub scope: String,
    /// The absolute lifetime.
    pub lifetime: Duration,
}

/// A device authorization to store ([`crate::Server::start_device`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice {
    pub client_id: String,
    pub client_name: String,
    /// The canonical scope string.
    pub scope: String,
    pub device_code_hash: String,
    /// `XXXX-XXXX`.
    pub user_code: String,
    pub interval_seconds: u32,
    pub ttl: Duration,
}

/// An authorization code, stored by its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub id: Uuid,
    pub grant_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub resource: String,
    pub code_challenge: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

/// A refresh token, stored by its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub id: Uuid,
    pub grant_id: Uuid,
    pub issued_at: DateTime<Utc>,
    /// Set once a successor was issued; presenting it again is reuse.
    pub rotated_at: Option<DateTime<Utc>>,
}

/// Storage of the authorization server. Secrets (codes, refresh tokens)
/// reach it only as hashes ([`crate::token::hash_token`]).
///
/// Every method that says *atomic* is a race guard the flows rely on: two
/// concurrent calls must never both succeed.
///
/// Timestamps may be kept at any precision the backend offers (the
/// [`crate::memory::MemoryStore`] keeps nanoseconds, a SQL column often
/// microseconds or milliseconds). grantry never compares a row a write
/// returned with the same row read back later; it compares ids and checks
/// timestamps against the clock. Any precision down to whole seconds is fine
/// if the backend truncates: that only shortens a lifetime or interval by less
/// than one unit. Do not round up: a `last_polled_at` rounded up by half a
/// second makes a device client that polls exactly on its interval look too
/// fast and get `slow_down`. A store should set `created_at` and
/// `expires_at` of a row from the same `now`, because the server derives the
/// device `expires_in` from `expires_at - created_at`.
#[async_trait]
pub trait OAuthStore: Send + Sync {
    /// Whom a grant is for.
    type Subject: Clone + PartialEq + Send + Sync + 'static;

    /// Store a dynamically registered public client with id `id`.
    async fn insert_client(
        &self,
        id: String,
        name: String,
        redirect_uris: &[String],
    ) -> Result<RegisteredClient, BackendError>;

    /// The registered client `id`.
    async fn use_client(&self, id: &str) -> Result<Option<RegisteredClient>, BackendError>;

    /// The cached metadata document for `url`, if it has not expired.
    async fn cached_document(&self, url: &str) -> Result<Option<Value>, BackendError>;

    /// Insert or replace the cached document for `url`.
    async fn store_document(
        &self,
        url: &str,
        document: Value,
        expires_at: DateTime<Utc>,
    ) -> Result<(), BackendError>;

    /// Store a validated request; the store assigns the id and sets
    /// `expires_at = now + ttl`.
    async fn insert_pending(&self, new: NewPending)
    -> Result<Pending<Self::Subject>, BackendError>;

    /// The unexpired pending authorization `id` as seen by `subject`.
    ///
    /// *Atomic:* the first call binds an unbound request to its subject; from
    /// then on it is `None` for every other subject, exactly as for an unknown
    /// id. An expired request is `None` and is not bound.
    async fn claim_pending(
        &self,
        id: Uuid,
        subject: &Self::Subject,
    ) -> Result<Option<Pending<Self::Subject>>, BackendError>;

    /// Claim and delete the pending authorization in one step.
    ///
    /// *Atomic:* single use for approve and deny alike. `None` when unknown,
    /// expired, already taken or bound to another subject. An expired request
    /// is not bound.
    async fn take_pending(
        &self,
        id: Uuid,
        subject: &Self::Subject,
    ) -> Result<Option<Pending<Self::Subject>>, BackendError>;

    /// Create the grant for `approved` (its scope is the approved one) and
    /// its authorization code. *Atomic:* both or neither.
    async fn create_grant_with_code(
        &self,
        approved: &Pending<Self::Subject>,
        subject: &Self::Subject,
        lifetime: Duration,
        code_hash: String,
        code_ttl: Duration,
    ) -> Result<Grant<Self::Subject>, BackendError>;

    /// The code with hash `code_hash`, used or not.
    async fn find_code(&self, code_hash: &str) -> Result<Option<Code>, BackendError>;

    /// Mark code `id` used. *Atomic:* `false` when it already was.
    async fn use_code(&self, id: Uuid) -> Result<bool, BackendError>;

    async fn find_grant(&self, id: Uuid) -> Result<Option<Grant<Self::Subject>>, BackendError>;

    /// Create a grant the host issued directly ([`crate::Server::issue_grant`]),
    /// with no redirect URI. A store whose host never does that may leave the
    /// default, which refuses.
    async fn create_grant(
        &self,
        new: NewGrant<Self::Subject>,
    ) -> Result<Grant<Self::Subject>, BackendError> {
        let _ = new;
        Err("this store does not create grants directly".into())
    }

    // --- Device authorization grant (RFC 8628) --------------------------------
    //
    // A store whose host offers no device login may leave these defaults,
    // which refuse.

    /// Store a pending device authorization; the store assigns the id and
    /// sets `expires_at = now + ttl`. `None` when `user_code` is already taken
    /// by a live authorization, so the server draws another. *Live* means
    /// unexpired, whatever its status: a denied or redeemed code stays taken
    /// until it expires.
    ///
    /// *Atomic*: checking that the code is free and inserting are one
    /// operation, so two calls with the same code never both return `Some`.
    /// A plain `UNIQUE(user_code)` is too strict while expired rows remain
    /// unswept, and a partial unique index cannot express "unexpired" (its
    /// predicate cannot use the clock). Serialize the check and the insert
    /// instead: a conditional `INSERT ... SELECT ... WHERE NOT EXISTS
    /// (unexpired row with that code)` in a serializable transaction, or
    /// behind a lock (SQLite's write lock, a Postgres advisory lock).
    async fn insert_device(
        &self,
        new: NewDevice,
    ) -> Result<Option<Device<Self::Subject>>, BackendError> {
        let _ = new;
        Err(NO_DEVICES.into())
    }

    /// The device authorization with hash `device_code_hash`, in any state.
    async fn find_device(
        &self,
        device_code_hash: &str,
    ) -> Result<Option<Device<Self::Subject>>, BackendError> {
        let _ = device_code_hash;
        Err(NO_DEVICES.into())
    }

    /// The unexpired device authorization (whatever its status) with
    /// `user_code` as `subject` may see it. A host with tenants answers `None`
    /// outside the subject's tenant, as for an unknown code.
    async fn device_by_user_code(
        &self,
        user_code: &str,
        subject: &Self::Subject,
    ) -> Result<Option<Device<Self::Subject>>, BackendError> {
        let _ = (user_code, subject);
        Err(NO_DEVICES.into())
    }

    /// Approve or deny device authorization `id` as `subject`, recording who.
    /// *Atomic:* only a pending, unexpired authorization is decided; `false`
    /// otherwise, so it is decided once.
    async fn decide_device(
        &self,
        id: Uuid,
        subject: &Self::Subject,
        approve: bool,
    ) -> Result<bool, BackendError> {
        let _ = (id, subject, approve);
        Err(NO_DEVICES.into())
    }

    /// Record a poll of device authorization `id` at `at` and its interval
    /// from now on.
    async fn record_poll(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
        interval_seconds: u32,
    ) -> Result<(), BackendError> {
        let _ = (id, at, interval_seconds);
        Err(NO_DEVICES.into())
    }

    /// Mark device authorization `id` redeemed and create its grant.
    /// *Atomic:* only an approved, unexpired authorization is redeemed, both
    /// or neither; `None` otherwise, so one approval yields one grant.
    async fn redeem_device(
        &self,
        id: Uuid,
        grant: NewGrant<Self::Subject>,
    ) -> Result<Option<Grant<Self::Subject>>, BackendError> {
        let _ = (id, grant);
        Err(NO_DEVICES.into())
    }

    /// Revoke grant `id` for `reason`. *Atomic:* `false` when it was already
    /// revoked or does not exist, so a revocation is recorded once.
    async fn revoke_grant(&self, id: Uuid, reason: &str) -> Result<bool, BackendError>;

    async fn insert_refresh_token(
        &self,
        grant: &Grant<Self::Subject>,
        token_hash: String,
    ) -> Result<(), BackendError>;

    /// The refresh token with hash `token_hash`, rotated or not.
    async fn find_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, BackendError>;

    /// Rotate `old` into a new token with `new_hash`: mark it rotated, insert
    /// the successor, stamp the grant's last refresh. *Atomic:* `false` when
    /// `old` was rotated concurrently, which the flow treats as reuse.
    async fn rotate_refresh_token(
        &self,
        old: &RefreshToken,
        grant: &Grant<Self::Subject>,
        new_hash: String,
    ) -> Result<bool, BackendError>;

    /// Delete expired pending authorizations, device authorizations, codes and
    /// cached documents; grants that expired or were revoked more than
    /// [`GRANT_RETENTION_DAYS`] ago, together with their codes and refresh
    /// tokens (rotated ones included); and registered clients older than
    /// [`UNUSED_CLIENT_DAYS`] that never got a grant and have no unexpired
    /// pending or device authorization. A client that ever had a grant stays, also
    /// after its grants are swept. [`RegisteredClient`] carries no field for
    /// that, so a store keeps its own flag on the client row, best set when a
    /// grant is created (so it also holds when a host deletes grants itself);
    /// checking only for existing grants would delete a returning client once
    /// its last grant is swept. A store adding the flag to existing data must
    /// backfill it for every client that has a grant, or those clients go once
    /// their grants pass the retention.
    ///
    /// Returns the rows removed, counting every row once: a grant's codes and
    /// refresh tokens count as well. An SQL backend must delete them
    /// explicitly, or count them in the same transaction, since the row count
    /// of an `ON DELETE CASCADE` delete does not include child rows.
    async fn sweep(&self) -> Result<u64, BackendError>;
}

/// How long [`OAuthStore::sweep`] keeps a grant after it expired or was
/// revoked, and with it its rotated refresh tokens.
///
/// While the grant is kept, presenting one of its old refresh tokens still
/// reaches the reuse check and is reported to [`Events::grant_revoked`]
/// (once, for a grant that only expired); the host can also still list the
/// grant as ended. Once it is swept such a token is merely unknown: the client
/// gets the same `invalid_grant`, but no event fires.
pub const GRANT_RETENTION_DAYS: i64 = 30;

/// How long after registration [`OAuthStore::sweep`] removes a client that
/// never got a grant and has no unexpired pending or device authorization.
pub const UNUSED_CLIENT_DAYS: i64 = 7;

const NO_DEVICES: &str = "this store does not keep device authorizations";

/// What [`Subjects::recheck`] decides.
#[derive(Debug, Clone, PartialEq)]
pub enum Recheck {
    /// Issue the token, with these app claims added to it.
    Allow(Map<String, Value>),
    /// Revoke the grant for this reason; the client gets `invalid_grant`.
    Revoke(String),
}

/// The host's decision about a grant's subject, run on every token issue
/// (code exchange and refresh): does the user still exist, may they still
/// log in, what is their role now.
#[async_trait]
pub trait Subjects<S>: Send + Sync {
    async fn recheck(&self, grant: &Grant<S>) -> Result<Recheck, BackendError>;
}

/// Hooks for audit and tracing. Called after the store committed.
#[async_trait]
pub trait Events<S>: Send + Sync {
    /// A grant was created by an approve or [`crate::Server::issue_grant`].
    async fn grant_created(&self, _grant: &Grant<S>) {}

    /// A grant was revoked by a flow (reuse, a failed recheck) or by
    /// [`crate::Server::revoke`]. `client_ip` is what the caller passed.
    async fn grant_revoked(&self, _grant: &Grant<S>, _reason: &str, _client_ip: Option<&str>) {}
}

/// [`Events`] that do nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvents;

#[async_trait]
impl<S: Sync> Events<S> for NoEvents {}

/// Why a flow revoked a grant.
pub mod reason {
    /// A rotated refresh token was presented again.
    pub const REFRESH_REUSE: &str = "refresh_reuse";
    /// An already exchanged authorization code was presented again.
    pub const CODE_REUSE: &str = "code_reuse";
}
