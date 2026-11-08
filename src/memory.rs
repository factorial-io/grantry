// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! An in-memory [`OAuthStore`] for tests and examples. One mutex makes every
//! method atomic. Not for production: nothing survives a restart.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::store::{
    BackendError, Code, Grant, NewGrant, NewPending, OAuthStore, Pending, RefreshToken,
    RegisteredClient,
};

/// How long a registered client may go without a grant before
/// [`OAuthStore::sweep`] removes it.
pub const UNUSED_CLIENT_DAYS: i64 = 7;

struct Inner<S> {
    clients: HashMap<String, RegisteredClient>,
    documents: HashMap<String, (Value, DateTime<Utc>)>,
    pending: HashMap<Uuid, Pending<S>>,
    grants: HashMap<Uuid, Grant<S>>,
    /// By hash.
    codes: HashMap<String, Code>,
    /// By hash.
    refresh: HashMap<String, RefreshToken>,
}

/// See the module docs.
pub struct MemoryStore<S> {
    inner: Mutex<Inner<S>>,
}

impl<S> Default for MemoryStore<S> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                clients: HashMap::new(),
                documents: HashMap::new(),
                pending: HashMap::new(),
                grants: HashMap::new(),
                codes: HashMap::new(),
                refresh: HashMap::new(),
            }),
        }
    }
}

impl<S> MemoryStore<S> {
    fn lock(&self) -> MutexGuard<'_, Inner<S>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Move every expiry and lifetime `by` into the past, as if that much
    /// time went by. For tests of expiry.
    pub fn age(&self, by: Duration) {
        let mut inner = self.lock();
        for p in inner.pending.values_mut() {
            p.expires_at -= by;
        }
        for c in inner.codes.values_mut() {
            c.expires_at -= by;
        }
        for g in inner.grants.values_mut() {
            g.expires_at -= by;
            g.created_at -= by;
        }
        for c in inner.clients.values_mut() {
            c.created_at -= by;
        }
        for (_, at) in inner.documents.values_mut() {
            *at -= by;
        }
    }
}

#[async_trait]
impl<S: Clone + PartialEq + Send + Sync + 'static> OAuthStore for MemoryStore<S> {
    type Subject = S;

    async fn insert_client(
        &self,
        id: String,
        name: String,
        redirect_uris: &[String],
    ) -> Result<RegisteredClient, BackendError> {
        let client = RegisteredClient {
            id: id.clone(),
            name,
            redirect_uris: redirect_uris.to_vec(),
            created_at: Utc::now(),
        };
        self.lock().clients.insert(id, client.clone());
        Ok(client)
    }

    async fn use_client(&self, id: &str) -> Result<Option<RegisteredClient>, BackendError> {
        Ok(self.lock().clients.get(id).cloned())
    }

    async fn cached_document(&self, url: &str) -> Result<Option<Value>, BackendError> {
        let now = Utc::now();
        Ok(self
            .lock()
            .documents
            .get(url)
            .filter(|(_, expires)| *expires > now)
            .map(|(doc, _)| doc.clone()))
    }

    async fn store_document(
        &self,
        url: &str,
        document: Value,
        expires_at: DateTime<Utc>,
    ) -> Result<(), BackendError> {
        self.lock()
            .documents
            .insert(url.to_string(), (document, expires_at));
        Ok(())
    }

    async fn insert_pending(&self, new: NewPending) -> Result<Pending<S>, BackendError> {
        let now = Utc::now();
        let pending = Pending {
            id: Uuid::new_v4(),
            client_id: new.client_id,
            client_name: new.client_name,
            loopback_only: new.loopback_only,
            redirect_uri: new.redirect_uri,
            scope: new.scope,
            state: new.state,
            code_challenge: new.code_challenge,
            resource: new.resource,
            subject: None,
            created_at: now,
            expires_at: now + new.ttl,
        };
        self.lock().pending.insert(pending.id, pending.clone());
        Ok(pending)
    }

    async fn claim_pending(
        &self,
        id: Uuid,
        subject: &S,
    ) -> Result<Option<Pending<S>>, BackendError> {
        let now = Utc::now();
        let mut inner = self.lock();
        let Some(row) = inner.pending.get_mut(&id) else {
            return Ok(None);
        };
        if row.subject.is_none() {
            row.subject = Some(subject.clone());
        }
        Ok((row.expires_at > now && row.subject.as_ref() == Some(subject)).then(|| row.clone()))
    }

    async fn take_pending(
        &self,
        id: Uuid,
        subject: &S,
    ) -> Result<Option<Pending<S>>, BackendError> {
        let now = Utc::now();
        let mut inner = self.lock();
        let Some(row) = inner.pending.get_mut(&id) else {
            return Ok(None);
        };
        if row.subject.is_none() {
            row.subject = Some(subject.clone());
        }
        if row.expires_at <= now || row.subject.as_ref() != Some(subject) {
            return Ok(None);
        }
        Ok(inner.pending.remove(&id))
    }

    async fn create_grant_with_code(
        &self,
        approved: &Pending<S>,
        subject: &S,
        lifetime: Duration,
        code_hash: String,
        code_ttl: Duration,
    ) -> Result<Grant<S>, BackendError> {
        let now = Utc::now();
        let grant = Grant {
            id: Uuid::new_v4(),
            subject: subject.clone(),
            client_id: approved.client_id.clone(),
            client_name: approved.client_name.clone(),
            redirect_uri: approved.redirect_uri.clone(),
            scope: approved.scope.clone(),
            created_at: now,
            expires_at: now + lifetime,
            last_refreshed_at: None,
            revoked_at: None,
            revoke_reason: None,
        };
        let code = Code {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            client_id: approved.client_id.clone(),
            redirect_uri: approved.redirect_uri.clone(),
            resource: approved.resource.clone(),
            code_challenge: approved.code_challenge.clone(),
            expires_at: now + code_ttl,
            used_at: None,
        };
        let mut inner = self.lock();
        inner.grants.insert(grant.id, grant.clone());
        inner.codes.insert(code_hash, code);
        Ok(grant)
    }

    async fn create_grant(&self, new: NewGrant<S>) -> Result<Grant<S>, BackendError> {
        let now = Utc::now();
        let grant = Grant {
            id: Uuid::new_v4(),
            subject: new.subject,
            client_id: new.client_id,
            client_name: new.client_name,
            redirect_uri: String::new(),
            scope: new.scope,
            created_at: now,
            expires_at: now + new.lifetime,
            last_refreshed_at: None,
            revoked_at: None,
            revoke_reason: None,
        };
        self.lock().grants.insert(grant.id, grant.clone());
        Ok(grant)
    }

    async fn find_code(&self, code_hash: &str) -> Result<Option<Code>, BackendError> {
        Ok(self.lock().codes.get(code_hash).cloned())
    }

    async fn use_code(&self, id: Uuid) -> Result<bool, BackendError> {
        let mut inner = self.lock();
        let Some(code) = inner
            .codes
            .values_mut()
            .find(|c| c.id == id && c.used_at.is_none())
        else {
            return Ok(false);
        };
        code.used_at = Some(Utc::now());
        Ok(true)
    }

    async fn find_grant(&self, id: Uuid) -> Result<Option<Grant<S>>, BackendError> {
        Ok(self.lock().grants.get(&id).cloned())
    }

    async fn revoke_grant(&self, id: Uuid, reason: &str) -> Result<bool, BackendError> {
        let mut inner = self.lock();
        let Some(grant) = inner.grants.get_mut(&id).filter(|g| g.revoked_at.is_none()) else {
            return Ok(false);
        };
        grant.revoked_at = Some(Utc::now());
        grant.revoke_reason = Some(reason.to_string());
        Ok(true)
    }

    async fn insert_refresh_token(
        &self,
        grant: &Grant<S>,
        token_hash: String,
    ) -> Result<(), BackendError> {
        self.lock().refresh.insert(
            token_hash,
            RefreshToken {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                issued_at: Utc::now(),
                rotated_at: None,
            },
        );
        Ok(())
    }

    async fn find_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, BackendError> {
        Ok(self.lock().refresh.get(token_hash).cloned())
    }

    async fn rotate_refresh_token(
        &self,
        old: &RefreshToken,
        grant: &Grant<S>,
        new_hash: String,
    ) -> Result<bool, BackendError> {
        let now = Utc::now();
        let mut inner = self.lock();
        let Some(token) = inner
            .refresh
            .values_mut()
            .find(|t| t.id == old.id && t.rotated_at.is_none())
        else {
            return Ok(false);
        };
        token.rotated_at = Some(now);
        inner.refresh.insert(
            new_hash,
            RefreshToken {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                issued_at: now,
                rotated_at: None,
            },
        );
        if let Some(g) = inner.grants.get_mut(&grant.id) {
            g.last_refreshed_at = Some(now);
        }
        Ok(true)
    }

    async fn sweep(&self) -> Result<u64, BackendError> {
        let now = Utc::now();
        let mut inner = self.lock();
        let before =
            inner.pending.len() + inner.codes.len() + inner.documents.len() + inner.clients.len();
        inner.pending.retain(|_, p| p.expires_at > now);
        inner.codes.retain(|_, c| c.expires_at > now);
        inner.documents.retain(|_, (_, expires)| *expires > now);
        let granted: Vec<String> = inner.grants.values().map(|g| g.client_id.clone()).collect();
        let cutoff = now - Duration::days(UNUSED_CLIENT_DAYS);
        inner
            .clients
            .retain(|id, c| c.created_at >= cutoff || granted.contains(id));
        let after =
            inner.pending.len() + inner.codes.len() + inner.documents.len() + inner.clients.len();
        Ok(u64::try_from(before - after).unwrap_or(0))
    }
}
