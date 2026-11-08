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

use crate::device::{Device, DeviceStatus};
use crate::store::{
    BackendError, Code, GRANT_RETENTION_DAYS, Grant, NewDevice, NewGrant, NewPending, OAuthStore,
    Pending, RefreshToken, RegisteredClient,
};

/// How long a registered client may go without a grant (none yet, or all swept) before
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
    /// By device-code hash.
    devices: HashMap<String, Device<S>>,
}

impl<S> Inner<S> {
    fn device_mut(&mut self, id: Uuid) -> Option<&mut Device<S>> {
        self.devices.values_mut().find(|d| d.id == id)
    }
}

fn new_grant<S>(new: NewGrant<S>, now: DateTime<Utc>) -> Grant<S> {
    Grant {
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
    }
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
                devices: HashMap::new(),
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
            g.revoked_at = g.revoked_at.map(|at| at - by);
        }
        for c in inner.clients.values_mut() {
            c.created_at -= by;
        }
        for (_, at) in inner.documents.values_mut() {
            *at -= by;
        }
        for d in inner.devices.values_mut() {
            d.created_at -= by;
            d.expires_at -= by;
            d.last_polled_at = d.last_polled_at.map(|at| at - by);
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
        let Some(row) = inner.pending.get_mut(&id).filter(|p| p.expires_at > now) else {
            return Ok(None);
        };
        if row.subject.is_none() {
            row.subject = Some(subject.clone());
        }
        Ok((row.subject.as_ref() == Some(subject)).then(|| row.clone()))
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
        let grant = new_grant(new, Utc::now());
        self.lock().grants.insert(grant.id, grant.clone());
        Ok(grant)
    }

    async fn insert_device(&self, new: NewDevice) -> Result<Option<Device<S>>, BackendError> {
        let now = Utc::now();
        let mut inner = self.lock();
        if inner
            .devices
            .values()
            .any(|d| d.user_code == new.user_code && d.expires_at > now)
        {
            return Ok(None);
        }
        let device = Device {
            id: Uuid::new_v4(),
            client_id: new.client_id,
            client_name: new.client_name,
            scope: new.scope,
            user_code: new.user_code,
            status: DeviceStatus::Pending,
            interval_seconds: new.interval_seconds,
            last_polled_at: None,
            subject: None,
            created_at: now,
            expires_at: now + new.ttl,
        };
        inner.devices.insert(new.device_code_hash, device.clone());
        Ok(Some(device))
    }

    async fn find_device(&self, device_code_hash: &str) -> Result<Option<Device<S>>, BackendError> {
        Ok(self.lock().devices.get(device_code_hash).cloned())
    }

    async fn device_by_user_code(
        &self,
        user_code: &str,
        _subject: &S,
    ) -> Result<Option<Device<S>>, BackendError> {
        let now = Utc::now();
        Ok(self
            .lock()
            .devices
            .values()
            .find(|d| d.user_code == user_code && d.expires_at > now)
            .cloned())
    }

    async fn decide_device(
        &self,
        id: Uuid,
        subject: &S,
        approve: bool,
    ) -> Result<bool, BackendError> {
        let now = Utc::now();
        let mut inner = self.lock();
        let Some(d) = inner
            .device_mut(id)
            .filter(|d| d.status_at(now) == DeviceStatus::Pending)
        else {
            return Ok(false);
        };
        d.status = if approve {
            DeviceStatus::Approved
        } else {
            DeviceStatus::Denied
        };
        d.subject = Some(subject.clone());
        Ok(true)
    }

    async fn record_poll(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
        interval_seconds: u32,
    ) -> Result<(), BackendError> {
        if let Some(d) = self.lock().device_mut(id) {
            d.last_polled_at = Some(at);
            d.interval_seconds = interval_seconds;
        }
        Ok(())
    }

    async fn redeem_device(
        &self,
        id: Uuid,
        grant: NewGrant<S>,
    ) -> Result<Option<Grant<S>>, BackendError> {
        let now = Utc::now();
        let mut inner = self.lock();
        let Some(d) = inner
            .device_mut(id)
            .filter(|d| d.status_at(now) == DeviceStatus::Approved)
        else {
            return Ok(None);
        };
        d.status = DeviceStatus::Redeemed;
        let grant = new_grant(grant, now);
        inner.grants.insert(grant.id, grant.clone());
        Ok(Some(grant))
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
        let count = |i: &Inner<S>| {
            i.pending.len()
                + i.codes.len()
                + i.documents.len()
                + i.clients.len()
                + i.devices.len()
                + i.grants.len()
                + i.refresh.len()
        };
        let before = count(&inner);
        let ended = now - Duration::days(GRANT_RETENTION_DAYS);
        inner
            .grants
            .retain(|_, g| g.expires_at.min(g.revoked_at.unwrap_or(g.expires_at)) >= ended);
        let Inner {
            grants,
            codes,
            refresh,
            ..
        } = &mut *inner;
        codes.retain(|_, c| c.expires_at > now && grants.contains_key(&c.grant_id));
        refresh.retain(|_, t| grants.contains_key(&t.grant_id));
        inner.pending.retain(|_, p| p.expires_at > now);
        inner.devices.retain(|_, d| d.expires_at > now);
        inner.documents.retain(|_, (_, expires)| *expires > now);
        let granted: Vec<String> = inner.grants.values().map(|g| g.client_id.clone()).collect();
        let cutoff = now - Duration::days(UNUSED_CLIENT_DAYS);
        inner
            .clients
            .retain(|id, c| c.created_at >= cutoff || granted.contains(id));
        Ok(u64::try_from(before - count(&inner)).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> NewPending {
        NewPending {
            client_id: "c".into(),
            client_name: "c".into(),
            loopback_only: true,
            redirect_uri: "http://localhost/cb".into(),
            scope: "read".into(),
            state: None,
            code_challenge: "x".into(),
            resource: "r".into(),
            ttl: Duration::seconds(600),
        }
    }

    #[tokio::test]
    async fn claim_pending_does_not_bind_an_expired_request() {
        let store = MemoryStore::<String>::default();
        let id = store.insert_pending(request()).await.unwrap().id;
        store.age(Duration::seconds(601));
        assert!(
            store
                .claim_pending(id, &"alice".into())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(store.lock().pending[&id].subject, None);
    }
}
