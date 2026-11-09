// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A Redis / Valkey [`OAuthStore`] for [grantry](https://docs.rs/grantry).
//!
//! ```ignore
//! let conn = redis::Client::open(redis_url)?.get_connection_manager().await?;
//! let store = Arc::new(grantry_redis::RedisStore::<String>::new(conn));
//! ```
//!
//! Every row is a hash under one key prefix (`grantry:` by default). The
//! *atomic* methods run as Lua scripts or `MULTI` transactions.
//!
//! Redis removes rows through key expiry, so [`OAuthStore::sweep`] has
//! nothing to do and returns 0. Pending authorizations, codes and cached
//! documents expire with their `expires_at`; a grant and its refresh tokens
//! [`GRANT_RETENTION_DAYS`] after it expired or was revoked; a registered
//! client [`UNUSED_CLIENT_DAYS`] after its registration or last use, unless
//! it ever got a grant. Device authorizations stay an hour past their end, so
//! a late poll still reads `expired_token`; their user code is free at the
//! end.
//!
//! Requirements:
//!
//! - Redis 6.2 or later, or Valkey; not Redis Cluster, because the scripts
//!   touch keys they look up.
//! - The subject's JSON (serde_json) is the same for equal subjects: the
//!   scripts compare subjects as JSON strings. A struct or a string is; a
//!   `HashMap` is not.
//! - Timestamps are kept in microseconds.

use std::collections::HashMap;
use std::fmt::Display;
use std::marker::PhantomData;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use grantry::device::{Device, DeviceStatus};
use grantry::store::{
    BackendError, Code, GRANT_RETENTION_DAYS, Grant, NewDevice, NewGrant, NewPending, OAuthStore,
    Pending, RefreshToken, RegisteredClient, UNUSED_CLIENT_DAYS,
};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

/// How long a device authorization is kept after its end. ponytail: fixed;
/// make it configurable if a host polls slower than this.
const EXPIRED_DEVICE_KEEP_HOURS: i64 = 1;

/// Adds a refresh token and its id index to a grant's key set, and gives
/// them the grant's remaining lifetime.
const ADD_TOKEN: &str = r"
local function add_token(grant, set, key, idkey, id, grant_id, issued, hash, fallback_ms)
  redis.call('HSET', key, 'id', id, 'grant_id', grant_id, 'issued_at', issued)
  redis.call('SET', idkey, hash)
  redis.call('SADD', set, key, idkey)
  local ttl = redis.call('PTTL', grant)
  if ttl < 0 then ttl = fallback_ms end
  redis.call('PEXPIRE', key, ttl)
  redis.call('PEXPIRE', idkey, ttl)
  redis.call('PEXPIRE', set, ttl)
end
";

/// KEYS: client. ARGV: ttl_ms.
const USE_CLIENT: &str = r"
if redis.call('EXISTS', KEYS[1]) == 0 then return false end
if redis.call('PTTL', KEYS[1]) >= 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return redis.call('HGETALL', KEYS[1])
";

/// KEYS: pending. ARGV: subject, now_us, take (`1` deletes).
const CLAIM: &str = r"
local exp = redis.call('HGET', KEYS[1], 'expires_at')
if not exp or tonumber(exp) <= tonumber(ARGV[2]) then return false end
local s = redis.call('HGET', KEYS[1], 'subject')
if not s then
  redis.call('HSET', KEYS[1], 'subject', ARGV[1])
  s = ARGV[1]
end
if s ~= ARGV[1] then return false end
local row = redis.call('HGETALL', KEYS[1])
if ARGV[3] == '1' then redis.call('DEL', KEYS[1]) end
return row
";

/// KEYS: code id index. ARGV: prefix, now_us.
const USE_CODE: &str = r"
local h = redis.call('GET', KEYS[1])
if not h then return 0 end
local k = ARGV[1] .. 'code:' .. h
if redis.call('EXISTS', k) == 0 or redis.call('HEXISTS', k, 'used_at') == 1 then return 0 end
redis.call('HSET', k, 'used_at', ARGV[2])
return 1
";

/// KEYS: grant, grant key set. ARGV: now_us, reason, retention_us.
const REVOKE: &str = r"
if redis.call('EXISTS', KEYS[1]) == 0 or redis.call('HEXISTS', KEYS[1], 'revoked_at') == 1 then
  return 0
end
redis.call('HSET', KEYS[1], 'revoked_at', ARGV[1], 'revoke_reason', ARGV[2])
local ended = math.min(tonumber(redis.call('HGET', KEYS[1], 'expires_at')), tonumber(ARGV[1]))
local keep = string.format('%.0f', math.floor((ended + tonumber(ARGV[3])) / 1000))
redis.call('PEXPIREAT', KEYS[1], keep)
for _, k in ipairs(redis.call('SMEMBERS', KEYS[2])) do redis.call('PEXPIREAT', k, keep) end
redis.call('PEXPIREAT', KEYS[2], keep)
return 1
";

/// KEYS: grant, grant key set, token, token id index.
/// ARGV: id, grant_id, issued_us, hash, fallback_ms.
const INSERT_REFRESH: &str = r"
add_token(KEYS[1], KEYS[2], KEYS[3], KEYS[4], ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5])
return 1
";

/// KEYS: old token id index, grant, grant key set, new token, new token id
/// index. ARGV: prefix, now_us, new id, grant_id, new hash, fallback_ms.
const ROTATE: &str = r"
local h = redis.call('GET', KEYS[1])
if not h then return 0 end
local old = ARGV[1] .. 'refresh:' .. h
if redis.call('EXISTS', old) == 0 or redis.call('HEXISTS', old, 'rotated_at') == 1 then return 0 end
redis.call('HSET', old, 'rotated_at', ARGV[2])
add_token(KEYS[2], KEYS[3], KEYS[4], KEYS[5], ARGV[3], ARGV[4], ARGV[2], ARGV[5], ARGV[6])
if redis.call('EXISTS', KEYS[2]) == 1 then
  redis.call('HSET', KEYS[2], 'last_refreshed_at', ARGV[2])
end
return 1
";

/// KEYS: user code, device, device id index.
/// ARGV: device-code hash, now_ms, expires_ms, keep_ms, fields...
const INSERT_DEVICE: &str = r"
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
if tonumber(ARGV[3]) > tonumber(ARGV[2]) then
  redis.call('SET', KEYS[1], ARGV[1], 'PXAT', ARGV[3])
end
redis.call('HSET', KEYS[2], unpack(ARGV, 5))
redis.call('SET', KEYS[3], ARGV[1])
redis.call('PEXPIREAT', KEYS[2], ARGV[4])
redis.call('PEXPIREAT', KEYS[3], ARGV[4])
return 1
";

/// KEYS: device id index. ARGV: prefix, now_us, status, subject.
const DECIDE: &str = r"
local h = redis.call('GET', KEYS[1])
if not h then return 0 end
local d = ARGV[1] .. 'device:' .. h
if redis.call('HGET', d, 'status') ~= 'pending' then return 0 end
if tonumber(redis.call('HGET', d, 'expires_at')) <= tonumber(ARGV[2]) then return 0 end
redis.call('HSET', d, 'status', ARGV[3], 'subject', ARGV[4])
return 1
";

/// KEYS: device id index. ARGV: prefix, at_us, interval.
const RECORD_POLL: &str = r"
local h = redis.call('GET', KEYS[1])
if not h then return 0 end
local d = ARGV[1] .. 'device:' .. h
if redis.call('EXISTS', d) == 0 then return 0 end
redis.call('HSET', d, 'last_polled_at', ARGV[2], 'interval_seconds', ARGV[3])
return 1
";

/// KEYS: device id index, grant, client. ARGV: prefix, now_us, keep_ms,
/// grant fields...
const REDEEM: &str = r"
local h = redis.call('GET', KEYS[1])
if not h then return 0 end
local d = ARGV[1] .. 'device:' .. h
if redis.call('HGET', d, 'status') ~= 'approved' then return 0 end
if tonumber(redis.call('HGET', d, 'expires_at')) <= tonumber(ARGV[2]) then return 0 end
redis.call('HSET', d, 'status', 'redeemed')
redis.call('HSET', KEYS[2], unpack(ARGV, 4))
redis.call('PEXPIREAT', KEYS[2], ARGV[3])
redis.call('PERSIST', KEYS[3])
return 1
";

struct Scripts {
    use_client: Script,
    claim: Script,
    use_code: Script,
    revoke: Script,
    insert_refresh: Script,
    rotate: Script,
    insert_device: Script,
    decide: Script,
    record_poll: Script,
    redeem: Script,
}

impl Scripts {
    fn new() -> Self {
        Self {
            use_client: Script::new(USE_CLIENT),
            claim: Script::new(CLAIM),
            use_code: Script::new(USE_CODE),
            revoke: Script::new(REVOKE),
            insert_refresh: Script::new(&format!("{ADD_TOKEN}{INSERT_REFRESH}")),
            rotate: Script::new(&format!("{ADD_TOKEN}{ROTATE}")),
            insert_device: Script::new(INSERT_DEVICE),
            decide: Script::new(DECIDE),
            record_poll: Script::new(RECORD_POLL),
            redeem: Script::new(REDEEM),
        }
    }
}

/// See the crate docs. `S` is the subject type.
pub struct RedisStore<S> {
    conn: ConnectionManager,
    prefix: String,
    scripts: Scripts,
    _subject: PhantomData<fn() -> S>,
}

impl<S> RedisStore<S> {
    /// A store under the key prefix `grantry:`.
    pub fn new(conn: ConnectionManager) -> Self {
        Self::with_prefix(conn, "grantry:")
    }

    /// A store whose keys all start with `prefix`.
    pub fn with_prefix(conn: ConnectionManager, prefix: impl Into<String>) -> Self {
        Self {
            conn,
            prefix: prefix.into(),
            scripts: Scripts::new(),
            _subject: PhantomData,
        }
    }

    fn key(&self, kind: &str, id: impl Display) -> String {
        format!("{}{kind}:{id}", self.prefix)
    }

    fn grant_set(&self, grant: Uuid) -> String {
        format!("{}grant:{grant}:keys", self.prefix)
    }

    fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    async fn row(&self, key: String) -> Result<Option<Row>, BackendError> {
        let map: HashMap<String, String> = self.conn().hgetall(&key).await?;
        Ok((!map.is_empty()).then_some(Row { key, map }))
    }
}

fn us(t: DateTime<Utc>) -> String {
    t.timestamp_micros().to_string()
}

fn ms(t: DateTime<Utc>) -> i64 {
    t.timestamp_millis()
}

fn retention() -> Duration {
    Duration::days(GRANT_RETENTION_DAYS)
}

fn unused_client_ms() -> i64 {
    Duration::days(UNUSED_CLIENT_DAYS).num_milliseconds()
}

fn json<T: Serialize>(value: &T) -> Result<String, BackendError> {
    Ok(serde_json::to_string(value)?)
}

fn flat(fields: Vec<(&'static str, String)>) -> Vec<String> {
    fields
        .into_iter()
        .flat_map(|(k, v)| [k.to_string(), v])
        .collect()
}

/// A hash read back, with typed field access.
struct Row {
    key: String,
    map: HashMap<String, String>,
}

impl Row {
    fn get(&self, field: &str) -> Result<&str, BackendError> {
        self.map
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| format!("grantry-redis: {} has no field {field}", self.key).into())
    }

    fn string(&self, field: &str) -> Result<String, BackendError> {
        self.get(field).map(str::to_owned)
    }

    fn opt(&self, field: &str) -> Option<String> {
        self.map.get(field).cloned()
    }

    fn uuid(&self, field: &str) -> Result<Uuid, BackendError> {
        Ok(self.get(field)?.parse()?)
    }

    fn time(&self, field: &str) -> Result<DateTime<Utc>, BackendError> {
        parse_time(self.get(field)?)
    }

    fn opt_time(&self, field: &str) -> Result<Option<DateTime<Utc>>, BackendError> {
        self.map.get(field).map(|v| parse_time(v)).transpose()
    }

    fn json<T: DeserializeOwned>(&self, field: &str) -> Result<T, BackendError> {
        Ok(serde_json::from_str(self.get(field)?)?)
    }

    fn opt_json<T: DeserializeOwned>(&self, field: &str) -> Result<Option<T>, BackendError> {
        Ok(self
            .map
            .get(field)
            .map(|v| serde_json::from_str(v))
            .transpose()?)
    }
}

fn parse_time(v: &str) -> Result<DateTime<Utc>, BackendError> {
    DateTime::from_timestamp_micros(v.parse()?)
        .ok_or_else(|| format!("grantry-redis: timestamp out of range: {v}").into())
}

fn status_str(status: DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Approved => "approved",
        DeviceStatus::Denied => "denied",
        DeviceStatus::Redeemed => "redeemed",
        DeviceStatus::Expired => "expired",
    }
}

fn parse_status(v: &str) -> Result<DeviceStatus, BackendError> {
    Ok(match v {
        "pending" => DeviceStatus::Pending,
        "approved" => DeviceStatus::Approved,
        "denied" => DeviceStatus::Denied,
        "redeemed" => DeviceStatus::Redeemed,
        "expired" => DeviceStatus::Expired,
        other => return Err(format!("grantry-redis: unknown device status {other}").into()),
    })
}

fn client_from(row: &Row) -> Result<RegisteredClient, BackendError> {
    Ok(RegisteredClient {
        id: row.string("id")?,
        name: row.string("name")?,
        redirect_uris: row.json("redirect_uris")?,
        created_at: row.time("created_at")?,
    })
}

fn pending_from<S: DeserializeOwned>(row: &Row) -> Result<Pending<S>, BackendError> {
    Ok(Pending {
        id: row.uuid("id")?,
        client_id: row.string("client_id")?,
        client_name: row.string("client_name")?,
        loopback_only: row.get("loopback_only")? == "1",
        redirect_uri: row.string("redirect_uri")?,
        scope: row.string("scope")?,
        state: row.opt("state"),
        code_challenge: row.string("code_challenge")?,
        resource: row.string("resource")?,
        subject: row.opt_json("subject")?,
        created_at: row.time("created_at")?,
        expires_at: row.time("expires_at")?,
    })
}

fn grant_from<S: DeserializeOwned>(row: &Row) -> Result<Grant<S>, BackendError> {
    Ok(Grant {
        id: row.uuid("id")?,
        subject: row.json("subject")?,
        client_id: row.string("client_id")?,
        client_name: row.string("client_name")?,
        redirect_uri: row.string("redirect_uri")?,
        scope: row.string("scope")?,
        created_at: row.time("created_at")?,
        expires_at: row.time("expires_at")?,
        last_refreshed_at: row.opt_time("last_refreshed_at")?,
        revoked_at: row.opt_time("revoked_at")?,
        revoke_reason: row.opt("revoke_reason"),
    })
}

/// The fields of a new grant: no refresh, no revocation yet.
fn grant_fields<S: Serialize>(g: &Grant<S>) -> Result<Vec<(&'static str, String)>, BackendError> {
    Ok(vec![
        ("id", g.id.to_string()),
        ("subject", json(&g.subject)?),
        ("client_id", g.client_id.clone()),
        ("client_name", g.client_name.clone()),
        ("redirect_uri", g.redirect_uri.clone()),
        ("scope", g.scope.clone()),
        ("created_at", us(g.created_at)),
        ("expires_at", us(g.expires_at)),
    ])
}

/// When a grant's keys go if it is never revoked.
fn grant_keep_ms<S>(g: &Grant<S>) -> i64 {
    ms(g.expires_at + retention())
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

fn code_from(row: &Row) -> Result<Code, BackendError> {
    Ok(Code {
        id: row.uuid("id")?,
        grant_id: row.uuid("grant_id")?,
        client_id: row.string("client_id")?,
        redirect_uri: row.string("redirect_uri")?,
        resource: row.string("resource")?,
        code_challenge: row.string("code_challenge")?,
        expires_at: row.time("expires_at")?,
        used_at: row.opt_time("used_at")?,
    })
}

fn refresh_from(row: &Row) -> Result<RefreshToken, BackendError> {
    Ok(RefreshToken {
        id: row.uuid("id")?,
        grant_id: row.uuid("grant_id")?,
        issued_at: row.time("issued_at")?,
        rotated_at: row.opt_time("rotated_at")?,
    })
}

fn device_from<S: DeserializeOwned>(row: &Row) -> Result<Device<S>, BackendError> {
    Ok(Device {
        id: row.uuid("id")?,
        client_id: row.string("client_id")?,
        client_name: row.string("client_name")?,
        scope: row.string("scope")?,
        user_code: row.string("user_code")?,
        status: parse_status(row.get("status")?)?,
        interval_seconds: row.get("interval_seconds")?.parse()?,
        last_polled_at: row.opt_time("last_polled_at")?,
        subject: row.opt_json("subject")?,
        created_at: row.time("created_at")?,
        expires_at: row.time("expires_at")?,
    })
}

#[async_trait]
impl<S> OAuthStore for RedisStore<S>
where
    S: Serialize + DeserializeOwned + Clone + PartialEq + Send + Sync + 'static,
{
    type Subject = S;

    async fn insert_client(
        &self,
        id: String,
        name: String,
        redirect_uris: &[String],
    ) -> Result<RegisteredClient, BackendError> {
        let client = RegisteredClient {
            id,
            name,
            redirect_uris: redirect_uris.to_vec(),
            created_at: Utc::now(),
        };
        let key = self.key("client", &client.id);
        let fields = [
            ("id", client.id.clone()),
            ("name", client.name.clone()),
            ("redirect_uris", json(&client.redirect_uris)?),
            ("created_at", us(client.created_at)),
        ];
        redis::pipe()
            .atomic()
            .del(&key)
            .ignore()
            .hset_multiple(&key, &fields)
            .ignore()
            .pexpire(&key, unused_client_ms())
            .ignore()
            .query_async::<()>(&mut self.conn())
            .await?;
        Ok(client)
    }

    async fn use_client(&self, id: &str) -> Result<Option<RegisteredClient>, BackendError> {
        let key = self.key("client", id);
        let map: Option<HashMap<String, String>> = self
            .scripts
            .use_client
            .key(&key)
            .arg(unused_client_ms())
            .invoke_async(&mut self.conn())
            .await?;
        map.map(|map| client_from(&Row { key, map })).transpose()
    }

    async fn cached_document(&self, url: &str) -> Result<Option<Value>, BackendError> {
        let doc: Option<String> = self.conn().get(self.key("doc", url)).await?;
        Ok(doc.map(|d| serde_json::from_str(&d)).transpose()?)
    }

    async fn store_document(
        &self,
        url: &str,
        document: Value,
        expires_at: DateTime<Utc>,
    ) -> Result<(), BackendError> {
        let key = self.key("doc", url);
        // PEXPIREAT in the past deletes the key, like an expired row.
        redis::pipe()
            .atomic()
            .set(&key, json(&document)?)
            .ignore()
            .pexpire_at(&key, ms(expires_at))
            .ignore()
            .query_async::<()>(&mut self.conn())
            .await?;
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
        let key = self.key("pending", pending.id);
        let mut fields = vec![
            ("id", pending.id.to_string()),
            ("client_id", pending.client_id.clone()),
            ("client_name", pending.client_name.clone()),
            (
                "loopback_only",
                if pending.loopback_only { "1" } else { "0" }.to_string(),
            ),
            ("redirect_uri", pending.redirect_uri.clone()),
            ("scope", pending.scope.clone()),
            ("code_challenge", pending.code_challenge.clone()),
            ("resource", pending.resource.clone()),
            ("created_at", us(now)),
            ("expires_at", us(pending.expires_at)),
        ];
        if let Some(state) = &pending.state {
            fields.push(("state", state.clone()));
        }
        redis::pipe()
            .atomic()
            .hset_multiple(&key, &fields)
            .ignore()
            .pexpire_at(&key, ms(pending.expires_at))
            .ignore()
            .query_async::<()>(&mut self.conn())
            .await?;
        Ok(pending)
    }

    async fn claim_pending(
        &self,
        id: Uuid,
        subject: &S,
    ) -> Result<Option<Pending<S>>, BackendError> {
        self.claim(id, subject, false).await
    }

    async fn take_pending(
        &self,
        id: Uuid,
        subject: &S,
    ) -> Result<Option<Pending<S>>, BackendError> {
        self.claim(id, subject, true).await
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
        let code_id = Uuid::new_v4();
        let code_expires = ms(now + code_ttl);
        let code_fields = [
            ("id", code_id.to_string()),
            ("grant_id", grant.id.to_string()),
            ("client_id", approved.client_id.clone()),
            ("redirect_uri", approved.redirect_uri.clone()),
            ("resource", approved.resource.clone()),
            ("code_challenge", approved.code_challenge.clone()),
            ("expires_at", us(now + code_ttl)),
        ];
        let (grant_key, code_key, code_id_key) = (
            self.key("grant", grant.id),
            self.key("code", &code_hash),
            self.key("code-id", code_id),
        );
        redis::pipe()
            .atomic()
            .hset_multiple(&grant_key, &grant_fields(&grant)?)
            .ignore()
            .pexpire_at(&grant_key, grant_keep_ms(&grant))
            .ignore()
            .hset_multiple(&code_key, &code_fields)
            .ignore()
            .pexpire_at(&code_key, code_expires)
            .ignore()
            .set(&code_id_key, &code_hash)
            .ignore()
            .pexpire_at(&code_id_key, code_expires)
            .ignore()
            // A client that ever had a grant stays.
            .persist(self.key("client", &grant.client_id))
            .ignore()
            .query_async::<()>(&mut self.conn())
            .await?;
        Ok(grant)
    }

    async fn find_code(&self, code_hash: &str) -> Result<Option<Code>, BackendError> {
        self.row(self.key("code", code_hash))
            .await?
            .map(|row| code_from(&row))
            .transpose()
    }

    async fn use_code(&self, id: Uuid) -> Result<bool, BackendError> {
        let done: i64 = self
            .scripts
            .use_code
            .key(self.key("code-id", id))
            .arg(&self.prefix)
            .arg(us(Utc::now()))
            .invoke_async(&mut self.conn())
            .await?;
        Ok(done == 1)
    }

    async fn find_grant(&self, id: Uuid) -> Result<Option<Grant<S>>, BackendError> {
        self.row(self.key("grant", id))
            .await?
            .map(|row| grant_from(&row))
            .transpose()
    }

    async fn create_grant(&self, new: NewGrant<S>) -> Result<Grant<S>, BackendError> {
        let grant = new_grant(new, Utc::now());
        let key = self.key("grant", grant.id);
        redis::pipe()
            .atomic()
            .hset_multiple(&key, &grant_fields(&grant)?)
            .ignore()
            .pexpire_at(&key, grant_keep_ms(&grant))
            .ignore()
            .persist(self.key("client", &grant.client_id))
            .ignore()
            .query_async::<()>(&mut self.conn())
            .await?;
        Ok(grant)
    }

    async fn insert_device(&self, new: NewDevice) -> Result<Option<Device<S>>, BackendError> {
        let now = Utc::now();
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
        let fields = vec![
            ("id", device.id.to_string()),
            ("client_id", device.client_id.clone()),
            ("client_name", device.client_name.clone()),
            ("scope", device.scope.clone()),
            ("user_code", device.user_code.clone()),
            ("status", status_str(device.status).to_string()),
            ("interval_seconds", device.interval_seconds.to_string()),
            ("created_at", us(now)),
            ("expires_at", us(device.expires_at)),
        ];
        let keep = device.expires_at + Duration::hours(EXPIRED_DEVICE_KEEP_HOURS);
        let inserted: i64 = self
            .scripts
            .insert_device
            .key(self.key("user-code", &device.user_code))
            .key(self.key("device", &new.device_code_hash))
            .key(self.key("device-id", device.id))
            .arg(&new.device_code_hash)
            .arg(ms(now))
            .arg(ms(device.expires_at))
            .arg(ms(keep))
            .arg(flat(fields))
            .invoke_async(&mut self.conn())
            .await?;
        Ok((inserted == 1).then_some(device))
    }

    async fn find_device(&self, device_code_hash: &str) -> Result<Option<Device<S>>, BackendError> {
        self.row(self.key("device", device_code_hash))
            .await?
            .map(|row| device_from(&row))
            .transpose()
    }

    async fn device_by_user_code(
        &self,
        user_code: &str,
        _subject: &S,
    ) -> Result<Option<Device<S>>, BackendError> {
        let hash: Option<String> = self.conn().get(self.key("user-code", user_code)).await?;
        let Some(hash) = hash else {
            return Ok(None);
        };
        let device = self.find_device(&hash).await?;
        // The index expires to the millisecond; the row knows the microsecond.
        Ok(device.filter(|d| d.expires_at > Utc::now()))
    }

    async fn decide_device(
        &self,
        id: Uuid,
        subject: &S,
        approve: bool,
    ) -> Result<bool, BackendError> {
        let status = if approve {
            DeviceStatus::Approved
        } else {
            DeviceStatus::Denied
        };
        let done: i64 = self
            .scripts
            .decide
            .key(self.key("device-id", id))
            .arg(&self.prefix)
            .arg(us(Utc::now()))
            .arg(status_str(status))
            .arg(json(subject)?)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(done == 1)
    }

    async fn record_poll(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
        interval_seconds: u32,
    ) -> Result<(), BackendError> {
        let _: i64 = self
            .scripts
            .record_poll
            .key(self.key("device-id", id))
            .arg(&self.prefix)
            .arg(us(at))
            .arg(interval_seconds)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn redeem_device(
        &self,
        id: Uuid,
        grant: NewGrant<S>,
    ) -> Result<Option<Grant<S>>, BackendError> {
        let now = Utc::now();
        let grant = new_grant(grant, now);
        let done: i64 = self
            .scripts
            .redeem
            .key(self.key("device-id", id))
            .key(self.key("grant", grant.id))
            .key(self.key("client", &grant.client_id))
            .arg(&self.prefix)
            .arg(us(now))
            .arg(grant_keep_ms(&grant))
            .arg(flat(grant_fields(&grant)?))
            .invoke_async(&mut self.conn())
            .await?;
        Ok((done == 1).then_some(grant))
    }

    async fn revoke_grant(&self, id: Uuid, reason: &str) -> Result<bool, BackendError> {
        let done: i64 = self
            .scripts
            .revoke
            .key(self.key("grant", id))
            .key(self.grant_set(id))
            .arg(us(Utc::now()))
            .arg(reason)
            .arg(retention().num_microseconds().unwrap_or(i64::MAX))
            .invoke_async(&mut self.conn())
            .await?;
        Ok(done == 1)
    }

    async fn insert_refresh_token(
        &self,
        grant: &Grant<S>,
        token_hash: String,
    ) -> Result<(), BackendError> {
        let id = Uuid::new_v4();
        let _: i64 = self
            .scripts
            .insert_refresh
            .key(self.key("grant", grant.id))
            .key(self.grant_set(grant.id))
            .key(self.key("refresh", &token_hash))
            .key(self.key("refresh-id", id))
            .arg(id.to_string())
            .arg(grant.id.to_string())
            .arg(us(Utc::now()))
            .arg(&token_hash)
            .arg(retention().num_milliseconds())
            .invoke_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn find_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, BackendError> {
        self.row(self.key("refresh", token_hash))
            .await?
            .map(|row| refresh_from(&row))
            .transpose()
    }

    async fn rotate_refresh_token(
        &self,
        old: &RefreshToken,
        grant: &Grant<S>,
        new_hash: String,
    ) -> Result<bool, BackendError> {
        let id = Uuid::new_v4();
        let done: i64 = self
            .scripts
            .rotate
            .key(self.key("refresh-id", old.id))
            .key(self.key("grant", grant.id))
            .key(self.grant_set(grant.id))
            .key(self.key("refresh", &new_hash))
            .key(self.key("refresh-id", id))
            .arg(&self.prefix)
            .arg(us(Utc::now()))
            .arg(id.to_string())
            .arg(grant.id.to_string())
            .arg(&new_hash)
            .arg(retention().num_milliseconds())
            .invoke_async(&mut self.conn())
            .await?;
        Ok(done == 1)
    }

    /// Key expiry removes rows (see the crate docs): nothing to do.
    async fn sweep(&self) -> Result<u64, BackendError> {
        Ok(0)
    }
}

impl<S> RedisStore<S>
where
    S: Serialize + DeserializeOwned,
{
    async fn claim(
        &self,
        id: Uuid,
        subject: &S,
        take: bool,
    ) -> Result<Option<Pending<S>>, BackendError> {
        let key = self.key("pending", id);
        let map: Option<HashMap<String, String>> = self
            .scripts
            .claim
            .key(&key)
            .arg(json(subject)?)
            .arg(us(Utc::now()))
            .arg(if take { "1" } else { "0" })
            .invoke_async(&mut self.conn())
            .await?;
        map.map(|map| pending_from(&Row { key, map })).transpose()
    }
}
