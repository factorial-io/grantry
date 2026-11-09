# grantry-redis

A Redis / Valkey `OAuthStore` for [grantry](https://crates.io/crates/grantry).

```rust
let conn = redis::Client::open(redis_url)?.get_connection_manager().await?;
let store = Arc::new(grantry_redis::RedisStore::<String>::new(conn));
// or RedisStore::with_prefix(conn, "myapp:oauth:")
```

The subject type must implement `Serialize` and `DeserializeOwned`, and equal subjects must serialize to the same JSON (a string or a struct does; a `HashMap` does not).

- Every row is a hash under one key prefix (`grantry:` by default). The atomic methods run as Lua scripts or `MULTI` transactions.
- Rows go away through key expiry, so `sweep` does nothing. Grants and their refresh tokens are kept `GRANT_RETENTION_DAYS` after they end. Unused clients go after `UNUSED_CLIENT_DAYS`. Clients that ever got a grant stay.
- Device authorizations stay an hour past their end, so a late poll still gets `expired_token`.
- Needs Redis 6.2+ or Valkey. Redis Cluster is not supported, because the scripts touch keys they look up.

The store passes grantry's `conformance` checks (`tests/conformance.rs`, with `REDIS_URL` set).

## License

[MPL-2.0](LICENSE).
