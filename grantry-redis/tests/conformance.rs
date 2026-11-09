// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Redis store against the `OAuthStore` contract checks. Needs a server
//! at `REDIS_URL`; without it the test passes without checking anything.

use grantry::conformance;
use grantry_redis::RedisStore;
use uuid::Uuid;

#[tokio::test]
async fn redis_store_conforms() -> Result<(), redis::RedisError> {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("REDIS_URL is not set: skipping the Redis conformance checks");
        return Ok(());
    };
    let conn = redis::Client::open(url)?.get_connection_manager().await?;
    let store =
        RedisStore::<String>::with_prefix(conn, format!("grantry-test:{}:", Uuid::new_v4()));
    conformance::check_core(&store, "alice".into(), "bob".into()).await;
    conformance::check_issued_grants(&store, "alice".into()).await;
    conformance::check_devices(&store, "alice".into()).await;
    Ok(())
}
