// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The in-memory store against the `OAuthStore` contract checks.

use grantry::conformance;
use grantry::memory::MemoryStore;

#[tokio::test]
async fn memory_store_conforms() {
    let store = MemoryStore::<String>::default();
    conformance::check_core(&store, "alice".into(), "bob".into()).await;
    conformance::check_issued_grants(&store, "alice".into()).await;
    conformance::check_devices(&store, "alice".into()).await;
}
