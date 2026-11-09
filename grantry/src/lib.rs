// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! OAuth 2.1 authorization server building blocks for Rust web apps and MCP
//! servers.
//!
//! grantry holds the protocol rules; the host application keeps storage,
//! users, consent screens and audit. The host implements four ports:
//!
//! - [`store::OAuthStore`]: clients, the metadata-document cache, pending
//!   authorizations, codes, grants and refresh tokens ([`memory::MemoryStore`]
//!   for tests, the `grantry-redis` crate for Redis / Valkey);
//! - [`store::Subjects`]: re-checks the user on every token issue and adds the
//!   app's own claims to the access token;
//! - [`store::Events`]: grant created / revoked, for audit;
//! - [`client::MetadataFetcher`]: fetches Client ID Metadata Documents under
//!   the host's egress policy (`client-fetch` has a plain reqwest one;
//!   [`client::NoFetch`] refuses all, for hosts without metadata documents).
//!
//! [`server::Server`] runs the flows over those ports: [`server::Server::authorize`],
//! [`server::Server::approve`] / [`server::Server::deny`] (called from the
//! host's consent page), [`server::Server::register`],
//! [`server::Server::exchange_code`], [`server::Server::refresh`] and
//! [`server::Server::verify`] / [`server::Server::verify_active`]. The device
//! authorization grant (RFC 8628) runs on the same server: [`server::Server::start_device`], the host's
//! verification page with [`server::Server::approve_device`] /
//! [`server::Server::deny_device`], and [`server::Server::poll_device`]; its
//! rules are [`device`]. The pure rules are usable on their own:
//! [`pkce`], [`redirect`], [`scope`], [`request`], [`token`], [`metadata`].
//!
//! The `axum` feature mounts the protocol routes (the `routes` module).

pub mod client;
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod device;
pub mod memory;
pub mod metadata;
pub mod pkce;
pub mod redirect;
pub mod request;
pub mod scope;
pub mod server;
pub mod store;
pub mod token;

#[cfg(feature = "axum")]
pub mod routes;

pub use client::{Client, ClientError, MetadataFetcher, NoFetch};
/// The JWT signing algorithm [`Signer`] takes, re-exported so hosts need not
/// depend on `jsonwebtoken` directly.
pub use jsonwebtoken::Algorithm;
pub use scope::ScopeSpec;
pub use server::{ActiveError, Config, PollError, Server, TokenError};
pub use store::{BackendError, Events, Grant, NoEvents, OAuthStore, Recheck, Subjects};
pub use token::Signer;
