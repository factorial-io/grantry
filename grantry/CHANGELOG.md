# Changelog

## [0.5.0](https://github.com/factorial-io/grantry/compare/v0.4.0...v0.5.0) (2026-11-09)


### Features

* add conformance checks for OAuthStore implementations ([a5262a0](https://github.com/factorial-io/grantry/commit/a5262a03d0f8b8f81ee4be29e9323f00a25efb4f))
* **routes:** expose each endpoint as a MethodRouter so hosts can layer one ([a5262a0](https://github.com/factorial-io/grantry/commit/a5262a03d0f8b8f81ee4be29e9323f00a25efb4f))

## [0.4.0](https://github.com/factorial-io/grantry/compare/v0.3.1...v0.4.0) (2026-11-08)


### ⚠ BREAKING CHANGES

* **deps:** grantry no longer enables jsonwebtoken's rust_crypto feature. A host that uses jsonwebtoken 11 itself with RSA, EC or EdDSA keys must enable a backend feature on its own dependency and install that provider at startup, before grantry's first token, e.g. jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default(). HMAC-only hosts need no change.
* Server::issue_grant takes subject: impl Into\<S\> instead of &S; pass the subject by value (or clone it).
* Server::refresh(form, client_id: Option<&str>, ip) is now Server::refresh(refresh_token: &str, client_id: &str, ip), and no longer returns TokenError::InvalidRequest.
* Server::poll_device and Server::refresh return (Grant\<S\>, TokenResponse) instead of TokenResponse.
* **deps:** jsonwebtoken types in the public API are now from jsonwebtoken 11; Algorithm is non_exhaustive there.

### Features

* add Config::new with defaults for the lifetimes and documents ([e95a66e](https://github.com/factorial-io/grantry/commit/e95a66ef3eda47f43073b18e915cd811344b4f66)), closes [#30](https://github.com/factorial-io/grantry/issues/30)
* add PollError::description ([abb2e39](https://github.com/factorial-io/grantry/commit/abb2e39e858c4b8f444b6630cfd7c0b58be1fe92)), closes [#28](https://github.com/factorial-io/grantry/issues/28)
* add Server::revoke_token for logout ([0bb76cb](https://github.com/factorial-io/grantry/commit/0bb76cb567986e5a8cac349cad5e33d9ff798f52)), closes [#32](https://github.com/factorial-io/grantry/issues/32)
* add Server::verify_active returning the active grant ([b4631ca](https://github.com/factorial-io/grantry/commit/b4631caab368d55ea541ee4032935632109f7fc9)), closes [#24](https://github.com/factorial-io/grantry/issues/24)
* implement Debug for Server ([9f38359](https://github.com/factorial-io/grantry/commit/9f38359791e8878edb9fd0cbb39b266f0dacfba8)), closes [#26](https://github.com/factorial-io/grantry/issues/26)
* re-export the server's error types at the crate root ([d0faa48](https://github.com/factorial-io/grantry/commit/d0faa48a3dff2cf3f3bb027744ca6a54c3640223)), closes [#27](https://github.com/factorial-io/grantry/issues/27)
* return the grant from poll_device and refresh ([6c7f91c](https://github.com/factorial-io/grantry/commit/6c7f91c0a81f35428961da488a6497d891fe1015)), closes [#25](https://github.com/factorial-io/grantry/issues/25)
* take the issue_grant subject as impl Into&lt;S&gt; ([62b8c6e](https://github.com/factorial-io/grantry/commit/62b8c6e4e58a86b206af9ebccdd9ff1707cf6e38)), closes [#31](https://github.com/factorial-io/grantry/issues/31)
* take the refresh token and client id as plain arguments in refresh ([37ba650](https://github.com/factorial-io/grantry/commit/37ba650e485d4bc101b7c20e5e840fd2ed351283)), closes [#29](https://github.com/factorial-io/grantry/issues/29)


### Bug Fixes

* **deps:** sign with an HMAC-only jsonwebtoken crypto provider ([73a1233](https://github.com/factorial-io/grantry/commit/73a1233509dc20e6f770d77d0756310c2fa9e251)), closes [#33](https://github.com/factorial-io/grantry/issues/33)
* **deps:** update jsonwebtoken to 11 ([494c3e4](https://github.com/factorial-io/grantry/commit/494c3e43e8345e39276f6e8ee0373d5139badba6))

## [0.3.1](https://github.com/factorial-io/grantry/compare/v0.3.0...v0.3.1) (2026-11-08)


### Bug Fixes

* measure unused clients from their last use, not registration ([#21](https://github.com/factorial-io/grantry/issues/21)) ([ea1e9c1](https://github.com/factorial-io/grantry/commit/ea1e9c1abf130908b905111515138ae53ee8c44e)), closes [#19](https://github.com/factorial-io/grantry/issues/19)

## [0.3.0](https://github.com/factorial-io/grantry/compare/v0.2.0...v0.3.0) (2026-11-08)


### Features

* re-export Algorithm and NoEvents, add NoFetch metadata fetcher ([63af2b8](https://github.com/factorial-io/grantry/commit/63af2b80325e79ba490026caf32c67ede6cf1e6b))
* re-export Algorithm and NoEvents, add NoFetch metadata fetcher ([9ce34a2](https://github.com/factorial-io/grantry/commit/9ce34a213c8c03b8593ae10a800cb0baf74e80bd)), closes [#11](https://github.com/factorial-io/grantry/issues/11)
* sweep grants that ended more than GRANT_RETENTION_DAYS ago ([59cd50a](https://github.com/factorial-io/grantry/commit/59cd50a5c654bfc27fdb226eccb7bca9df43a005))
* sweep grants that ended more than GRANT_RETENTION_DAYS ago ([0aa5041](https://github.com/factorial-io/grantry/commit/0aa504100a1797d293dcd5d08bf1f621f532e888)), closes [#9](https://github.com/factorial-io/grantry/issues/9)


### Bug Fixes

* do not bind expired pending requests in claim_pending; document store contract ([80ec022](https://github.com/factorial-io/grantry/commit/80ec022379156e951b165da88a72f97a839bd53f))
* do not bind expired pending requests in claim_pending; document store contract ([f2e2d54](https://github.com/factorial-io/grantry/commit/f2e2d54163c4cc66cf0fc216a7c000b10fd7d50e)), closes [#10](https://github.com/factorial-io/grantry/issues/10)
* review follow-ups for [#12](https://github.com/factorial-io/grantry/issues/12), [#13](https://github.com/factorial-io/grantry/issues/13) and [#14](https://github.com/factorial-io/grantry/issues/14) ([#18](https://github.com/factorial-io/grantry/issues/18)) ([19050ac](https://github.com/factorial-io/grantry/commit/19050ac94365c3019b2b568944375ea6baa79453))

## [0.2.0](https://github.com/factorial-io/grantry/compare/v0.1.0-rc.1...v0.2.0) (2026-11-08)


### Features

* **device:** the device authorization grant (RFC 8628) on Server ([7dc6897](https://github.com/factorial-io/grantry/commit/7dc689713fdc3af03057df5407fd8f1cf47ad202))
* host-issued grants and the device authorization grant (RFC 8628) ([ace70bf](https://github.com/factorial-io/grantry/commit/ace70bfee90842bda35b05f5a3a38ea2ca930fd9))
* **server:** issue_grant for a subject the host authenticated ([fd7bbfe](https://github.com/factorial-io/grantry/commit/fd7bbfe059a1ff43b77136a27db0fb5bcca90a1e))
* **server:** refresh tokens expire after an idle lifetime ([d4464d8](https://github.com/factorial-io/grantry/commit/d4464d89c5f79241b9b21bf4dfc441128b854b3b))
* **token:** Signer::hmac over raw secret bytes and typed verify_as ([db42468](https://github.com/factorial-io/grantry/commit/db42468d07c1669eb04f88072f6d2a32a637efd3))
* **token:** TokenFormat lets the host mint codes and refresh tokens ([39d8c1a](https://github.com/factorial-io/grantry/commit/39d8c1afd439e103b0f12c939430dd6b41a4777c))


### Miscellaneous Chores

* release 0.2.0 ([fb23cb4](https://github.com/factorial-io/grantry/commit/fb23cb4687bed9c6985b12c2fecfe0ec666271b5))

## 0.1.0-rc.1 (2026-11-08)


### Features

* OAuth 2.1 authorization server extracted from flowdrop-rs ([281171f](https://github.com/factorial-io/grantry/commit/281171f8e6f245ae5a1441502b5bf638f7025358))
