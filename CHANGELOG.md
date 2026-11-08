# Changelog

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
