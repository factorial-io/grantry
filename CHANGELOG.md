# Changelog

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
