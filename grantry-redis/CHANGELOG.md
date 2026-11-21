# Changelog

## [0.2.1](https://github.com/factorial-io/grantry/compare/grantry-redis-v0.2.0...grantry-redis-v0.2.1) (2026-11-21)


### Bug Fixes

* return an error instead of panicking on out-of-range expiries ([0a28f24](https://github.com/factorial-io/grantry/commit/0a28f24ae24005f2cda3c2d9b3ec9b3c0b17a75a)), closes [#48](https://github.com/factorial-io/grantry/issues/48)


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * grantry bumped from 0.6.0 to 0.6.1
  * dev-dependencies
    * grantry bumped from 0.6.0 to 0.6.1

## [0.2.0](https://github.com/factorial-io/grantry/compare/grantry-redis-v0.1.0...grantry-redis-v0.2.0) (2026-11-20)


### ⚠ BREAKING CHANGES

* public time types are now jiff::Timestamp and

### Features

* replace chrono with jiff in the public API ([a9d5012](https://github.com/factorial-io/grantry/commit/a9d5012fb7a5b8131a39f2a901154521dadba984)), closes [#45](https://github.com/factorial-io/grantry/issues/45)


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * grantry bumped from 0.5.0 to 0.6.0
  * dev-dependencies
    * grantry bumped from 0.5.0 to 0.6.0

## 0.1.0 (2026-11-09)


### Features

* add grantry-redis, a Redis / Valkey OAuthStore ([a56ae2e](https://github.com/factorial-io/grantry/commit/a56ae2e4a659a7793014c6c988f0e21249a2e3b1))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * grantry bumped from 0.4 to 0.5.0
  * dev-dependencies
    * grantry bumped from 0.4 to 0.5.0
