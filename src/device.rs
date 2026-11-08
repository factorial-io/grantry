// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The device authorization grant (RFC 8628): the pure rules. Codes, their
//! normalisation and the state machine a poll and a decision are judged by.
//! [`crate::Server`] runs the flow over them; the host's store keeps the rows
//! and decides who may see one (a tenant, say).
//!
//! Contributed from Fons (`fons-identity::device`), where these rules ran the
//! `fons-cli` login; ported verbatim with its tests, from `time` to `chrono`.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// RFC 8628 §6.1: no vowels (no words), no digits (no look-alikes).
pub const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Letters in a user code; shown as `XXXX-XXXX`.
pub const USER_CODE_LEN: usize = 8;

/// How long a device authorization lives, in seconds.
pub const DEVICE_TTL_SECS: i64 = 600;

/// The polling interval a client starts with, in seconds.
pub const POLL_INTERVAL: u32 = 5;

/// What one `slow_down` adds to the interval, in seconds (RFC 8628 §3.5).
pub const SLOW_DOWN_STEP: u32 = 5;

/// How many user codes [`crate::Server::start_device`] draws before giving
/// up on finding a free one.
pub const USER_CODE_ATTEMPTS: usize = 5;

/// The longest `client_name` kept for display, in characters.
pub const CLIENT_NAME_MAX: usize = 100;

/// A user code from random `bytes` by rejection sampling: a byte below 240 (=
/// 12 × 20) maps uniformly onto the alphabet, the rest are skipped. `None`
/// when `bytes` holds fewer than eight usable values.
pub fn user_code_from(bytes: &[u8]) -> Option<String> {
    let letters: Vec<u8> = bytes
        .iter()
        .filter(|&&b| b < 240)
        .map(|&b| USER_CODE_ALPHABET[usize::from(b % 20)])
        .take(USER_CODE_LEN)
        .collect();
    (letters.len() == USER_CODE_LEN).then(|| display(&letters))
}

/// A fresh user code.
pub fn generate_user_code() -> String {
    loop {
        // 32 bytes leave 24 to spare; needing another draw is ~1e-14.
        if let Some(code) = user_code_from(&rand::random::<[u8; 32]>()) {
            return code;
        }
    }
}

fn display(letters: &[u8]) -> String {
    let (a, b) = letters.split_at(USER_CODE_LEN / 2);
    format!(
        "{}-{}",
        String::from_utf8_lossy(a),
        String::from_utf8_lossy(b)
    )
}

/// What a person typed, as the stored `XXXX-XXXX`: case and a dash or spaces
/// do not matter, anything else does. `None` for a value that cannot be a user
/// code, so it is refused without a lookup.
pub fn normalize_user_code(input: &str) -> Option<String> {
    let letters: Vec<u8> = input
        .bytes()
        .filter(|b| *b != b'-' && !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    (letters.len() == USER_CODE_LEN && letters.iter().all(|b| USER_CODE_ALPHABET.contains(b)))
        .then(|| display(&letters))
}

/// `client_name` as stored: trimmed, at most [`CLIENT_NAME_MAX`] characters.
pub fn client_name(raw: &str) -> String {
    raw.trim().chars().take(CLIENT_NAME_MAX).collect()
}

/// The lifecycle of a device authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Waiting for the person.
    Pending,
    /// Approved, tokens not yet collected.
    Approved,
    /// Refused by the person. Final.
    Denied,
    /// Tokens issued. Final.
    Redeemed,
    /// Past its end before redemption. Final.
    Expired,
}

impl DeviceStatus {
    /// The stored spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
        }
    }
}

/// A stored status the enum does not know.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown device status `{0}`")]
pub struct UnknownStatus(pub String);

impl std::str::FromStr for DeviceStatus {
    type Err = UnknownStatus;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match text {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "denied" => Self::Denied,
            "redeemed" => Self::Redeemed,
            "expired" => Self::Expired,
            other => return Err(UnknownStatus(other.to_string())),
        })
    }
}

/// One stored device authorization, without its device-code hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device<S> {
    pub id: Uuid,
    pub client_id: String,
    /// What the client said about itself ([`client_name`]).
    pub client_name: String,
    /// The canonical scope string the grant will carry.
    pub scope: String,
    /// `XXXX-XXXX`.
    pub user_code: String,
    /// The stored state; [`Self::status_at`] is the one to act on.
    pub status: DeviceStatus,
    /// The current polling interval in seconds.
    pub interval_seconds: u32,
    /// The previous poll.
    pub last_polled_at: Option<DateTime<Utc>>,
    /// Who approved or denied it.
    pub subject: Option<S>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl<S> Device<S> {
    /// The state at `now`: a `pending` or `approved` authorization past its
    /// end reads as `expired` whether or not anything has written that yet.
    pub fn status_at(&self, now: DateTime<Utc>) -> DeviceStatus {
        match self.status {
            DeviceStatus::Pending | DeviceStatus::Approved if now >= self.expires_at => {
                DeviceStatus::Expired
            }
            status => status,
        }
    }
}

/// What a poll at a given moment comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// `authorization_pending`.
    Pending,
    /// `slow_down`; the authorization's interval becomes `interval`.
    SlowDown {
        /// The raised interval, in seconds.
        interval: u32,
    },
    /// `access_denied`.
    Denied,
    /// `expired_token`.
    Expired,
    /// Approved: issue the tokens now.
    Redeem,
    /// Already redeemed: `invalid_grant`, and no second grant.
    Redeemed,
}

/// Judges a poll of `device` at `now`. Pure.
///
/// Final states answer as they are however fast the client polls; only a
/// pending authorization is subject to `slow_down`, which is a variant of
/// `authorization_pending` (RFC 8628 §3.5).
pub fn judge_poll<S>(device: &Device<S>, now: DateTime<Utc>) -> Poll {
    match device.status_at(now) {
        DeviceStatus::Expired => Poll::Expired,
        DeviceStatus::Denied => Poll::Denied,
        DeviceStatus::Redeemed => Poll::Redeemed,
        DeviceStatus::Approved => Poll::Redeem,
        DeviceStatus::Pending => {
            let interval = Duration::seconds(i64::from(device.interval_seconds));
            match device.last_polled_at {
                Some(last) if now - last < interval => Poll::SlowDown {
                    interval: device.interval_seconds.saturating_add(SLOW_DOWN_STEP),
                },
                _ => Poll::Pending,
            }
        }
    }
}

/// Whether the person may still approve or deny `device` at `now`: only while
/// it is pending.
pub fn decidable<S>(device: &Device<S>, now: DateTime<Utc>) -> bool {
    device.status_at(now) == DeviceStatus::Pending
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).expect("timestamp")
    }

    fn pending() -> Device<&'static str> {
        Device {
            id: Uuid::new_v4(),
            client_id: "cli".into(),
            client_name: "cli on host".into(),
            scope: "read offline_access".into(),
            user_code: "WDJB-MJHT".into(),
            status: DeviceStatus::Pending,
            interval_seconds: POLL_INTERVAL,
            last_polled_at: None,
            subject: None,
            created_at: t0(),
            expires_at: t0() + Duration::minutes(10),
        }
    }

    #[test]
    fn user_codes_avoid_ambiguous_characters() {
        for _ in 0..2000 {
            let code = generate_user_code();
            assert_eq!(code.len(), 9, "{code}");
            assert_eq!(code.as_bytes()[4], b'-', "{code}");
            for b in code.bytes().filter(|b| *b != b'-') {
                assert!(USER_CODE_ALPHABET.contains(&b), "{code}");
                assert!(!b"AEIOUY".contains(&b), "no vowel: {code}");
                assert!(!b.is_ascii_digit() && !b.is_ascii_lowercase(), "{code}");
            }
            assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
        }
    }

    /// Rejection sampling: bytes 240..=255 would bias the first 16 letters.
    #[test]
    fn user_code_sampling_skips_biased_bytes() {
        let mut bytes = vec![255u8, 240, 250];
        bytes.extend(0..8);
        assert_eq!(user_code_from(&bytes).as_deref(), Some("BCDF-GHJK"));
        assert_eq!(user_code_from(&[255; 32]), None);
        assert_eq!(
            user_code_from(&[19, 39, 59, 79, 99, 119, 139, 159]).as_deref(),
            Some("ZZZZ-ZZZZ")
        );
    }

    /// Fons's golden user code (`fons-identity::golden`), from the same bytes.
    #[test]
    fn fons_golden_user_code() {
        let bytes = [0, 19, 20, 239, 240, 255, 100, 7, 13, 57, 200, 1];
        assert_eq!(user_code_from(&bytes).as_deref(), Some("BZBZ-BKRW"));
        assert_eq!(
            normalize_user_code(" bzbz bkrw ").as_deref(),
            Some("BZBZ-BKRW")
        );
        assert_eq!(normalize_user_code("BZBZ-BKRA"), None, "a vowel");
    }

    #[test]
    fn typed_codes_normalise() {
        assert_eq!(
            normalize_user_code("wdjb-mjht").as_deref(),
            Some("WDJB-MJHT")
        );
        assert_eq!(
            normalize_user_code(" WDJB MJHT ").as_deref(),
            Some("WDJB-MJHT")
        );
        assert_eq!(
            normalize_user_code("WDJBMJHT").as_deref(),
            Some("WDJB-MJHT")
        );
        assert_eq!(normalize_user_code("WDJB-MJH"), None, "too short");
        assert_eq!(normalize_user_code("WDJB-MJHA"), None, "a vowel");
        assert_eq!(normalize_user_code("WDJB-MJH1"), None, "a digit");
        assert_eq!(normalize_user_code("WDJB/MJHT"), None, "a stray character");
    }

    #[test]
    fn client_names_are_capped_at_100_characters() {
        assert_eq!(client_name("  fons-cli on host "), "fons-cli on host");
        let long = "ä".repeat(150);
        assert_eq!(client_name(&long).chars().count(), 100);
    }

    /// Ten minutes after creation a pending (or approved but uncollected)
    /// authorization polls as expired and can no longer be decided.
    #[test]
    fn expiry() {
        let device = pending();
        let ten = t0() + Duration::minutes(10);
        assert_eq!(
            judge_poll(&device, ten - Duration::seconds(1)),
            Poll::Pending
        );
        assert_eq!(judge_poll(&device, ten), Poll::Expired);
        assert!(decidable(&device, ten - Duration::seconds(1)));
        assert!(!decidable(&device, ten), "approving it fails");

        let approved = Device {
            status: DeviceStatus::Approved,
            ..pending()
        };
        assert_eq!(judge_poll(&approved, ten), Poll::Expired);
        let denied = Device {
            status: DeviceStatus::Denied,
            ..pending()
        };
        assert_eq!(
            judge_poll(&denied, ten),
            Poll::Denied,
            "denied stays denied"
        );
    }

    #[test]
    fn single_redemption() {
        let approved = Device {
            status: DeviceStatus::Approved,
            ..pending()
        };
        assert_eq!(judge_poll(&approved, t0()), Poll::Redeem);
        let redeemed = Device {
            status: DeviceStatus::Redeemed,
            ..approved
        };
        assert_eq!(judge_poll(&redeemed, t0()), Poll::Redeemed);
        assert_eq!(
            judge_poll(&redeemed, t0() + Duration::hours(1)),
            Poll::Redeemed,
            "redeemed never turns into expired"
        );
        assert!(!decidable(&redeemed, t0()));
    }

    #[test]
    fn polling_within_the_interval_slows_down() {
        let mut device = pending();
        device.last_polled_at = Some(t0());
        assert_eq!(
            judge_poll(&device, t0() + Duration::seconds(4)),
            Poll::SlowDown { interval: 10 }
        );
        assert_eq!(
            judge_poll(&device, t0() + Duration::seconds(5)),
            Poll::Pending
        );
        device.status = DeviceStatus::Approved;
        assert_eq!(
            judge_poll(&device, t0() + Duration::seconds(1)),
            Poll::Redeem,
            "a final answer is not held back"
        );
    }

    #[test]
    fn decided_codes_cannot_be_decided_again() {
        for status in [
            DeviceStatus::Approved,
            DeviceStatus::Denied,
            DeviceStatus::Expired,
        ] {
            let device = Device {
                status,
                ..pending()
            };
            assert!(!decidable(&device, t0()), "{status:?}");
        }
    }

    #[test]
    fn statuses_round_trip() {
        for s in [
            DeviceStatus::Pending,
            DeviceStatus::Approved,
            DeviceStatus::Denied,
            DeviceStatus::Redeemed,
            DeviceStatus::Expired,
        ] {
            assert_eq!(s.as_str().parse::<DeviceStatus>(), Ok(s));
        }
        assert!("nope".parse::<DeviceStatus>().is_err());
    }
}
