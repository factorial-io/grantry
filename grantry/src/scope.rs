// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Scopes as strings, checked against a set the app supplies. The app maps
//! approved strings to its own types at the edge.

/// A scope token the app does not know.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown scope `{0}`")]
pub struct UnknownScope(pub String);

/// The scopes an authorization server knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSpec {
    /// Every scope, in canonical order: the order scope strings are written in.
    pub known: Vec<String>,
    /// What a request that names no scope asks for. A grant stores the
    /// scopes it was approved with, so changing this never widens a grant.
    pub default: Vec<String>,
    /// The scope that earns a refresh token, usually `offline_access`.
    pub offline: String,
}

impl ScopeSpec {
    /// A spec from string slices.
    pub fn new(known: &[&str], default: &[&str], offline: &str) -> Self {
        let owned = |s: &[&str]| s.iter().map(ToString::to_string).collect();
        Self {
            known: owned(known),
            default: owned(default),
            offline: offline.to_string(),
        }
    }

    /// Parse a space-separated scope string. Duplicates collapse; an unknown
    /// token fails the whole string. Input order is kept.
    pub fn parse<'a>(&self, scope: &'a str) -> Result<Vec<&'a str>, UnknownScope> {
        let mut scopes = Vec::new();
        for token in scope.split_whitespace() {
            if !self.known.iter().any(|k| k == token) {
                return Err(UnknownScope(token.to_string()));
            }
            if !scopes.contains(&token) {
                scopes.push(token);
            }
        }
        Ok(scopes)
    }

    /// The canonical scope string of `scopes`: canonical order,
    /// space-separated; unknown ones are dropped.
    pub fn join<S: AsRef<str>>(&self, scopes: &[S]) -> String {
        self.known
            .iter()
            .filter(|k| scopes.iter().any(|s| s.as_ref() == k.as_str()))
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The default scope string.
    pub fn default_scope(&self) -> String {
        self.join(&self.default)
    }

    /// Whether `scope` (a stored scope string) includes the offline scope.
    pub fn is_offline(&self, scope: &str) -> bool {
        scope.split_whitespace().any(|s| s == self.offline)
    }

    /// The approved scope string: `kept`, when given, must be a non-empty
    /// subset of the `requested` scope string; `None` is a refusal.
    pub fn approved(&self, requested: &str, kept: Option<&[String]>) -> Option<String> {
        let Some(kept) = kept else {
            return Some(requested.to_owned());
        };
        let requested = scope_list(requested);
        let joined = kept.join(" ");
        self.parse(&joined)
            .ok()
            .filter(|scopes| !scopes.is_empty())
            .filter(|scopes| scopes.iter().all(|s| requested.contains(s)))
            .map(|scopes| self.join(&scopes))
    }
}

/// The scopes of a space-separated scope string.
pub fn scope_list(scope: &str) -> Vec<&str> {
    scope.split_whitespace().collect()
}

#[cfg(test)]
pub(crate) fn mcp() -> ScopeSpec {
    ScopeSpec::new(
        &["read", "write", "run", "delete", "offline_access"],
        &["read", "write", "run", "delete"],
        "offline_access",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_and_print_canonically() {
        let spec = mcp();
        assert_eq!(
            spec.join(&spec.parse("run offline_access read run").unwrap()),
            "read run offline_access"
        );
        assert_eq!(spec.parse("read admin"), Err(UnknownScope("admin".into())));
        assert_eq!(spec.default_scope(), "read write run delete");
        assert!(spec.is_offline("read offline_access"));
        assert!(!spec.is_offline("read"));
    }

    #[test]
    fn approved_scope_narrows_to_a_subset() {
        let spec = mcp();
        assert_eq!(spec.approved("a b", None).as_deref(), Some("a b"));
        assert_eq!(spec.approved("read", Some(&[])), None);
        assert_eq!(
            spec.approved("read run", Some(&["run".into()])).as_deref(),
            Some("run")
        );
        assert_eq!(spec.approved("read", Some(&["run".into()])), None);
        assert_eq!(spec.approved("read", Some(&["nope".into()])), None);
    }
}
