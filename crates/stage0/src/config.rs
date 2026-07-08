// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `_stage1` metadata schema.
//!
//! Mirrors `stage1`'s per-arch admission structure under a distinct `_stage1` key, so a
//! UEFI payload is never confused with a Linux `_stage2` binary in the same document.
//!
//! Two admission modes per arch entry:
//!   - **sha256** -- pin an exact hash inline (`url` + `sha256` in the trusted user-data;
//!     static payload).
//!   - **ed25519** -- pin a release pubkey + a `manifest_url`. stage0 fetches a signed
//!     **manifest** (`{ url, sha256, args, version }`), verifies it against the pinned key,
//!     then admits the payload by the manifest's exact `sha256`. Binding the payload (and its
//!     args) under ONE signature means a hostile mirror can neither mix-and-match
//!     independently-signed pieces nor swap the payload, while the release still rolls forward
//!     by re-signing a new manifest (the user-data is unchanged).
//!
//! `args` (inline, or from the signed manifest) set the booted EFI program's UEFI *LoadOptions*
//! -- the generic way stage0 parameterizes whatever EFI image it chain-loads. stage0 never
//! forwards its own firmware/shell invocation arguments to stage1. For a Linux UKI stage1 the
//! kernel command line is baked into the signed, measured UKI and is authoritative: under Secure
//! Boot the stub ignores LoadOptions, so these do not alter the UKI cmdline (operator config for
//! a UKI flows through `_stage2`). A non-UKI EFI stage1 may read these LoadOptions as its args.

use alloc::string::String;
use alloc::vec::Vec;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

/// One URL, or a fallback list tried in order (mirror resiliency). Deserializes from a
/// JSON string or an array of strings. stage0 is http-only (no TLS); trying mirrors is
/// safe because the payload is cryptographically pinned, so bytes from any URL must verify.
#[derive(Debug, Clone)]
pub struct UrlList(pub Vec<String>);

impl<'de> Deserialize<'de> for UrlList {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        Ok(match OneOrMany::deserialize(d)? {
            OneOrMany::One(s) => UrlList(alloc::vec![s]),
            OneOrMany::Many(v) => UrlList(v),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct UserData {
    #[serde(rename = "_stage1")]
    pub stage1: Stage1Config,
}

#[derive(Debug, Deserialize)]
pub struct Stage1Config {
    /// Inline UEFI LoadOptions for the booted stage1 EFI image (sha256 mode; a non-UKI
    /// stage1 reads these as its args). In ed25519 mode the signed manifest's `args` take
    /// precedence. See the module docs for how a Linux UKI treats these.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    // Exactly one of these is read per build (see `for_this_arch`); the other
    // is still deserialized so a single multi-arch document works everywhere.
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    #[serde(default)]
    pub aarch64: Option<ArchConfig>,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    #[serde(default)]
    pub x86_64: Option<ArchConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ArchConfig {
    /// Payload URL(s) for **sha256 mode** (the payload is pinned inline). In ed25519 mode the
    /// payload URL comes from the signed manifest instead, so this is unused there.
    #[serde(default)]
    pub url: Option<UrlList>,
    /// sha256 mode: the payload's exact 64-hex digest (immutable payload).
    #[serde(default)]
    pub sha256: Option<String>,
    /// ed25519 mode: a base64 32-byte release pubkey. The payload rolls forward via a signed
    /// manifest at `manifest_url` (no metadata edits per update).
    #[serde(default)]
    pub ed25519: Option<String>,
    /// ed25519 mode: where the signed manifest is fetched from (string or fallback list).
    #[serde(default)]
    pub manifest_url: Option<UrlList>,
    /// ed25519 mode: where the manifest's detached signature is fetched from. Any `{sha256}`
    /// is replaced with the **retrieved manifest's** hex digest (content-addressed), so the
    /// signature can be co-located per mirror. Defaults to `<manifest_url>.sig`. String or list.
    #[serde(default)]
    pub manifest_sig_url: Option<UrlList>,
}

/// The signed release manifest (ed25519 mode). Fetched from `manifest_url` and verified against
/// the pinned release key; the payload is then admitted by its `sha256`.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    /// Payload URL(s) (mirror list). `{sha256}` is replaced with `sha256` below.
    pub url: UrlList,
    /// The payload's exact 64-hex digest.
    pub sha256: String,
    /// Args handed to the payload (LoadOptions for stage0's EFI child).
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Monotonic release version (anti-rollback hint; enforcement is future work).
    #[serde(default)]
    pub version: u64,
}

/// How stage0 admits the payload before measuring + loading it.
pub enum Verify {
    /// sha256 mode: the payload (from `ArchConfig::url`) must hash to this 64-hex string.
    Sha256(String),
    /// ed25519 mode: fetch the manifest from `manifest_url`, verify its detached signature
    /// (from `manifest_sig_url`, `{sha256}` -> manifest hash, else `<manifest_url>.sig`)
    /// against `pubkey`, then admit the payload by the manifest's `sha256`.
    Ed25519 {
        pubkey: String,
        manifest_url: UrlList,
        manifest_sig_url: Option<UrlList>,
    },
}

impl Stage1Config {
    /// The config entry for the architecture stage0 was built for.
    #[must_use]
    pub fn for_this_arch(&self) -> Option<&ArchConfig> {
        #[cfg(target_arch = "x86_64")]
        {
            self.x86_64.as_ref()
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.aarch64.as_ref()
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            None
        }
    }
}

// http:// only: stage0's TCP4 client speaks plain HTTP, TLS is not used (integrity comes from
// the pin/signature, not the transport). Rejecting https:// turns an unfetchable URL into a
// clear config-time error rather than a late download failure.
fn ok_url(s: &str) -> bool {
    s.starts_with("http://") && s.chars().all(|c| c.is_ascii_graphic())
}
fn ok_list(l: &UrlList) -> bool {
    !l.0.is_empty() && l.0.iter().all(|s| ok_url(s))
}
fn ok_sha256(hex: &str) -> bool {
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

impl Manifest {
    /// Parse + validate a fetched manifest (called after its signature is verified).
    pub fn parse(json: &[u8]) -> Result<Manifest, &'static str> {
        let m: Manifest = serde_json::from_slice(json).map_err(|_| "manifest is not valid JSON")?;
        if !ok_list(&m.url) {
            return Err("manifest url must be a non-empty http:// URL (or list), printable ASCII");
        }
        if !ok_sha256(&m.sha256) {
            return Err("manifest sha256 must be exactly 64 hex characters");
        }
        Ok(m)
    }
}

impl ArchConfig {
    /// Validate the arch entry and return the selected [`Verify`] mode.
    pub fn validate(&self) -> Result<Verify, &'static str> {
        if self.manifest_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("manifest_url must be http:// URL(s), printable ASCII");
        }
        if self.manifest_sig_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("manifest_sig_url must be http:// URL(s), printable ASCII");
        }
        if self.manifest_sig_url.is_some() && self.manifest_url.is_none() {
            return Err("manifest_sig_url requires manifest_url");
        }
        match (&self.sha256, &self.ed25519) {
            (Some(_), Some(_)) => Err("specify only one of sha256 / ed25519"),
            (None, None) => Err("must specify one of sha256 / ed25519"),
            (Some(hex), None) => {
                // sha256 (static) mode: the payload is pinned inline and fetched from `url`.
                if self.manifest_url.is_some() {
                    return Err("manifest_url requires ed25519 signed mode");
                }
                let url = self.url.as_ref().ok_or("sha256 mode requires url")?;
                if !ok_list(url) {
                    return Err("url must be a non-empty http:// URL (or list), printable ASCII (TLS unsupported)");
                }
                if !ok_sha256(hex) {
                    return Err("sha256 must be exactly 64 hex characters");
                }
                Ok(Verify::Sha256(hex.clone()))
            }
            (None, Some(pubkey)) => {
                // ed25519 (roll-forward) mode: a signed manifest pins the payload.
                let manifest_url = self
                    .manifest_url
                    .clone()
                    .ok_or("ed25519 mode requires manifest_url")?;
                match STANDARD.decode(pubkey.trim()) {
                    Ok(bytes) if bytes.len() == 32 => Ok(Verify::Ed25519 {
                        pubkey: pubkey.clone(),
                        manifest_url,
                        manifest_sig_url: self.manifest_sig_url.clone(),
                    }),
                    Ok(_) => Err("ed25519 pubkey must decode to 32 bytes"),
                    Err(_) => Err("ed25519 pubkey must be base64"),
                }
            }
        }
    }
}

/// Parse the user-data JSON into a [`UserData`].
pub fn parse(json: &[u8]) -> Result<UserData, &'static str> {
    serde_json::from_slice(json).map_err(|_| "invalid JSON or missing _stage1 key")
}
