// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `_stage1` metadata schema.
//!
//! Mirrors `stage1`'s per-arch discriminated union but under a distinct `_stage1` key, so a UEFI
//! payload is never confused with a Linux `_stage2` binary in the same document. Each arch entry
//! is either a [`Payload`] (admit a UEFI binary now, by sha256 pin or ed25519-signed) or a
//! [`ManifestRef`] (fetch a signed manifest — itself a `_stage1` fragment — and resolve it).
//!
//! `args` (and the signed `args_url`) set the booted EFI program's UEFI *LoadOptions* -- the
//! generic way stage0 parameterizes whatever EFI image it chain-loads. They are sourced ONLY from
//! this metadata (or the signed URL / manifest); stage0 never forwards its own firmware/shell
//! invocation arguments to stage1. For a Linux UKI stage1 specifically, the kernel command line is
//! baked into the signed, measured UKI and is authoritative: under Secure Boot the stub ignores
//! LoadOptions, so `args` cannot alter the UKI cmdline (operator config for a UKI flows through
//! `_stage2`). A non-UKI EFI stage1 is free to read these LoadOptions as its arguments.

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
    // Exactly one of these is read per build (see `for_this_arch`); the other
    // is still deserialized so a single multi-arch document works everywhere.
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    #[serde(default)]
    pub aarch64: Option<ArchConfig>,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    #[serde(default)]
    pub x86_64: Option<ArchConfig>,
}

/// One architecture's admission entry: the discriminated union ([`Entry`]) plus the resolution
/// history accumulated by the manifest loop (used only for cycle detection — stage0 forwards no
/// doc, so the history is not surfaced anywhere).
#[derive(Debug, Deserialize)]
pub struct ArchConfig {
    #[serde(flatten)]
    pub entry: Entry,
    // Deserialized so a merged manifest fragment carrying this key round-trips, but stage0 never
    // reads it: it forwards no document (the UKI re-fetches its own metadata) and detects cycles
    // with a loop-local record. stage1 is where this history is surfaced (into the stdin doc).
    #[serde(default)]
    #[allow(dead_code)]
    pub resolved_manifests: Vec<ManifestRef>,
}

/// The per-arch discriminated union: a concrete payload to admit, or a signed manifest to resolve.
#[derive(Debug, Deserialize)]
pub enum Entry {
    #[serde(rename = "payload")]
    Payload(Payload),
    #[serde(rename = "manifest")]
    Manifest(ManifestRef),
}

/// A concrete payload admission. Exactly one of `sha256` (pin an exact hash) or `ed25519` (pin a
/// long-term release pubkey; the payload rolls forward gated by a detached `.sig`) selects the mode.
#[derive(Debug, Deserialize)]
pub struct Payload {
    pub url: UrlList,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub ed25519: Option<String>,
    /// Where the detached ed25519 signature lives (signed mode). `{sha256}` → payload digest.
    /// Defaults to `<url>.sig`. String or list.
    #[serde(default)]
    pub sig_url: Option<UrlList>,
    /// Inline UEFI LoadOptions (overridden by a verified `args_url`).
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Optional signed load options (ed25519 mode only): fetched from `args_url` (`{sha256}`
    /// substituted), verified against the same release key via `args_sig_url` (else `<args_url>.sig`),
    /// used verbatim as the payload's LoadOptions, overriding inline `args`. String or list.
    #[serde(default)]
    pub args_url: Option<UrlList>,
    #[serde(default)]
    pub args_sig_url: Option<UrlList>,
}

/// A pointer to a signed manifest (also a resolution-history record). The manifest is fetched from
/// `url`, its detached signature (`sig_url`, else `<url>.sig`) verified against the pinned `ed25519`
/// key, then deep-merged and re-evaluated. `sha256` optionally pins the manifest's own bytes.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestRef {
    pub url: UrlList,
    pub ed25519: String,
    #[serde(default)]
    pub sig_url: Option<UrlList>,
    #[serde(default)]
    pub sha256: Option<String>,
}

/// How stage0 admits a downloaded payload before measuring + loading it.
pub enum Admit {
    /// Payload's SHA-256 must equal this 64-hex string.
    Sha256(String),
    /// Detached ed25519 signature must verify against this base64 32-byte release key. `sig_url`
    /// is where the payload signature is fetched (or `None` → `<url>.sig`); `args_url`/`args_sig_url`
    /// optionally add signed load options. All `*_url` values still carry an unsubstituted `{sha256}`.
    Ed25519 {
        pubkey: String,
        sig_url: Option<UrlList>,
        args_url: Option<UrlList>,
        args_sig_url: Option<UrlList>,
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

// http:// only: stage0's TCP4 client speaks plain HTTP, TLS is not used (integrity comes from the
// pin/signature, not the transport). Rejecting https:// turns an unfetchable URL into a clear
// config-time error rather than a late download failure.
fn ok_url(s: &str) -> bool {
    s.starts_with("http://") && s.chars().all(|c| c.is_ascii_graphic())
}
fn ok_list(l: &UrlList) -> bool {
    !l.0.is_empty() && l.0.iter().all(|s| ok_url(s))
}
fn ok_sha256(hex: &str) -> bool {
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}
fn ok_pubkey(s: &str) -> Result<(), &'static str> {
    match STANDARD.decode(s.trim()) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        Ok(_) => Err("ed25519 pubkey must decode to 32 bytes"),
        Err(_) => Err("ed25519 pubkey must be base64"),
    }
}

impl Payload {
    /// Validate the URL(s) + the (single) verification field, returning the selected [`Admit`] mode.
    pub fn admission(&self) -> Result<Admit, &'static str> {
        if !ok_list(&self.url) {
            return Err("url must be a non-empty http:// URL (or list of them), printable ASCII (TLS unsupported)");
        }
        if self.sig_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("sig_url must be http:// URL(s), printable ASCII");
        }
        if self.args_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("args_url must be http:// URL(s), printable ASCII");
        }
        if self.args_sig_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("args_sig_url must be http:// URL(s), printable ASCII");
        }
        if self.args_sig_url.is_some() && self.args_url.is_none() {
            return Err("args_sig_url requires args_url");
        }
        match (&self.sha256, &self.ed25519) {
            (Some(_), Some(_)) => Err("specify only one of sha256 / ed25519"),
            (None, None) => Err("payload must specify one of sha256 / ed25519"),
            (Some(hex), None) => {
                if self.args_url.is_some() {
                    return Err("args_url requires ed25519 signed mode");
                }
                if !ok_sha256(hex) {
                    return Err("sha256 must be exactly 64 hex characters");
                }
                Ok(Admit::Sha256(hex.clone()))
            }
            (None, Some(pubkey)) => {
                ok_pubkey(pubkey)?;
                Ok(Admit::Ed25519 {
                    pubkey: pubkey.clone(),
                    sig_url: self.sig_url.clone(),
                    args_url: self.args_url.clone(),
                    args_sig_url: self.args_sig_url.clone(),
                })
            }
        }
    }
}

impl ManifestRef {
    /// Validate the manifest pointer (http-only).
    pub fn validate(&self) -> Result<(), &'static str> {
        if !ok_list(&self.url) {
            return Err("manifest url must be a non-empty http:// URL (or list), printable ASCII");
        }
        if self.sig_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("manifest sig_url must be http:// URL(s), printable ASCII");
        }
        if self.sha256.as_ref().is_some_and(|h| !ok_sha256(h)) {
            return Err("manifest sha256 must be exactly 64 hex characters");
        }
        ok_pubkey(&self.ed25519)
    }
}

/// Parse the user-data JSON into a [`UserData`].
pub fn parse(json: &[u8]) -> Result<UserData, &'static str> {
    serde_json::from_slice(json).map_err(|_| "invalid JSON or missing _stage1 key")
}
