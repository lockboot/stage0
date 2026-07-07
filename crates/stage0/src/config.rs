// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `_stage1` metadata schema.
//!
//! Mirrors `stage1`'s per-arch `{url, sha256}` structure (plus optional `args`)
//! but under a distinct `_stage1` key, so a UEFI payload is never confused with
//! a Linux `_stage2` binary in the same document.
//!
//! `args` (and the signed `args_url`) set the booted EFI program's UEFI *LoadOptions* --
//! the generic way stage0 parameterizes whatever EFI image it chain-loads. They are
//! sourced ONLY from this metadata (or the signed URL); stage0 never forwards its own
//! firmware/shell invocation arguments to stage1. For a Linux UKI stage1 specifically,
//! the kernel command line is baked into the signed, measured UKI and is authoritative:
//! under Secure Boot the stub ignores LoadOptions, so `_stage1.args` cannot alter the UKI
//! cmdline (operator config for a UKI flows through `_stage2`, not the kernel cmdline).
//! A non-UKI EFI stage1 is free to read these LoadOptions as its arguments.

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
    /// Inline UEFI LoadOptions for the booted stage1 EFI image (a non-UKI stage1 reads
    /// these as its args). Overridden by the signed `args_url`. See the module docs for
    /// how a Linux UKI treats these (baked cmdline wins; ignored under Secure Boot).
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
    pub url: UrlList,
    // Exactly one of these selects the verification mode (see `verify`):
    //   sha256  → pin an exact hash (immutable payload).
    //   ed25519 → pin a long-term release pubkey (base64); the payload may roll
    //             forward without editing metadata, gated by a detached `.sig`.
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub ed25519: Option<String>,
    /// Where the detached ed25519 signature lives (signed mode). Any `{sha256}`
    /// is replaced with the payload's hex digest, so the signature can be
    /// content-addressed. Defaults to `<url>.sig` when omitted. String or list.
    #[serde(default)]
    pub sig_url: Option<UrlList>,
    /// Optional signed load options (ed25519 mode only). The args are fetched from
    /// `args_url` (with `{sha256}` substituted), and their detached signature from
    /// `args_sig_url` (with `{sha256}` substituted), or `<args_url>.sig` when that
    /// is omitted. The signature is verified against the same release key as the
    /// payload; the verified bytes are used verbatim as the payload's UEFI load
    /// options, overriding inline `args`. String or list.
    #[serde(default)]
    pub args_url: Option<UrlList>,
    #[serde(default)]
    pub args_sig_url: Option<UrlList>,
}

/// How stage0 admits the downloaded payload before measuring + loading it.
pub enum Verify {
    /// Payload's SHA-256 must equal this 64-hex string.
    Sha256(String),
    /// Detached ed25519 signature must verify against this base64-encoded 32-byte
    /// release public key. `sig_url` is where the payload signature is fetched from
    /// (or `None` to default to `<url>.sig`). `args_url`/`args_sig_url` optionally
    /// add signed load options verified against the same key. All `*_url` values
    /// still carry an unsubstituted `{sha256}`; the caller substitutes it.
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

impl ArchConfig {
    /// Validate the URL and the (single) verification field, returning the
    /// selected [`Verify`] mode.
    pub fn validate(&self) -> Result<Verify, &'static str> {
        // http:// only: stage0's TCP4 client speaks plain HTTP, TLS is not used
        // (integrity comes from the pin/signature, not the transport). Rejecting
        // https:// here turns an unfetchable URL into a clear config-time error
        // rather than a late download failure. Each field is a URL or a fallback list.
        let ok_url = |s: &str| s.starts_with("http://") && s.chars().all(|c| c.is_ascii_graphic());
        let ok_list = |l: &UrlList| !l.0.is_empty() && l.0.iter().all(|s| ok_url(s));
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
            (None, None) => Err("must specify one of sha256 / ed25519"),
            (Some(hex), None) => {
                // Signed args need the release key, which only signed mode pins.
                if self.args_url.is_some() {
                    return Err("args_url requires ed25519 signed mode");
                }
                if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("sha256 must be exactly 64 hex characters");
                }
                Ok(Verify::Sha256(hex.clone()))
            }
            (None, Some(pubkey)) => {
                // A raw ed25519 public key is 32 bytes.
                match STANDARD.decode(pubkey.trim()) {
                    Ok(bytes) if bytes.len() == 32 => Ok(Verify::Ed25519 {
                        pubkey: pubkey.clone(),
                        sig_url: self.sig_url.clone(),
                        args_url: self.args_url.clone(),
                        args_sig_url: self.args_sig_url.clone(),
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
