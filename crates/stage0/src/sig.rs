// SPDX-License-Identifier: MIT OR Apache-2.0

//! ed25519 admission control for "signed mode" payloads.
//!
//! In signed mode the metadata pins a long-term **release public key** (32-byte ed25519, base64)
//! instead of an exact SHA-256. The payload at the URL is whatever the latest signed build is;
//! stage0 fetches a detached signature (`<url>.sig`, 64 raw bytes) and verifies it against the
//! pinned key before loading. This lets a release roll forward without editing VM metadata.
//!
//! Signatures are **domain-separated**: the ed25519 signature is over a fixed 64-byte preimage
//! `sha256(domain_tag) || sha256(message)`, so a signature minted for one role can never be reused
//! in another. This must match the signer byte-for-byte (github.com/lockboot/stage1,
//! crates/ed25519-sign + the `stage0-sign` CLI in this repo). stage0 only verifies the `stage1.*`
//! roles; the shared golden vector lives in `stage0-sign`'s tests.
//!
//! The signature is *admission control only*: it is not measured, and the key is not measured.
//! The attestation surface stays minimal: PCR 14 records the SHA-256 of whatever binary ran.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_compact::{PublicKey, Signature};
use sha2::{Digest, Sha256};

/// A signing context — the domain-separation namespace. stage0 admits only the `stage1.*` roles.
/// Wire constants; must match the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// `_stage1` payload (the UKI).
    Stage1Uki,
    /// `_stage1` LoadOptions (signed args).
    Stage1Args,
    /// `_stage1` signed manifest.
    Stage1Manifest,
}

impl Domain {
    fn tag(self) -> &'static str {
        match self {
            Domain::Stage1Uki => "lockboot.v1.stage1.uki",
            Domain::Stage1Args => "lockboot.v1.stage1.args",
            Domain::Stage1Manifest => "lockboot.v1.stage1.manifest",
        }
    }
}

/// The 64-byte signed preimage `sha256(domain_tag) || sha256(message)` (must match the signer).
fn preimage(domain: Domain, message: &[u8]) -> [u8; 64] {
    let dom: [u8; 32] = Sha256::digest(domain.tag().as_bytes()).into();
    let msg: [u8; 32] = Sha256::digest(message).into();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&dom);
    out[32..].copy_from_slice(&msg);
    out
}

/// Verify a detached ed25519 `signature` for `domain` over `message` against the base64
/// `pubkey_b64` pinned in the metadata. Pass the raw `message` (the downloaded bytes); this hashes
/// it. Constant-work, needs no RNG.
pub fn verify(
    pubkey_b64: &str,
    domain: Domain,
    message: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    let key_bytes = STANDARD
        .decode(pubkey_b64.trim())
        .map_err(|_| "ed25519 pubkey is not valid base64")?;
    let public_key =
        PublicKey::from_slice(&key_bytes).map_err(|_| "ed25519 pubkey wrong length")?;
    let signature =
        Signature::from_slice(signature).map_err(|_| "ed25519 signature wrong length")?;
    public_key
        .verify(preimage(domain, message), &signature)
        .map_err(|_| "ed25519 signature verification failed")
}
