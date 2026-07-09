// SPDX-License-Identifier: MIT OR Apache-2.0

//! `stage0-sign` — a small standalone host-side signer for stage0's release / test artifacts.
//!
//! Generates ed25519 keys and produces **domain-separated** detached signatures that stage0's
//! `sig.rs` admission check accepts: the signature is over `sha256(domain_tag) || sha256(message)`.
//! It lives in this repo (rather than reusing stage1's `deploy`) so stage0 builds and tests
//! standalone; the framing is duplicated from `crates/stage0/src/sig.rs` and pinned to stage1's
//! signer byte-for-byte by the golden known-answer test below. No `getrandom`/`libc`/`rand` —
//! randomness is `/dev/urandom` via `std`, so it builds with no C toolchain on the host.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use ed25519_compact::{KeyPair, Seed};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A signing context — the `_stage1.*` roles stage0 admits. `tag()` must match stage1's namespace.
#[derive(Clone, Copy)]
enum Domain {
    Stage1Uki,
    Stage1Args,
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

impl std::str::FromStr for Domain {
    type Err = &'static str;
    fn from_str(s: &str) -> std::result::Result<Self, &'static str> {
        Ok(match s {
            "stage1.uki" => Domain::Stage1Uki,
            "stage1.args" => Domain::Stage1Args,
            "stage1.manifest" => Domain::Stage1Manifest,
            _ => return Err("unknown signing domain (want stage1.uki / stage1.args / stage1.manifest)"),
        })
    }
}

#[derive(Parser)]
#[command(name = "stage0-sign", version, about = "ed25519 keygen + domain-separated signatures for stage0 artifacts.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an ed25519 key (PKCS#8 PEM) and print its base64 public key.
    Keygen(KeygenArgs),
    /// Sign one file for a signing domain.
    Sign(SignArgs),
}

#[derive(Args)]
struct KeygenArgs {
    /// Write the ed25519 PKCS#8 PEM private key here (created mode 0600).
    #[arg(long)]
    out: PathBuf,
    /// Also write the base64 public key here (the value pinned in `ed25519` metadata fields).
    #[arg(long = "pub")]
    pub_out: Option<PathBuf>,
}

#[derive(Args)]
struct SignArgs {
    /// Signing domain: stage1.uki / stage1.args / stage1.manifest.
    #[arg(long)]
    domain: String,
    /// ed25519 PKCS#8 PEM private key.
    #[arg(long)]
    key: PathBuf,
    /// File to sign.
    #[arg(long = "in")]
    input: PathBuf,
    /// Write the detached signature here.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen(a) => keygen(a),
        Cmd::Sign(a) => sign_cmd(a),
    }
}

fn keygen(a: KeygenArgs) -> Result<()> {
    let seed = random_seed()?;
    let pubkey = STANDARD.encode(*KeyPair::from_seed(Seed::new(seed)).pk);
    write_private(&a.out, pem_from_seed(&seed).as_bytes())?;
    if let Some(p) = &a.pub_out {
        std::fs::write(p, &pubkey).with_context(|| format!("writing {}", p.display()))?;
    }
    println!("wrote {} (ed25519 private key, mode 0600)", a.out.display());
    println!("pubkey: {pubkey}");
    Ok(())
}

fn sign_cmd(a: SignArgs) -> Result<()> {
    let domain: Domain = a.domain.parse().map_err(|e| anyhow!("--domain {}: {e}", a.domain))?;
    let pem = std::fs::read_to_string(&a.key).with_context(|| format!("reading key {}", a.key.display()))?;
    let bytes = std::fs::read(&a.input).with_context(|| format!("reading {}", a.input.display()))?;
    let (sig, pubkey) = sign_bytes(&pem, domain, &bytes)?;
    std::fs::write(&a.out, &sig).with_context(|| format!("writing {}", a.out.display()))?;
    println!("signed {} [{}] -> {} (pubkey {})", a.input.display(), domain.tag(), a.out.display(), pubkey);
    Ok(())
}

/// The 64-byte signed preimage `sha256(domain_tag) || sha256(message)` (must match `sig.rs`).
fn preimage(domain: Domain, message: &[u8]) -> [u8; 64] {
    let dom: [u8; 32] = Sha256::digest(domain.tag().as_bytes()).into();
    let msg: [u8; 32] = Sha256::digest(message).into();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&dom);
    out[32..].copy_from_slice(&msg);
    out
}

/// Sign `message` for `domain` with the PKCS#8 PEM `pem`; returns (signature, base64 pubkey).
fn sign_bytes(pem: &str, domain: Domain, message: &[u8]) -> Result<(Vec<u8>, String)> {
    let seed = seed_from_pkcs8_pem(pem)?;
    let kp = KeyPair::from_seed(Seed::new(seed));
    let sig = kp.sk.sign(preimage(domain, message), None);
    Ok((sig.to_vec(), STANDARD.encode(*kp.pk)))
}

/// Extract the 32-byte ed25519 seed from a PKCS#8 PEM (RFC 8410): `... 04 22 04 20 <seed>`.
fn seed_from_pkcs8_pem(pem: &str) -> Result<[u8; 32]> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().concat();
    let der = STANDARD.decode(b64.trim()).context("private key PEM body is not valid base64")?;
    let pos = der
        .windows(4)
        .position(|w| w == [0x04u8, 0x22, 0x04, 0x20])
        .ok_or_else(|| anyhow!("not a PKCS#8 Ed25519 private key (expected 04 22 04 20 marker)"))?;
    let start = pos + 4;
    if start + 32 > der.len() {
        bail!("truncated ed25519 private key");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[start..start + 32]);
    Ok(seed)
}

/// Build the PKCS#8 (RFC 8410) PEM `openssl genpkey` emits, inverse of `seed_from_pkcs8_pem`.
fn pem_from_seed(seed: &[u8; 32]) -> String {
    let mut der: Vec<u8> = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(&der))
}

/// 32 CSPRNG bytes from the kernel via `/dev/urandom` (std only — no getrandom/libc/C toolchain).
fn random_seed() -> Result<[u8; 32]> {
    use std::io::Read;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut seed)
        .context("read /dev/urandom")?;
    Ok(seed)
}

/// Write `bytes` to `path`, creating it mode 0600 (private key material).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-repo wire-contract anchor: this exact (key, domain, message) -> signature must equal
    /// stage1's ed25519-sign golden vector, so stage0-sign's signatures verify in stage0 and
    /// vice-versa for the shared `stage1.*` roles. Drift in either repo's framing fails CI.
    #[test]
    fn golden_kat() {
        let (sig, pubkey) =
            sign_bytes(&pem_from_seed(&[7u8; 32]), Domain::Stage1Manifest, b"lockboot-kat").unwrap();
        assert_eq!(pubkey, "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=");
        assert_eq!(
            STANDARD.encode(&sig),
            "nVZgjXp9d4zjnj9axtTQALlMADGqGKPTnR6RjMr8h8nI3wNpsBy0M4ZBjVfjlLKRZTN0pH3AAsGJqU0tJRTQDA=="
        );
    }
}
