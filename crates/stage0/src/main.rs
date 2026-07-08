// SPDX-License-Identifier: MIT OR Apache-2.0

//! stage0 - a measured UEFI network bootloader for the lockboot stack.
//!
//! Boots as a pure UEFI application (no Linux kernel), pulls a `_stage1`
//! user-data document from the cloud metadata service, downloads a UEFI payload
//! over raw `EFI_TCP4` (see `tcp4.rs`), admits it via one of two policies (a
//! pinned SHA-256, or an ed25519 signature against a pinned release key, see
//! `sig.rs`), measures it into the TPM via `EFI_TCG2_PROTOCOL` (PCR 14 =
//! SHA-256 of the loaded binary), then chain-loads it.
//!
//! The payload is loaded through a temporary security-arch override (`secauth.rs`)
//! rather than relying on the firmware `db`, so the deployment is not forced to
//! Secure-Boot-sign every late-bound payload. The attestation surface is kept
//! deliberately small: the only thing measured is PCR 14, meaning "stage0 ran, and
//! it loaded a binary with this hash." The admission signature/key are not measured.

#![no_std]
#![no_main]

extern crate alloc;

mod config;
mod dns4;
mod embedded;
mod http;
mod metadata;
mod net;
mod secauth;
mod sig;
mod tcg2;
mod tcp4;
mod timing;
mod udp4;

use alloc::string::String;
use alloc::vec::Vec;
use config::{Manifest, UrlList, Verify};
use sha2::{Digest, Sha256};
use uefi::boot;
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::runtime::{self, ResetType};
use uefi::CString16;

/// PCR extended with SHA-256 of the loaded payload (matches stage1's binary PCR).
const PCR_BINARY: u8 = 14;

/// How long to hold before the fail-closed power-off. This is sized for the cloud,
/// not the console UX: EC2's serial capture (`get-console-output`) only refreshes on
/// the order of a minute, so a stage0 that errors early and powers off in a few
/// seconds disappears before Nitro ever flushes the error to the captured buffer,
/// leaving an operator with a terminated instance and ZERO log. Hold long enough to
/// guarantee at least one capture cycle. The successful path never reaches here (the
/// payload boots an OS); only failures pay this, where seeing why is worth the wait.
const FAIL_CLOSED_DRAIN_US: usize = 90_000_000; // 90s

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    match run() {
        // A real payload ExitBootServices and boots an OS; it must never return.
        // If it does, the machine state is no longer trustworthy.
        Ok(()) => crate::slog!("stage0: payload returned control to stage0 (unexpected)"),
        Err(status) => crate::slog!("stage0: ERROR {status:?}"),
    }
    // stage0 is the root of trust, so it never hands back to firmware: BdsDxe would
    // boot another device or sit at a menu, and after control has left stage0 the
    // platform (payload, firmware) can no longer be trusted. Fail CLOSED by powering
    // the machine off. Hold first (see FAIL_CLOSED_DRAIN_US) so the cloud serial
    // console actually captures the error before the instance halts.
    crate::slog!("stage0: powering off in {}s (fail-closed)", FAIL_CLOSED_DRAIN_US / 1_000_000);
    boot::stall(FAIL_CLOSED_DRAIN_US);
    runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None)
}

fn run() -> Result<(), Status> {
    // Calibrate the boot-relative clock first so every log line below is stamped.
    timing::init();
    crate::slog!("stage0: version: {}", env!("CARGO_PKG_VERSION"));

    // Bring the network up once (DHCP), then fetch metadata. Metadata and payload
    // both ride the raw-TCP4 HTTP client (http.rs).
    let (verify, sha256_urls, inline_args) = {
        net::bringup()?;

        // An embedded `_stage1` section is part of the signed, measured PE, so it
        // is used in place of the cloud metadata service when present.
        let json = match embedded::metadata() {
            Some(j) => {
                let h = hex::encode(sha256(&j));
                crate::slog!("stage0: metadata: embedded {} bytes sha256:{h}", j.len());
                j
            }
            None => metadata::fetch()?,
        };
        let user_data = config::parse(&json).map_err(|m| {
            crate::slog!("stage0: config error: {m}");
            Status::INVALID_PARAMETER
        })?;
        let arch = user_data.stage1.for_this_arch().ok_or_else(|| {
            crate::slog!("stage0: no _stage1 config for this architecture");
            Status::UNSUPPORTED
        })?;
        let verify = arch.validate().map_err(|m| {
            crate::slog!("stage0: invalid arch config: {m}");
            Status::INVALID_PARAMETER
        })?;
        // `url` is only used in sha256 mode; ed25519 mode carries its URLs in the manifest.
        (verify, arch.url.clone(), user_data.stage1.args.clone())
    };

    // Admit the payload: sha256 mode downloads from the inline `url` and checks the pin;
    // ed25519 mode fetches + verifies a signed manifest first, then admits by the hash it
    // names. Any signed args (from the manifest) come back to override inline `args`.
    let (binary, digest, signed_args) = admit_payload(&verify, sha256_urls.as_ref())?;

    // Measure before executing. Only PCR 14 (the binary): the config/key are not
    // measured, so attestation is simply "stage0 ran and loaded this hash".
    // Scoped so the TCG2 protocol is released before chain-loading: stage0 opens
    // it exclusively, and the payload needs to open it too (else ACCESS_DENIED).
    {
        let mut tpm = tcg2::open_tpm().map_err(|e| {
            crate::slog!("stage0: TPM unavailable: {e}");
            Status::DEVICE_ERROR
        })?;
        measure(&mut tpm, PCR_BINARY, &digest)?;
    }
    crate::slog!("stage0: PCR{PCR_BINARY} extended");

    // Chain-load the measured payload from memory. The payload is admitted by
    // stage0's own policy above, not the firmware db, so load it through a
    // temporary security-arch override (see secauth.rs).
    let image = secauth::load_image_verified(&binary).inspect_err(|&status| {
        crate::slog!("stage0: load_image failed: {status:?}");
    })?;

    // Load options: manifest args (ed25519 mode), if any, override the inline `args`. The
    // backing buffer must stay alive until after start_image.
    let opts = signed_args.or_else(|| {
        inline_args.as_deref().filter(|a| !a.is_empty()).map(|a| a.join(" "))
    });
    let _options = set_load_options(image, opts.as_deref());

    crate::slog!("stage0: starting payload");
    boot::start_image(image).map_err(|e| e.status())?;

    Ok(())
}

/// Extend a PCR with `data` via the TCG2-backed TPM transport.
fn measure(tpm: &mut vaportpm_attest::Tpm, pcr: u8, data: &[u8]) -> Result<(), Status> {
    use vaportpm_attest::PcrOps;
    tpm.pcr_extend(pcr, data).map_err(|e| {
        crate::slog!("stage0: pcr_extend(PCR{pcr}) failed: {e}");
        Status::DEVICE_ERROR
    })
}

/// Replace `{sha256}` in each URL with the payload's hex digest (content-addressing).
fn substitute(urls: &[String], hash: &str) -> Vec<String> {
    urls.iter().map(|u| u.replace("{sha256}", hash)).collect()
}

/// Download the first URL that responds (fallback across mirrors).
fn download_first(urls: &[String]) -> Result<Vec<u8>, Status> {
    let mut last = Status::NOT_FOUND;
    for url in urls {
        match http::download(url) {
            Ok(bytes) => return Ok(bytes),
            Err(s) => {
                crate::slog!("stage0: url unavailable: {url} ({s:?})");
                last = s;
            }
        }
    }
    Err(last)
}

/// Admit the payload. sha256 mode downloads from the inline `url` and checks the pin; ed25519
/// mode fetches + verifies a signed manifest, then admits the payload by the manifest's hash.
/// Returns the bytes, their SHA-256 digest, and any signed load options (from the manifest).
fn admit_payload(
    verify: &Verify,
    sha256_urls: Option<&UrlList>,
) -> Result<(Vec<u8>, [u8; 32], Option<String>), Status> {
    match verify {
        Verify::Sha256(expected) => {
            // Static pin: the payload URL(s) come from the (trusted) user-data.
            let urls = sha256_urls.ok_or(Status::INVALID_PARAMETER)?;
            admit_by_hash(&urls.0, expected, None)
        }
        Verify::Ed25519 { pubkey, manifest_url, manifest_sig_url } => {
            // Roll-forward: one signed manifest binds the payload hash + args under one key,
            // so a hostile mirror can neither mix-and-match nor swap the payload.
            let manifest = fetch_manifest(pubkey, manifest_url, manifest_sig_url.as_ref())?;
            let urls = substitute(&manifest.url.0, &manifest.sha256);
            let args = manifest
                .args
                .as_ref()
                .filter(|a| !a.is_empty())
                .map(|a| a.join(" "));
            admit_by_hash(&urls, &manifest.sha256, args)
        }
    }
}

/// Try each mirror until one downloads and matches `expected_hex` (content is pinned, so any
/// mirror yielding the right bytes is acceptable). Threads `args` (signed load options) through.
fn admit_by_hash(
    urls: &[String],
    expected_hex: &str,
    args: Option<String>,
) -> Result<(Vec<u8>, [u8; 32], Option<String>), Status> {
    let mut last = Status::NOT_FOUND;
    for url in urls {
        match download_verify(url, expected_hex) {
            Ok((binary, digest)) => return Ok((binary, digest, args)),
            Err(s) => {
                crate::slog!("stage0: payload url rejected: {url} ({s:?})");
                last = s;
            }
        }
    }
    Err(last)
}

/// Download one payload candidate and check its SHA-256 against `expected_hex` (a gate — the
/// hash itself is never measured; PCR 14 gets the loaded binary).
fn download_verify(url: &str, expected_hex: &str) -> Result<(Vec<u8>, [u8; 32]), Status> {
    crate::sdbg!("stage0:   downloading payload from {url}");
    let binary = http::download(url)?;
    crate::slog!("stage0: payload: {} bytes from {url}", binary.len());
    let digest = sha256(&binary);
    let hash = hex::encode(digest);
    if !hash.eq_ignore_ascii_case(expected_hex) {
        crate::slog!("stage0: SHA256 mismatch! expected {expected_hex}, got {hash}");
        return Err(Status::SECURITY_VIOLATION);
    }
    crate::slog!("stage0: verified: sha256:{hash}");
    Ok((binary, digest))
}

/// Fetch + verify the signed release manifest (ed25519 mode). Tries each `manifest_url` mirror;
/// a candidate is accepted only if it downloads, its detached signature verifies against
/// `pubkey`, and it parses as a valid [`Manifest`]. The signature comes from `manifest_sig_url`
/// (with `{sha256}` replaced by the retrieved manifest's own digest), else `<manifest_url>.sig`.
fn fetch_manifest(
    pubkey: &str,
    manifest_url: &UrlList,
    manifest_sig_url: Option<&UrlList>,
) -> Result<Manifest, Status> {
    let mut last = Status::NOT_FOUND;
    for murl in &manifest_url.0 {
        match try_fetch_manifest(pubkey, murl, manifest_sig_url) {
            Ok(m) => return Ok(m),
            Err(s) => {
                crate::slog!("stage0: manifest rejected: {murl} ({s:?})");
                last = s;
            }
        }
    }
    Err(last)
}

fn try_fetch_manifest(
    pubkey: &str,
    murl: &str,
    manifest_sig_url: Option<&UrlList>,
) -> Result<Manifest, Status> {
    let bytes = http::download(murl)?;
    let mhash = hex::encode(sha256(&bytes));
    let sig_urls = match manifest_sig_url {
        Some(u) => substitute(&u.0, &mhash),
        None => alloc::vec![alloc::format!("{murl}.sig")],
    };
    let signature = download_first(&sig_urls)?;
    sig::verify(pubkey, &bytes, &signature).map_err(|m| {
        crate::slog!("stage0: manifest signature invalid: {m}");
        Status::SECURITY_VIOLATION
    })?;
    let manifest = Manifest::parse(&bytes).map_err(|m| {
        crate::slog!("stage0: invalid manifest: {m}");
        Status::INVALID_PARAMETER
    })?;
    crate::slog!(
        "stage0: manifest verified (sha256:{}, version {}, key:{pubkey})",
        manifest.sha256,
        manifest.version
    );
    Ok(manifest)
}

/// Set the loaded image's load options from the final `opts` string (UCS-2).
/// Returns the backing [`CString16`], which the caller must keep alive until
/// `start_image`.
///
/// `opts` is sourced only from the metadata `_stage1.args` or the signed manifest's `args`
/// (see `run`); stage0 never reads or forwards its own firmware/shell invocation
/// arguments to the child. For a Linux UKI child these LoadOptions would be the kernel
/// command line, but the UKI bakes + measures its own `.cmdline` and the stub ignores
/// LoadOptions under Secure Boot -- so on a UKI in production this has no effect, by
/// design (operator config for a UKI flows through `_stage2`). A non-UKI EFI stage1
/// reads these as its arguments.
fn set_load_options(image: Handle, opts: Option<&str>) -> Option<CString16> {
    let opts = opts?;
    if opts.is_empty() {
        return None;
    }
    let options = CString16::try_from(opts).ok()?;
    let mut loaded = boot::open_protocol_exclusive::<LoadedImage>(image).ok()?;
    unsafe {
        loaded.set_load_options(options.as_ptr().cast::<u8>(), options.num_bytes() as u32);
    }
    Some(options)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
