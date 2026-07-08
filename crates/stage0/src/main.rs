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
use config::{Admit, ArchConfig, Entry, ManifestRef, UrlList};
use serde_json::Value;
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
    let (binary, digest, opts) = {
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
        // Resolve `_stage1.<arch>`: admit a payload directly, or follow a chain of signed
        // manifests (each deep-merged into the doc and re-evaluated) until a payload is reached.
        // Returns the admitted binary, its digest, and the load options (signed args, else inline).
        resolve_payload(&json)?
    };

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

    // Load options were resolved above (signed args override inline). The backing buffer
    // must stay alive until after start_image.
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

/// Resolve `_stage1.<arch>` to a concrete payload and admit it. The entry is a discriminated union:
/// a `payload` is admitted directly (sha256 pin or ed25519-signed); a `manifest` is fetched, verified
/// against its pinned key, deep-merged into the doc, and the merged entry re-evaluated — a loop that
/// follows a chain of signed manifests (per-hop key delegation) until it reaches a payload. A repeated
/// (url,hash) is a cycle and fails closed. stage0 forwards no document (the UKI re-fetches its own
/// metadata), so the merged doc drives only re-evaluation. Returns the admitted binary, its digest,
/// and the load options (signed args, else inline `args` joined by spaces).
fn resolve_payload(json: &[u8]) -> Result<(Vec<u8>, [u8; 32], Option<String>), Status> {
    // Validate the document up front (clear error) + confirm this arch is present, then drive
    // resolution off a Value so a signed manifest fragment can be deep-merged and re-evaluated.
    let ud = config::parse(json).map_err(|m| {
        crate::slog!("stage0: config error: {m}");
        Status::INVALID_PARAMETER
    })?;
    ud.stage1.for_this_arch().ok_or_else(|| {
        crate::slog!("stage0: no _stage1 config for this architecture");
        Status::UNSUPPORTED
    })?;
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
    let mut doc: Value = serde_json::from_slice(json).map_err(|_| Status::INVALID_PARAMETER)?;
    let mut history: Vec<ManifestRef> = Vec::new();

    loop {
        let entry_val = doc
            .get("_stage1")
            .and_then(|s| s.get(arch))
            .ok_or_else(|| {
                crate::slog!("stage0: no _stage1 config for this architecture");
                Status::UNSUPPORTED
            })?;
        let ac: ArchConfig = serde_json::from_value(entry_val.clone()).map_err(|_| {
            crate::slog!("stage0: invalid _stage1 entry");
            Status::INVALID_PARAMETER
        })?;

        match ac.entry {
            Entry::Payload(p) => {
                let mode = p.admission().map_err(|m| {
                    crate::slog!("stage0: invalid _stage1 payload: {m}");
                    Status::INVALID_PARAMETER
                })?;
                let (binary, digest, signed_args) = admit_payload(&p.url.0, &mode)?;
                let opts = signed_args.or_else(|| {
                    p.args.as_deref().filter(|a| !a.is_empty()).map(|a| a.join(" "))
                });
                return Ok((binary, digest, opts));
            }
            Entry::Manifest(m) => {
                m.validate().map_err(|e| {
                    crate::slog!("stage0: invalid _stage1 manifest: {e}");
                    Status::INVALID_PARAMETER
                })?;
                let (murl, bytes, hash) = fetch_manifest(&m)?;
                if history
                    .iter()
                    .any(|r| r.sha256.as_deref() == Some(hash.as_str()) && r.url.0 == [murl.clone()])
                {
                    crate::slog!("stage0: manifest resolution cycle at {murl}");
                    return Err(Status::SECURITY_VIOLATION);
                }
                history.push(ManifestRef {
                    url: UrlList(alloc::vec![murl]),
                    ed25519: m.ed25519.clone(),
                    sig_url: m.sig_url.clone(),
                    sha256: Some(hash),
                });
                // Consume the pointer, then deep-merge the manifest fragment (manifest wins). The
                // merged entry re-populates with a `payload` (stop) or a fresh `manifest` (delegate).
                if let Some(e) = doc.get_mut("_stage1").and_then(|s| s.get_mut(arch)).and_then(Value::as_object_mut) {
                    e.remove("manifest");
                }
                let manifest_doc: Value = serde_json::from_slice(&bytes).map_err(|_| {
                    crate::slog!("stage0: manifest is not valid JSON");
                    Status::INVALID_PARAMETER
                })?;
                deep_merge(&mut doc, &manifest_doc);
            }
        }
    }
}

/// Fetch a signed manifest (mirror fallback) and verify its detached signature against the pinned
/// key. Returns the serving URL, the verified bytes, and their hex sha256.
fn fetch_manifest(m: &ManifestRef) -> Result<(String, Vec<u8>, String), Status> {
    let mut last = Status::NOT_FOUND;
    for url in &m.url.0 {
        match try_fetch_manifest(m, url) {
            Ok((bytes, hash)) => return Ok((url.clone(), bytes, hash)),
            Err(s) => {
                crate::slog!("stage0: manifest rejected: {url} ({s:?})");
                last = s;
            }
        }
    }
    Err(last)
}

fn try_fetch_manifest(m: &ManifestRef, url: &str) -> Result<(Vec<u8>, String), Status> {
    let bytes = http::download(url)?;
    let hash = hex::encode(sha256(&bytes));
    if let Some(pin) = &m.sha256 {
        if !pin.eq_ignore_ascii_case(&hash) {
            crate::slog!("stage0: manifest sha256 mismatch: expected {pin}, got {hash}");
            return Err(Status::SECURITY_VIOLATION);
        }
    }
    let sig_urls = match &m.sig_url {
        Some(u) => substitute(&u.0, &hash),
        None => alloc::vec![alloc::format!("{url}.sig")],
    };
    let signature = download_first(&sig_urls)?;
    sig::verify(&m.ed25519, &bytes, &signature).map_err(|e| {
        crate::slog!("stage0: manifest verification failed: {e}");
        Status::SECURITY_VIOLATION
    })?;
    crate::slog!("stage0: manifest verified: sha256:{hash} (ed25519 key:{})", m.ed25519);
    Ok((bytes, hash))
}

/// Recursively merge `overlay` into `base`: two objects merge key-by-key (recursing on shared keys);
/// anything else takes `overlay`. `overlay` (the signed manifest) wins on every conflict.
fn deep_merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(k) {
                    Some(existing) => deep_merge(existing, v),
                    None => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (b, o) => *b = o.clone(),
    }
}

/// Try each payload URL until one downloads and admits (content is pinned, so any mirror
/// that yields verifying bytes is acceptable). Returns the bytes, their SHA-256 digest,
/// and any verified signed load options.
fn admit_payload(urls: &[String], mode: &Admit) -> Result<(Vec<u8>, [u8; 32], Option<String>), Status> {
    let mut last = Status::NOT_FOUND;
    for url in urls {
        match admit_from(url, mode) {
            Ok(result) => return Ok(result),
            Err(s) => {
                crate::slog!("stage0: payload url rejected: {url} ({s:?})");
                last = s;
            }
        }
    }
    Err(last)
}

/// Download one payload candidate and run admission control (a gate — never measured).
fn admit_from(url: &str, mode: &Admit) -> Result<(Vec<u8>, [u8; 32], Option<String>), Status> {
    crate::sdbg!("stage0:   downloading payload from {url}");
    let binary = http::download(url)?;
    crate::slog!("stage0: payload: {} bytes from {url}", binary.len());
    let digest = sha256(&binary);
    let hash = hex::encode(digest);
    let mut signed_args: Option<String> = None;
    match mode {
        Admit::Sha256(expected) => {
            if !hash.eq_ignore_ascii_case(expected) {
                crate::slog!("stage0: SHA256 mismatch! expected {expected}, got {hash}");
                return Err(Status::SECURITY_VIOLATION);
            }
            crate::slog!("stage0: verified: sha256:{hash} (sha256 pin)");
        }
        Admit::Ed25519 { pubkey, sig_url, args_url, args_sig_url } => {
            // Detached signature: the `sig_url` templates with `{sha256}` replaced by the
            // payload digest (content-addressable), else `<url>.sig` (co-located per mirror).
            let sig_urls = match sig_url {
                Some(u) => substitute(&u.0, &hash),
                None => alloc::vec![alloc::format!("{url}.sig")],
            };
            let signature = download_first(&sig_urls)?;
            sig::verify(pubkey, &binary, &signature).map_err(|m| {
                crate::slog!("stage0: ed25519 verification failed: {m}");
                Status::SECURITY_VIOLATION
            })?;
            crate::slog!("stage0: verified: sha256:{hash} (ed25519 key:{pubkey})");
            if let Some(au) = args_url {
                signed_args = Some(fetch_signed_args(&au.0, args_sig_url.as_ref(), pubkey, &hash)?);
            }
        }
    }
    Ok((binary, digest, signed_args))
}

/// Fetch and verify signed load options (ed25519 mode). `args_url`/`args_sig_url` may
/// contain `{sha256}` (replaced with the payload digest) and may each be a fallback list.
/// The detached signature (from `args_sig_url`, else `<args_url>.sig`) must verify against
/// the release `pubkey`; the verified bytes are returned verbatim (trimmed) as load options.
fn fetch_signed_args(
    args_urls: &[String],
    args_sig_url: Option<&UrlList>,
    pubkey: &str,
    payload_hash: &str,
) -> Result<String, Status> {
    let args_urls = substitute(args_urls, payload_hash);
    let sig_urls = match args_sig_url {
        Some(u) => substitute(&u.0, payload_hash),
        None => args_urls.iter().map(|u| alloc::format!("{u}.sig")).collect(),
    };
    let args = download_first(&args_urls)?;
    let sig = download_first(&sig_urls)?;
    sig::verify(pubkey, &args, &sig).map_err(|m| {
        crate::slog!("stage0: signed args verification failed: {m}");
        Status::SECURITY_VIOLATION
    })?;
    let opts = core::str::from_utf8(&args)
        .map_err(|_| {
            crate::slog!("stage0: signed args are not valid UTF-8");
            Status::INVALID_PARAMETER
        })?
        .trim();
    crate::slog!("stage0: args: {} bytes signed (ed25519)", opts.len());
    Ok(opts.into())
}

/// Set the loaded image's load options from the final `opts` string (UCS-2).
/// Returns the backing [`CString16`], which the caller must keep alive until
/// `start_image`.
///
/// `opts` is sourced only from the metadata `_stage1.args` or the signed `args_url`
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
