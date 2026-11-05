// SPDX-License-Identifier: MIT OR Apache-2.0

//! A trivial UEFI payload for exercising the stage0 netboot path end to end.
//!
//! When chain-loaded by stage0 it prints a banner and dumps every allocated PCR
//! in every active bank over `EFI_TCG2_PROTOCOL`, proving the
//! measure-then-execute flow worked (PCR 14 holds the payload measurement) and
//! giving the predictor/verifier a full reference set to validate against. A real
//! payload would instead set up and boot its own OS.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{anyhow, bail, Result};
use uefi::boot::{self, ScopedProtocol};
use uefi::prelude::*;
use uefi::println;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::tcg::v2::Tcg;
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::CStr16;
use vaportpm_attest::{PcrOps, TpmTransport};

struct Tcg2Transport {
    tcg: ScopedProtocol<Tcg>,
    max_response_size: usize,
}

impl TpmTransport for Tcg2Transport {
    fn transmit_raw(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; self.max_response_size.max(64)];
        self.tcg
            .submit_command(command, &mut out)
            .map_err(|e| anyhow!("SubmitCommand failed: {:?}", e.status()))?;
        if out.len() < 10 {
            bail!("short TPM response");
        }
        let size = u32::from_be_bytes([out[2], out[3], out[4], out[5]]) as usize;
        if size < 10 || size > out.len() {
            bail!("bad TPM response size {}", size);
        }
        out.truncate(size);
        Ok(out)
    }
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    println!("payload: hello from the chain-loaded UEFI payload");

    // Secure Boot mode variables as the firmware reports them this boot (value + attributes, or
    // absent): what stage0's gate saw, and whether the firmware implements the UEFI 2.5 modes.
    print_mode_vars();

    match print_pcrs() {
        Ok(()) => {}
        Err(e) => println!("payload: could not read PCRs: {e}"),
    }

    // Experiment: attempt the User -> Deployed Mode transition from here (pre-ExitBootServices,
    // the same position stage0 would do it from), AFTER this boot's PCRs were dumped, so the next
    // boot (`--reboot`) shows whether it persisted and whether PCR 7 moved.
    if load_options_contains("--set-deployed") {
        set_deployed_mode();
    }

    // EC2's serial console buffer is only flushed periodically; if the payload terminates
    // immediately the PCR dump above never makes it out. Hold ~60s with a heartbeat so it is
    // visibly alive and the console keeps flushing -- skipped when LoadOptions carry `--nosleep`
    // (the QEMU test harness passes it, since it captures serial live and has no such lag).
    if !load_options_contains("--nosleep") {
        println!("payload: holding ~60s so the serial console flushes...");
        for i in 1..=6 {
            boot::stall(10_000_000); // 10s
            println!("payload: flush {i}/6 (~{}s)", i * 10);
        }
    }

    println!("payload: done");
    // A test payload never boots an OS, so it never needs to hand control back to stage0. Power
    // off cleanly instead of returning: a return makes stage0 treat it as an unexpected
    // fall-through and run its own (~90s) fail-closed drain, needlessly slowing the boot.
    // `--reboot` cold-resets instead, for one PCR dump per boot on the same instance (cross-boot
    // stability). It loops until the instance is stopped/deleted -- bound it externally (e.g.
    // GCP --max-run-duration).
    if load_options_contains("--reboot") {
        println!("payload: --reboot: cold reset");
        runtime::reset(ResetType::COLD, Status::SUCCESS, None)
    }
    runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None)
}

/// Read a UEFI global variable: `Some((first byte, attributes))`, or `None` if absent/unreadable.
fn global_var(name: &CStr16) -> Option<(u8, VariableAttributes)> {
    let mut buf = [0u8; 8];
    runtime::get_variable(name, &VariableVendor::GLOBAL_VARIABLE, &mut buf)
        .ok()
        .and_then(|(data, attrs)| data.first().map(|b| (*b, attrs)))
}

/// One line per mode variable: "payload: mode <Name>=<value> attrs=0x<bits>" or "=absent".
fn print_mode_vars() {
    for name in [
        uefi::cstr16!("SecureBoot"),
        uefi::cstr16!("SetupMode"),
        uefi::cstr16!("AuditMode"),
        uefi::cstr16!("DeployedMode"),
    ] {
        match global_var(name) {
            Some((v, a)) => println!("payload: mode {name}={v} attrs=0x{:02x}", a.bits()),
            None => println!("payload: mode {name}=absent"),
        }
    }
}

/// Try `DeployedMode = 1`, first with the UEFI-spec attributes (BS|RT), then NV|BS|RT; report
/// each SetVariable status and the read-back. Experiment only: says whether the firmware allows
/// the transition from a pre-ExitBootServices image, not whether it is irreversible.
fn set_deployed_mode() {
    if matches!(global_var(uefi::cstr16!("DeployedMode")), Some((1, _))) {
        println!("payload: --set-deployed: already DeployedMode=1, nothing to do");
        return;
    }
    let bs_rt = VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
    for (label, attrs) in [
        ("BS|RT", bs_rt),
        ("NV|BS|RT", bs_rt | VariableAttributes::NON_VOLATILE),
    ] {
        let r = runtime::set_variable(
            uefi::cstr16!("DeployedMode"),
            &VariableVendor::GLOBAL_VARIABLE,
            attrs,
            &[1u8],
        );
        match r {
            Ok(()) => {
                println!("payload: --set-deployed: SetVariable({label}) = SUCCESS");
                break;
            }
            Err(e) => println!(
                "payload: --set-deployed: SetVariable({label}) = {:?}",
                e.status()
            ),
        }
    }
    print_mode_vars();
}

/// True if this image's UEFI LoadOptions (set by stage0 from `_stage1.args` / a signed manifest)
/// contain the ASCII `flag`. Lets the QEMU test harness (`--nosleep`) skip the EC2-only
/// serial-flush hold. LoadOptions are UCS-2, so an ASCII flag encodes as each byte followed by
/// `0x00`; we scan the raw bytes for that needle (avoids any CStr16 decode/normalisation).
fn load_options_contains(flag: &str) -> bool {
    let Ok(li) = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) else {
        return false;
    };
    let Some(bytes) = li.load_options_as_bytes() else {
        return false;
    };
    let needle: Vec<u8> = flag.bytes().flat_map(|b| [b, 0]).collect();
    bytes.windows(needle.len()).any(|w| w == needle.as_slice())
}

fn print_pcrs() -> Result<()> {
    let handle = boot::get_handle_for_protocol::<Tcg>()
        .map_err(|e| anyhow!("no EFI_TCG2_PROTOCOL: {:?}", e.status()))?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(handle)
        .map_err(|e| anyhow!("open EFI_TCG2_PROTOCOL: {:?}", e.status()))?;
    let max_response_size = tcg
        .get_capability()
        .map_err(|e| anyhow!("get_capability: {:?}", e.status()))?
        .max_response_size as usize;

    let mut tpm = vaportpm_attest::Tpm::with_transport(Box::new(Tcg2Transport {
        tcg,
        max_response_size,
    }));

    // Which banks are active, so the verifier knows which algs to expect.
    let mut banks_line = String::from("payload: active PCR banks:");
    for alg in tpm.get_active_pcr_banks()? {
        banks_line.push(' ');
        banks_line.push_str(alg.name());
    }
    println!("{banks_line}");

    // Dump every allocated PCR in every active bank (including all-zero ones),
    // bracketed by stable markers so the predictor can scrape the block out of a
    // noisy cloud serial log. Line format: "payload: PCR <alg> <idx2> <hex>".
    let mut pcrs = tpm.read_all_allocated_pcrs()?;
    pcrs.sort_by_key(|(idx, alg, _)| (*idx, *alg as u16));

    println!("payload: ===PCR-DUMP-BEGIN===");
    for (idx, alg, value) in &pcrs {
        println!(
            "payload: PCR {} {idx:02} {}",
            alg.name(),
            hex::encode(value)
        );
    }
    println!("payload: ===PCR-DUMP-END===");
    Ok(())
}
