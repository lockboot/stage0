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
use uefi::proto::tcg::v2::Tcg;
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

    match print_pcrs() {
        Ok(()) => {}
        Err(e) => println!("payload: could not read PCRs: {e}"),
    }

    // EC2's serial console buffer is only flushed periodically; if the payload
    // returns immediately, stage0 falls through, the VM resets/terminates, and the
    // PCR dump above never makes it out. Hold ~60s before handing back, with a
    // heartbeat so it is visibly alive and the console keeps draining.
    println!("payload: holding ~60s so the serial console drains...");
    for i in 1..=6 {
        boot::stall(10_000_000); // 10s
        println!("payload: drain {i}/6 (~{}s)", i * 10);
    }

    println!("payload: done");
    Status::SUCCESS
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
        println!("payload: PCR {} {idx:02} {}", alg.name(), hex::encode(value));
    }
    println!("payload: ===PCR-DUMP-END===");
    Ok(())
}
