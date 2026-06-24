// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ena.efi` - a clean-room UEFI SimpleNetworkProtocol driver for the AWS Elastic
//! Network Adapter (ENA, PCI vendor `0x1d0f`).
//!
//! EC2's Nitro UEFI firmware ships no NIC driver (it expects the OS to drive ENA),
//! so the firmware's IP4/TCP4 stack never has an SNP to bind to and stage0's
//! `net::bringup()` fails with `IP4_CONFIG2 NOT_FOUND`. This driver fills that gap:
//! it produces `EFI_SIMPLE_NETWORK_PROTOCOL` on the ENA controller, and EDK2's
//! existing MNP/IP4/TCP4/UDP4 stack layers on top, so stage0's networking works
//! unchanged.
//!
//! It is a well-behaved UEFI Driver-Model driver: the entry point only installs a
//! `DriverBinding` and returns. It touches no hardware until the firmware calls
//! `Start()` on a matching ENA handle, so on non-ENA platforms (GCP virtio-net,
//! local QEMU) it loads and sits idle.
//!
//! stage0 loads it from a measured PE section (integrity bound via PCR4, see
//! the stage0 PCR baseline); the driver itself is never measured into its own PCR.

#![no_std]
#![no_main]

extern crate alloc;

mod binding;
mod device;
mod pci;
mod snp;

use uefi::prelude::*;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    // Install the DriverBinding and return SUCCESS. Because the PE subsystem is
    // EFI_BOOT_SERVICE_DRIVER, the image stays resident after this returns; the
    // firmware (or stage0's connect_all_controllers) calls back into binding::start
    // when it connects the ENA controller.
    match binding::install() {
        Ok(()) => {
            uefi::println!("ena: DriverBinding installed (idle until an ENA device binds)");
            Status::SUCCESS
        }
        Err(e) => {
            uefi::println!("ena: failed to install DriverBinding: {:?}", e.status());
            e.status()
        }
    }
}
