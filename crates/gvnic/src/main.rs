// SPDX-License-Identifier: MIT OR Apache-2.0

//! `gvnic.efi` - a UEFI SimpleNetworkProtocol driver for the Google Virtual NIC (gVNIC,
//! PCI `1ae0:0042`, Linux driver name `gve`).
//!
//! GCP's UEFI firmware ships no gVNIC driver (its x86 OVMF has the full NetworkPkg stack
//! -- SNP/MNP/ARP/IP4/DHCP4/UDP4/TCP4 -- but no NIC driver for gVNIC, and no longer one
//! for virtio-net either), while GCP *requires* gVNIC for Confidential VMs and Arm. So the
//! firmware's IP stack never has an SNP to bind to and stage0's `net::bringup()` fails
//! with `IP4_CONFIG2 NOT_FOUND`. This driver fills that gap exactly as `ena.efi` does on
//! EC2: it produces `EFI_SIMPLE_NETWORK_PROTOCOL` on the gVNIC controller and EDK2's
//! existing MNP/IP4/TCP4/UDP4 stack layers on top, so stage0's networking is unchanged.
//!
//! A well-behaved UEFI Driver-Model driver: the entry point only installs a
//! `DriverBinding` and returns; it touches no hardware until the firmware calls `Start()`
//! on a matching gVNIC handle, so on other platforms (EC2/ENA, local QEMU) it sits idle.
//!
//! stage0 loads it from a measured PE section (integrity bound via PCR4, like ena.efi).
//!
//! Device protocol: derived from the Linux `gve` driver (drivers/net/ethernet/google/gve,
//! Copyright Google LLC, `(GPL-2.0 OR MIT)`), used under the MIT terms; reference commit
//! 45e0a63f9c86. See `device.rs`.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod clock;
mod binding;
mod device;
mod pci;
mod snp;

use uefi::boot;
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    // stage0's log-timestamp epoch, if it passed one (clock.rs).
    if let Ok(li) = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) {
        clock::init(li.load_options_as_bytes());
    }
    // Install the DriverBinding and return SUCCESS. Because the PE subsystem is
    // EFI_BOOT_SERVICE_DRIVER, the image stays resident after this returns; the
    // firmware (or stage0's connect_all_controllers) calls back into binding::start
    // when it connects the gVNIC controller.
    match binding::install() {
        Ok(()) => {
            vlog!("DriverBinding installed (idle until a gVNIC device binds)");
            Status::SUCCESS
        }
        Err(e) => {
            log!("failed to install DriverBinding: {:?}", e.status());
            e.status()
        }
    }
}
