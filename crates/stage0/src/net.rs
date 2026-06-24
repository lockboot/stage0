// SPDX-License-Identifier: MIT OR Apache-2.0

//! Link/IP-layer network bring-up: connect the firmware's network drivers and
//! obtain a DHCP lease, so the TCP4 transport, UDP4 DNS resolver, and HTTP client can
//! assume the interface is addressed. Nothing here is HTTP-specific.

use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::Status;
use uefi_raw::protocol::network::ip4_config2::Ip4Config2Policy;

/// How often to poll for the DHCP lease. Fine-grained so bring-up returns promptly
/// (the crate's `ifup` polls at 1s granularity); small enough that the firmware's
/// IP4/DHCP timers still run during the stall.
const DHCP_POLL_INTERVAL_MS: u64 = 10;
/// Give up on DHCP after this long.
const DHCP_TIMEOUT_MS: u64 = 30_000;

/// The ENA driver, built per-arch by the Makefile into `build/<arch>/ena.efi` and
/// embedded unconditionally: stage0 + ena ship as ONE measured unit (the driver is
/// covered by stage0's PCR4, no separate pin). EC2's Nitro firmware ships no ENA
/// driver, so without this there is no SNP for the IP4/TCP4/UDP4 stack to bind.
/// Building stage0 requires `build/<arch>/ena.efi` to exist (the Makefile builds it
/// first); a missing file is a hard compile error, by design.
#[cfg(target_arch = "x86_64")]
static ENA_DRIVER: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../build/x86_64/ena.efi"));
#[cfg(target_arch = "aarch64")]
static ENA_DRIVER: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../build/aarch64/ena.efi"));

/// Load and start any embedded UEFI NIC drivers, before connecting controllers, so a
/// firmware that lacks a driver for its NIC (notably EC2/ENA) still gets an SNP
/// producer. The driver is a well-behaved Driver-Model driver: inert on platforms
/// whose NIC it does not match (GCP virtio-net, local QEMU).
fn load_embedded_drivers() {
    crate::slog!("stage0: loading embedded ena driver ({} bytes)", ENA_DRIVER.len());
    match crate::secauth::load_image_verified(ENA_DRIVER) {
        Ok(handle) => match boot::start_image(handle) {
            Ok(()) => crate::slog!("stage0: ena driver started"),
            Err(e) => crate::slog!("stage0: ena start_image failed: {:?}", e.status()),
        },
        Err(status) => crate::slog!("stage0: ena load_image failed: {status:?}"),
    }
}

/// Bring the network up: connect the firmware's drivers, then obtain a DHCP lease.
/// Call once before any networking.
pub fn bringup() -> Result<(), Status> {
    load_embedded_drivers();
    connect_all_controllers();
    let nic = boot::get_handle_for_protocol::<Ip4Config2>().map_err(|e| {
        crate::slog!(
            "stage0:   no EFI_IP4_CONFIG2 (firmware lacks the IPv4 stack?): {:?}",
            e.status()
        );
        e.status()
    })?;
    let mut ip4 = Ip4Config2::new(nic).map_err(|e| e.status())?;
    dhcp_up(&mut ip4)
}

/// Bring the interface up via DHCP and wait for the lease, polling at
/// [`DHCP_POLL_INTERVAL_MS`]. The DHCP exchange itself is firmware-paced; this just
/// returns the instant the lease lands. No-op if the interface is already addressed.
fn dhcp_up(ip4: &mut Ip4Config2) -> Result<(), Status> {
    let addr = |a: uefi_raw::Ipv4Address| a.0;
    let info = ip4.get_interface_info().map_err(|e| e.status())?;
    if addr(info.station_addr) != [0, 0, 0, 0] {
        let a = addr(info.station_addr);
        crate::slog!("stage0: network: OK {}.{}.{}.{} (already up)", a[0], a[1], a[2], a[3]);
        return Ok(());
    }

    ip4.set_policy(Ip4Config2Policy::DHCP).map_err(|e| {
        crate::slog!("stage0:   DHCP set-policy failed: {:?}", e.status());
        e.status()
    })?;

    let start = crate::timing::since_boot_ms();
    loop {
        boot::stall((DHCP_POLL_INTERVAL_MS * 1000) as usize);
        let info = ip4.get_interface_info().map_err(|e| e.status())?;
        let a = addr(info.station_addr);
        if a != [0, 0, 0, 0] {
            let took = crate::timing::since_boot_ms().wrapping_sub(start);
            crate::slog!("stage0: network: OK {}.{}.{}.{} (DHCP {took} ms)", a[0], a[1], a[2], a[3]);
            return Ok(());
        }
        if crate::timing::since_boot_ms().wrapping_sub(start) >= DHCP_TIMEOUT_MS {
            crate::slog!("stage0:   DHCP timed out after {DHCP_TIMEOUT_MS} ms");
            return Err(Status::TIMEOUT);
        }
    }
}

/// Connect all drivers to all handles (best-effort), forcing the firmware to bind
/// its network stack so the TCP4/IP4 service bindings become available even on the
/// first boot before BDS has connected everything.
fn connect_all_controllers() {
    let handles = match boot::locate_handle_buffer(boot::SearchType::AllHandles) {
        Ok(h) => h,
        Err(e) => {
            crate::slog!("stage0:   locate_handle_buffer failed: {:?}", e.status());
            return;
        }
    };
    let mut connected = 0usize;
    for handle in handles.iter() {
        if boot::connect_controller(*handle, None, None, true).is_ok() {
            connected += 1;
        }
    }
    crate::sdbg!(
        "stage0:   connected drivers on {}/{} handles",
        connected,
        handles.len()
    );
}
