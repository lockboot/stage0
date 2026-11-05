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

/// The embedded NIC drivers, built per-arch by the Makefile into `build/<arch>/*.efi` and
/// embedded unconditionally: stage0 + its drivers ship as ONE measured unit (covered by
/// stage0's PCR4, no separate pin). Each fills a firmware gap:
///   * `ena.efi`   -- EC2: Nitro's UEFI firmware ships no ENA driver;
///   * `gvnic.efi` -- GCP: the UEFI firmware ships no gVNIC driver (and GCP requires gVNIC
///     for Confidential VMs and Arm).
///
/// Without them there is no SNP for the firmware's IP4/TCP4/UDP4 stack to bind. Building
/// stage0 requires the files to exist (the Makefile builds them first); a missing file is a
/// hard compile error, by design.
macro_rules! embedded_driver {
    ($name:literal) => {{
        #[cfg(target_arch = "x86_64")]
        static D: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../build/x86_64/",
            $name
        ));
        #[cfg(target_arch = "aarch64")]
        static D: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../build/aarch64/",
            $name
        ));
        D
    }};
}

/// Load and start the embedded UEFI NIC drivers, before connecting controllers, so a
/// firmware that lacks a driver for its NIC (EC2/ENA, GCP/gVNIC) still gets an SNP
/// producer. Each is a well-behaved Driver-Model driver: inert on platforms whose NIC it
/// does not match (its Supported() gates on PCI vendor:device).
fn load_embedded_drivers() {
    let drivers: [(&str, &[u8]); 2] = [
        ("ena", embedded_driver!("ena.efi")),
        ("gvnic", embedded_driver!("gvnic.efi")),
    ];
    for (name, image) in drivers {
        crate::slog!(
            "stage0: loading embedded {name} driver ({} bytes)",
            image.len()
        );
        match crate::secauth::load_image_verified(image) {
            Ok(handle) => match boot::start_image(handle) {
                Ok(()) => crate::slog!("stage0: {name} driver started"),
                Err(e) => crate::slog!("stage0: {name} start_image failed: {:?}", e.status()),
            },
            Err(status) => crate::slog!("stage0: {name} load_image failed: {status:?}"),
        }
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
        log_net_inventory();
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
        crate::slog!(
            "stage0: network: OK {}.{}.{}.{} (already up)",
            a[0],
            a[1],
            a[2],
            a[3]
        );
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
            crate::slog!(
                "stage0: network: OK {}.{}.{}.{} (DHCP {took} ms)",
                a[0],
                a[1],
                a[2],
                a[3]
            );
            return Ok(());
        }
        if crate::timing::since_boot_ms().wrapping_sub(start) >= DHCP_TIMEOUT_MS {
            crate::slog!("stage0:   DHCP timed out after {DHCP_TIMEOUT_MS} ms");
            return Err(Status::TIMEOUT);
        }
    }
}

/// Failure-path diagnostic (we are about to fail closed anyway): which layer of the UEFI network
/// stack is missing. Logs how many handles carry each layer's protocol, bottom-up (PCI device ->
/// SNP -> MNP -> ARP/IP4 -> IP4Config2/DHCP4 -> UDP4/TCP4), then the name of every loaded
/// driver (DriverBinding handles, named via ComponentName2/1), so "no SNP on the NIC" (no NIC
/// driver), "SNP but no MNP/IP4" (no NetworkPkg stack), and "stack present but unbound" are
/// distinguishable from the serial log alone.
fn log_net_inventory() {
    use uefi::proto::driver::ComponentName;
    use uefi::{guid, Guid};
    const LAYERS: [(&str, Guid); 9] = [
        ("PciIo", guid!("4cf5b200-68b8-4ca5-9eec-b23e3f50029a")),
        ("SNP", guid!("a19832b9-ac25-11d3-9a2d-0090273fc14d")),
        ("MNP-SB", guid!("f36ff770-a7e1-42cf-9ed2-56f0f271f44c")),
        ("ARP-SB", guid!("f44c00ee-1f2c-4a00-aa09-1c9f3e0800a3")),
        ("IP4-SB", guid!("c51711e7-b4bf-404a-bfb8-0a048ef1ffe4")),
        ("IP4Config2", guid!("5b446ed1-e30b-4faa-871a-3654eca36080")),
        ("DHCP4-SB", guid!("9d9a39d8-bd42-4a73-a4d5-8ee94be11380")),
        ("UDP4-SB", guid!("83f01464-99bd-45e5-b383-af6305d8e9e6")),
        ("TCP4-SB", guid!("00720665-67eb-4a99-baf7-d3c33a1c7cc9")),
    ];
    let count = |g: &Guid| {
        boot::locate_handle_buffer(boot::SearchType::ByProtocol(g))
            .map(|h| h.len())
            .unwrap_or(0)
    };
    for (name, g) in LAYERS.iter() {
        crate::slog!("stage0:   net inventory: {name}={}", count(g));
    }

    const DRIVER_BINDING: Guid = guid!("18a031ab-b443-4d1a-a5c0-0c09261e9f71");
    let Ok(drivers) = boot::locate_handle_buffer(boot::SearchType::ByProtocol(&DRIVER_BINDING))
    else {
        crate::slog!("stage0:   net inventory: no DriverBinding handles");
        return;
    };
    crate::slog!("stage0:   net inventory: {} drivers loaded:", drivers.len());
    for h in drivers.iter() {
        let named = ComponentName::open(*h).ok().and_then(|cn| {
            let lang = cn.supported_languages().ok()?.next()?;
            cn.driver_name(lang).ok().map(|n| alloc::format!("{n}"))
        });
        crate::slog!(
            "stage0:   net inventory:   driver {}",
            named.as_deref().unwrap_or("(unnamed)")
        );
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
