// SPDX-License-Identifier: MIT OR Apache-2.0

//! `EFI_DRIVER_BINDING_PROTOCOL` for gVNIC. `supported()` is the gate that keeps the
//! driver inert on non-GCP platforms: it returns `SUCCESS` only for PCI `1ae0:0042`.
//! `start()` brings the device up; `stop()` is stubbed (as in ena).

use alloc::boxed::Box;

use uefi::boot;
use uefi::{Handle, Status};
use uefi_raw::protocol::device_path::DevicePathProtocol;
use uefi_raw::protocol::driver::DriverBindingProtocol;
use uefi_raw::Handle as RawHandle;

use crate::device::{GVNIC_DEVICE_ID, GVNIC_VENDOR_ID};
use crate::pci::PciIo;

/// Build and install the DriverBinding on our own image handle. The instance must
/// outlive this function (the firmware keeps the pointer), so it is leaked.
pub fn install() -> uefi::Result<()> {
    let image = boot::image_handle();
    let binding = Box::new(DriverBindingProtocol {
        supported,
        start,
        stop,
        version: 0x10,
        image_handle: image.as_ptr(),
        driver_binding_handle: image.as_ptr(),
    });
    let ptr = Box::into_raw(binding);
    unsafe {
        boot::install_protocol_interface(Some(image), &DriverBindingProtocol::GUID, ptr.cast())?;
    }
    Ok(())
}

/// Return SUCCESS only for a gVNIC controller. Opens PciIo with GetProtocol (a
/// non-owning test open) and checks vendor + device id.
unsafe extern "efiapi" fn supported(
    _this: *const DriverBindingProtocol,
    controller_handle: RawHandle,
    _remaining: *const DevicePathProtocol,
) -> Status {
    let Some(controller) = (unsafe { Handle::from_ptr(controller_handle) }) else {
        return Status::UNSUPPORTED;
    };
    let params = boot::OpenProtocolParams {
        handle: controller,
        agent: boot::image_handle(),
        controller: None,
    };
    let pci = match unsafe {
        boot::open_protocol::<PciIo>(params, boot::OpenProtocolAttributes::GetProtocol)
    } {
        Ok(p) => p,
        Err(_) => return Status::UNSUPPORTED,
    };
    // Gate on vendor AND device id: other Google virtual devices share vendor 0x1ae0.
    match pci.vendor_device() {
        Ok((GVNIC_VENDOR_ID, GVNIC_DEVICE_ID)) => Status::SUCCESS,
        _ => Status::UNSUPPORTED,
    }
}

/// Bind the gVNIC controller: open PciIo BY_DRIVER (claiming the device), probe it
/// (reset + admin queue + describe/configure + QPLs + one TX/RX queue pair), then install
/// SNP on the handle. EDK2's MNP/IP4/TCP4/UDP4 binds on top, producing IP4_CONFIG2 for stage0.
unsafe extern "efiapi" fn start(
    _this: *const DriverBindingProtocol,
    controller_handle: RawHandle,
    _remaining: *const DevicePathProtocol,
) -> Status {
    let Some(controller) = (unsafe { Handle::from_ptr(controller_handle) }) else {
        return Status::UNSUPPORTED;
    };
    let params = boot::OpenProtocolParams {
        handle: controller,
        agent: boot::image_handle(),
        controller: Some(controller),
    };
    let pci = match unsafe {
        boot::open_protocol::<PciIo>(params, boot::OpenProtocolAttributes::ByDriver)
    } {
        Ok(p) => p,
        Err(e) => {
            // ALREADY_STARTED is expected: connect_all_controllers reaches the NIC twice (via
            // the parent bus and directly), so start() is invoked a second time once we
            // already manage the device. That is benign; only log genuine failures.
            if e.status() != Status::ALREADY_STARTED {
                uefi::println!(
                    "gvnic: start(): open PciIo BY_DRIVER failed: {:?}",
                    e.status()
                );
            }
            return e.status();
        }
    };
    uefi::println!("gvnic: start(): probing gVNIC device...");
    // On any error, `pci` drops here and closes the BY_DRIVER open (releasing the device).
    let nic = match unsafe { crate::device::probe(&pci.0) } {
        Ok(nic) => nic,
        Err(e) => {
            uefi::println!("gvnic: probe FAILED: {:?}", e);
            return e;
        }
    };
    let mac = nic.mac();
    uefi::println!(
        "gvnic: probe OK mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} mtu={}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        nic.mtu
    );
    // Keep PciIo open for the device's lifetime (probe stored the raw pointer in `nic`).
    core::mem::forget(pci);
    match crate::snp::install(controller, nic) {
        Ok(()) => {
            uefi::println!("gvnic: SNP installed on controller; networking should come up");
            Status::SUCCESS
        }
        Err(e) => {
            uefi::println!("gvnic: SNP install failed: {:?}", e.status());
            e.status()
        }
    }
}

/// Unbind: shutdown queues, uninstall SNP, free DMA, close PciIo. Stubbed.
unsafe extern "efiapi" fn stop(
    _this: *const DriverBindingProtocol,
    _controller_handle: RawHandle,
    _number_of_children: usize,
    _child_handle_buffer: *const RawHandle,
) -> Status {
    Status::UNSUPPORTED
}
