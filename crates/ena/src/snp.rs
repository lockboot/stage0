// SPDX-License-Identifier: MIT OR Apache-2.0

//! `EFI_SIMPLE_NETWORK_PROTOCOL` production, backed by an [`Ena`] device.
//!
//! The SNP interface is the first field of [`SnpDev`], so the firmware-visible
//! `*const SimpleNetworkProtocol` is also a `*mut SnpDev` (the EDK2 "CR" idiom): each
//! member fn recovers the device with `dev(this)`. State machine mirrors VirtioNetDxe:
//! Stopped -> Started -> Initialized. Reset/StationAddress/Statistics/NvData are
//! UNSUPPORTED (as VirtioNetDxe does); the rest drive the ENA TX/RX rings.

use alloc::boxed::Box;
use core::ffi::c_void;

use uefi::boot;
use uefi::{guid, Guid, Handle, Status};
use uefi_raw::protocol::network::snp::{
    InterruptStatus, NetworkMode, NetworkState, NetworkStatistics, ReceiveFlags,
    SimpleNetworkProtocol,
};
use uefi_raw::{Boolean, IpAddress, MacAddress};

use crate::device::Ena;

const SNP_GUID: Guid = guid!("a19832b9-ac25-11d3-9a2d-0090273fc14d");
const SNP_REVISION: u64 = 0x0001_0000;
/// MTU we advertise to EDK2's IP stack (the ring buffers are larger, see BUF_SIZE).
const MAX_PACKET: u32 = 1500;

/// SNP interface + its Mode + the owning ENA device. `snp` MUST stay first.
#[repr(C)]
pub struct SnpDev {
    snp: SimpleNetworkProtocol,
    mode: NetworkMode,
    ena: Ena,
}

/// Recover the `SnpDev` from a member-fn `this` pointer (snp is at offset 0).
unsafe fn dev<'a>(this: *const SimpleNetworkProtocol) -> &'a mut SnpDev {
    &mut *(this as *mut SnpDev)
}

/// Build the SNP wrapper for `ena`, install it on `controller`, and leak it (the
/// firmware owns it for the controller's life). EDK2's MNP/IP4/TCP4/UDP4 then bind.
pub fn install(controller: Handle, ena: Ena) -> uefi::Result<()> {
    let mode = build_mode(ena.mac());
    let dev = Box::new(SnpDev {
        snp: SimpleNetworkProtocol {
            revision: SNP_REVISION,
            start,
            stop,
            initialize,
            reset,
            shutdown,
            receive_filters,
            station_address,
            statistics,
            multicast_ip_to_mac,
            non_volatile_data,
            get_status,
            transmit,
            receive,
            wait_for_packet: core::ptr::null_mut(),
            mode: core::ptr::null_mut(),
        },
        mode,
        ena,
    });
    let p = Box::into_raw(dev);
    unsafe {
        (*p).snp.mode = &mut (*p).mode;
        boot::install_protocol_interface(Some(controller), &SNP_GUID, (&(*p).snp as *const SimpleNetworkProtocol).cast())?;
    }
    Ok(())
}

fn build_mode(mac: [u8; 6]) -> NetworkMode {
    let mut cur = [0u8; 32];
    cur[..6].copy_from_slice(&mac);
    let mut bcast = [0u8; 32];
    for b in &mut bcast[..6] {
        *b = 0xff;
    }
    NetworkMode {
        state: NetworkState::STOPPED,
        hw_address_size: 6,
        media_header_size: 14,
        max_packet_size: MAX_PACKET,
        nv_ram_size: 0,
        nv_ram_access_size: 0,
        receive_filter_mask: (ReceiveFlags::UNICAST | ReceiveFlags::BROADCAST | ReceiveFlags::MULTICAST).bits(),
        receive_filter_setting: (ReceiveFlags::UNICAST | ReceiveFlags::BROADCAST).bits(),
        max_mcast_filter_count: 0,
        mcast_filter_count: 0,
        mcast_filter: core::array::from_fn(|_| MacAddress([0u8; 32])),
        current_address: MacAddress(cur),
        broadcast_address: MacAddress(bcast),
        permanent_address: MacAddress(cur),
        if_type: 1, // ethernet
        mac_address_changeable: Boolean::from(false),
        multiple_tx_supported: Boolean::from(false),
        media_present_supported: Boolean::from(true),
        media_present: Boolean::from(true),
    }
}

unsafe extern "efiapi" fn start(this: *const SimpleNetworkProtocol) -> Status {
    let d = dev(this);
    if d.mode.state == NetworkState::STOPPED {
        d.mode.state = NetworkState::STARTED;
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn stop(this: *const SimpleNetworkProtocol) -> Status {
    dev(this).mode.state = NetworkState::STOPPED;
    Status::SUCCESS
}

unsafe extern "efiapi" fn initialize(
    this: *const SimpleNetworkProtocol,
    _extra_rx: usize,
    _extra_tx: usize,
) -> Status {
    let d = dev(this);
    if d.mode.state == NetworkState::STOPPED {
        return Status::NOT_STARTED;
    }
    d.ena.init_rx();
    d.mode.state = NetworkState::INITIALIZED;
    uefi::println!("ena: SNP initialized (rx posted, link up)");
    Status::SUCCESS
}

unsafe extern "efiapi" fn reset(_this: *const SimpleNetworkProtocol, _ext: Boolean) -> Status {
    Status::SUCCESS
}

unsafe extern "efiapi" fn shutdown(this: *const SimpleNetworkProtocol) -> Status {
    dev(this).mode.state = NetworkState::STARTED;
    Status::SUCCESS
}

unsafe extern "efiapi" fn receive_filters(
    _this: *const SimpleNetworkProtocol,
    _enable: ReceiveFlags,
    _disable: ReceiveFlags,
    _reset_mcast: Boolean,
    _mcast_count: usize,
    _mcast_filter: *const MacAddress,
) -> Status {
    // We receive unicast+broadcast already; accept the request without reprogramming.
    Status::SUCCESS
}

unsafe extern "efiapi" fn station_address(
    _this: *const SimpleNetworkProtocol,
    _reset: Boolean,
    _new: *const MacAddress,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn statistics(
    _this: *const SimpleNetworkProtocol,
    _reset: Boolean,
    _size: *mut usize,
    _table: *mut NetworkStatistics,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn multicast_ip_to_mac(
    _this: *const SimpleNetworkProtocol,
    ipv6: Boolean,
    ip: *const IpAddress,
    mac: *mut MacAddress,
) -> Status {
    if ipv6 != Boolean::from(false) || ip.is_null() || mac.is_null() {
        return Status::UNSUPPORTED; // IPv4 only
    }
    let ipb = ip as *const u8; // first 4 bytes are the v4 octets
    let m = mac as *mut u8; // MacAddress is a transparent [u8;32]
    m.add(0).write(0x01);
    m.add(1).write(0x00);
    m.add(2).write(0x5e);
    m.add(3).write(ipb.add(1).read() & 0x7f);
    m.add(4).write(ipb.add(2).read());
    m.add(5).write(ipb.add(3).read());
    Status::SUCCESS
}

unsafe extern "efiapi" fn non_volatile_data(
    _this: *const SimpleNetworkProtocol,
    _read: Boolean,
    _offset: usize,
    _buffer_size: usize,
    _buffer: *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn get_status(
    this: *const SimpleNetworkProtocol,
    interrupt_status: *mut InterruptStatus,
    tx_buf: *mut *mut c_void,
) -> Status {
    let d = dev(this);
    if d.mode.state != NetworkState::INITIALIZED {
        return Status::NOT_STARTED;
    }
    let completed = d.ena.poll_tx();
    if !tx_buf.is_null() {
        *tx_buf = completed.map(|p| p as *mut c_void).unwrap_or(core::ptr::null_mut());
    }
    if !interrupt_status.is_null() {
        let mut s = InterruptStatus::empty();
        if completed.is_some() {
            s |= InterruptStatus::TRANSMIT;
        }
        *interrupt_status = s;
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn transmit(
    this: *const SimpleNetworkProtocol,
    header_size: usize,
    buffer_size: usize,
    buffer: *const c_void,
    src: *const MacAddress,
    dest: *const MacAddress,
    protocol: *const u16,
) -> Status {
    let d = dev(this);
    if d.mode.state != NetworkState::INITIALIZED {
        return Status::NOT_STARTED;
    }
    let buf = buffer as *mut u8;
    // If HeaderSize != 0 the SNP must build the media header into the buffer from
    // src/dest/protocol; otherwise the buffer is already a complete frame.
    if header_size != 0 {
        if header_size < 14 || dest.is_null() || protocol.is_null() {
            return Status::INVALID_PARAMETER;
        }
        // MacAddress is a transparent [u8;32]; use the raw pointer directly (taking a
        // reference through the raw deref is UB-adjacent and a hard error now).
        core::ptr::copy_nonoverlapping(dest as *const u8, buf, 6);
        let src6 = if src.is_null() {
            d.ena.mac()
        } else {
            let mut m = [0u8; 6];
            core::ptr::copy_nonoverlapping(src as *const u8, m.as_mut_ptr(), 6);
            m
        };
        core::ptr::copy_nonoverlapping(src6.as_ptr(), buf.add(6), 6);
        let p = *protocol;
        buf.add(12).write_volatile((p >> 8) as u8);
        buf.add(13).write_volatile((p & 0xff) as u8);
    }
    match d.ena.transmit(buf, buffer_size, buffer) {
        Ok(()) => Status::SUCCESS,
        Err(e) => e,
    }
}

unsafe extern "efiapi" fn receive(
    this: *const SimpleNetworkProtocol,
    header_size: *mut usize,
    buffer_size: *mut usize,
    buffer: *mut c_void,
    src: *mut MacAddress,
    dest: *mut MacAddress,
    protocol: *mut u16,
) -> Status {
    let d = dev(this);
    if d.mode.state != NetworkState::INITIALIZED {
        return Status::NOT_STARTED;
    }
    let cap = *buffer_size;
    match d.ena.receive(buffer as *mut u8, cap) {
        Some(n) => {
            *buffer_size = n;
            let b = buffer as *const u8;
            if !header_size.is_null() {
                *header_size = 14;
            }
            if !dest.is_null() && n >= 6 {
                core::ptr::copy_nonoverlapping(b, dest as *mut u8, 6);
            }
            if !src.is_null() && n >= 12 {
                core::ptr::copy_nonoverlapping(b.add(6), src as *mut u8, 6);
            }
            if !protocol.is_null() && n >= 14 {
                *protocol = ((*b.add(12) as u16) << 8) | (*b.add(13) as u16);
            }
            Status::SUCCESS
        }
        None => Status::NOT_READY,
    }
}
