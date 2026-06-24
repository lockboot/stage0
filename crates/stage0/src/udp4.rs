// SPDX-License-Identifier: MIT OR Apache-2.0

//! Raw `EFI_UDP4_PROTOCOL` transport: send one datagram, receive the reply.
//!
//! This exists so `dns4.rs` can resolve names itself. EC2's UEFI firmware ships no
//! `EFI_DNS4` (its OVMF build gates DnsDxe behind the HTTP-boot flags, which default
//! off), but `EFI_UDP4` is always present where we can boot at all: the firmware's
//! DHCP is built on UDP4, so a working lease is proof the protocol is there.
//!
//! `uefi-raw` 0.11 does not expose UDP4, so the FFI bindings (UEFI spec,
//! EFI_UDP4_PROTOCOL) are defined here.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::unsafe_protocol;
use uefi::Status;
use uefi_raw::protocol::driver::ServiceBindingProtocol;
use uefi_raw::{Boolean, Event, Ipv4Address};

// ---- EFI_UDP4_PROTOCOL FFI (UEFI spec) ----

#[repr(C)]
#[allow(dead_code)] // fields are written for the firmware, not read back by us
struct ConfigData {
    accept_broadcast: Boolean,
    accept_promiscuous: Boolean,
    accept_any_port: Boolean,
    allow_duplicate_port: Boolean,
    type_of_service: u8,
    time_to_live: u8,
    do_not_fragment: Boolean,
    receive_timeout: u32,
    transmit_timeout: u32,
    use_default_address: Boolean,
    station_address: Ipv4Address,
    subnet_mask: Ipv4Address,
    station_port: u16,
    remote_address: Ipv4Address,
    remote_port: u16,
}

#[repr(C)]
#[allow(dead_code)]
struct SessionData {
    source_address: Ipv4Address,
    source_port: u16,
    dest_address: Ipv4Address,
    dest_port: u16,
}

#[repr(C)]
struct FragmentData {
    fragment_length: u32,
    fragment_buffer: *mut c_void,
}

#[repr(C)]
struct TxData {
    udp_session_data: *const SessionData,
    gateway_address: *const Ipv4Address,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [FragmentData; 1],
}

#[repr(C)]
#[allow(dead_code)] // timestamp/session filled by the firmware, unread by us
struct RxData {
    timestamp: [u8; 16], // EFI_TIME
    recycle_signal: Event,
    udp_session: SessionData,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [FragmentData; 1],
}

#[repr(C)]
union Packet {
    rx_data: *mut RxData,
    tx_data: *const TxData,
}

#[repr(C)]
struct CompletionToken {
    event: Event,
    status: Status,
    packet: Packet,
}

/// `EFI_UDP4_PROTOCOL` method table. Slots we don't call keep the correct order and
/// size but use a placeholder signature (never invoked).
#[repr(C)]
#[allow(dead_code)]
struct Udp4Protocol {
    get_mode_data: unsafe extern "efiapi" fn() -> Status,
    configure: unsafe extern "efiapi" fn(*mut Udp4Protocol, *const ConfigData) -> Status,
    groups: unsafe extern "efiapi" fn() -> Status,
    routes: unsafe extern "efiapi" fn() -> Status,
    transmit: unsafe extern "efiapi" fn(*mut Udp4Protocol, *mut CompletionToken) -> Status,
    receive: unsafe extern "efiapi" fn(*mut Udp4Protocol, *mut CompletionToken) -> Status,
    cancel: unsafe extern "efiapi" fn(*mut Udp4Protocol, *mut CompletionToken) -> Status,
    poll: unsafe extern "efiapi" fn(*mut Udp4Protocol) -> Status,
}

#[unsafe_protocol("83f01464-99bd-45e5-b383-af6305d8e9e6")]
struct Udp4Sb(ServiceBindingProtocol);

#[unsafe_protocol("3ad9df29-4501-478d-b1f8-7f7fe70e50f3")]
struct Udp4(Udp4Protocol);

/// Spin on an async token's volatile `status`, pumping the driver via `Poll()` (UDP4
/// only services the network when polled), bounded by `budget_ms` on the boot clock.
unsafe fn pump(udp: *mut Udp4Protocol, status: *const Status, budget_ms: u64) -> Status {
    let start = crate::timing::since_boot_ms();
    loop {
        let s = ptr::read_volatile(status);
        if s != Status::NOT_READY {
            return s;
        }
        let _ = ((*udp).poll)(udp);
        if crate::timing::since_boot_ms().wrapping_sub(start) >= budget_ms {
            return Status::TIMEOUT;
        }
    }
}

fn new_event() -> Result<Event, Status> {
    unsafe {
        boot::create_event(
            uefi::boot::EventType::empty(),
            uefi::boot::Tpl::CALLBACK,
            None,
            None,
        )
    }
    .map(|e| e.as_ptr())
    .map_err(|e| e.status())
}

/// Send `request` as one UDP datagram to `ip:port` and return the first reply datagram,
/// retransmitting up to `tries` times with a `per_try_ms` wait each. Each call uses its
/// own UDP4 child, torn down on return (which also reclaims the receive buffer).
pub fn query(
    ip: [u8; 4],
    port: u16,
    request: &[u8],
    tries: u32,
    per_try_ms: u64,
) -> Result<Vec<u8>, Status> {
    let nic = boot::get_handle_for_protocol::<Udp4Sb>().map_err(|e| {
        crate::slog!("stage0:   no EFI_UDP4 service binding: {:?}", e.status());
        e.status()
    })?;
    let mut sb = unsafe {
        boot::open_protocol::<Udp4Sb>(
            OpenProtocolParams {
                handle: nic,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|e| e.status())?
    };

    let mut child: uefi_raw::Handle = ptr::null_mut();
    let st = unsafe { (sb.0.create_child)(&mut sb.0, &mut child) };
    if st != Status::SUCCESS {
        return Err(st);
    }
    let child_handle = unsafe { uefi::Handle::from_ptr(child).ok_or(Status::DEVICE_ERROR)? };

    let result = query_on_child(child_handle, ip, port, request, tries, per_try_ms);

    let _ = unsafe { (sb.0.destroy_child)(&mut sb.0, child) };
    result
}

fn query_on_child(
    child: uefi::Handle,
    ip: [u8; 4],
    port: u16,
    request: &[u8],
    tries: u32,
    per_try_ms: u64,
) -> Result<Vec<u8>, Status> {
    let mut udp = unsafe {
        boot::open_protocol::<Udp4>(
            OpenProtocolParams {
                handle: child,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|e| e.status())?
    };
    let udp_ptr: *mut Udp4Protocol = &mut udp.0;

    // Use the firmware's DHCP address; pin the remote to ip:port so Transmit goes there
    // and Receive only delivers replies from it.
    let cfg = ConfigData {
        accept_broadcast: Boolean::from(false),
        accept_promiscuous: Boolean::from(false),
        accept_any_port: Boolean::from(false),
        allow_duplicate_port: Boolean::from(false),
        type_of_service: 0,
        time_to_live: 64,
        do_not_fragment: Boolean::from(false),
        receive_timeout: 0,
        transmit_timeout: 0,
        use_default_address: Boolean::from(true),
        station_address: Ipv4Address([0, 0, 0, 0]),
        subnet_mask: Ipv4Address([0, 0, 0, 0]),
        station_port: 0,
        remote_address: Ipv4Address(ip),
        remote_port: port,
    };
    let st = unsafe { ((*udp_ptr).configure)(udp_ptr, &cfg) };
    if st != Status::SUCCESS {
        crate::slog!("stage0:   UDP4 configure failed: {st:?}");
        return Err(st);
    }

    let mut last = Status::TIMEOUT;
    for _ in 0..tries {
        if let Err(e) = udp_send(udp_ptr, request) {
            last = e;
            break;
        }
        match udp_recv(udp_ptr, per_try_ms) {
            Ok(data) => {
                let _ = unsafe { ((*udp_ptr).configure)(udp_ptr, ptr::null()) };
                return Ok(data);
            }
            Err(Status::TIMEOUT) => last = Status::TIMEOUT, // datagram lost: retransmit
            Err(e) => {
                last = e;
                break;
            }
        }
    }
    let _ = unsafe { ((*udp_ptr).configure)(udp_ptr, ptr::null()) }; // reset
    Err(last)
}

/// Transmit one datagram to the configured remote and wait for the send to complete.
fn udp_send(udp_ptr: *mut Udp4Protocol, data: &[u8]) -> Result<(), Status> {
    let tx = TxData {
        udp_session_data: ptr::null(),
        gateway_address: ptr::null(),
        data_length: data.len() as u32,
        fragment_count: 1,
        fragment_table: [FragmentData {
            fragment_length: data.len() as u32,
            fragment_buffer: data.as_ptr() as *mut c_void,
        }],
    };
    let event = new_event()?;
    let mut token = CompletionToken {
        event,
        status: Status::NOT_READY,
        packet: Packet { tx_data: &tx as *const TxData },
    };
    let st = unsafe { ((*udp_ptr).transmit)(udp_ptr, &mut token) };
    let st = if st == Status::SUCCESS {
        unsafe { pump(udp_ptr, &token.status, 5_000) }
    } else {
        st
    };
    if st != Status::SUCCESS {
        // The pending transmit must not outlive our token; cancel it first.
        let _ = unsafe { ((*udp_ptr).cancel)(udp_ptr, &mut token) };
    }
    let _ = unsafe { uefi::Event::from_ptr(event).map(boot::close_event) };
    if st != Status::SUCCESS {
        crate::slog!("stage0:   UDP4 transmit failed: {st:?}");
        return Err(st);
    }
    Ok(())
}

/// Wait up to `budget_ms` for one datagram. On timeout, cancel the pending receive so
/// the driver cannot write to our token after we return.
fn udp_recv(udp_ptr: *mut Udp4Protocol, budget_ms: u64) -> Result<Vec<u8>, Status> {
    let event = new_event()?;
    let mut token = CompletionToken {
        event,
        status: Status::NOT_READY,
        packet: Packet { rx_data: ptr::null_mut() },
    };
    let call = unsafe { ((*udp_ptr).receive)(udp_ptr, &mut token) };
    let st = if call == Status::SUCCESS {
        unsafe { pump(udp_ptr, &token.status, budget_ms) }
    } else {
        call
    };

    if st != Status::SUCCESS {
        let _ = unsafe { ((*udp_ptr).cancel)(udp_ptr, &mut token) };
        let _ = unsafe { uefi::Event::from_ptr(event).map(boot::close_event) };
        return Err(st);
    }

    // Copy the datagram out of the (possibly fragmented) receive buffer. We do not
    // signal RecycleSignal: this child handles one datagram and is then destroyed,
    // which reclaims the buffer.
    let out = unsafe {
        let rx = token.packet.rx_data;
        let mut buf = Vec::new();
        if !rx.is_null() {
            let n = (*rx).data_length as usize;
            let fcount = (*rx).fragment_count as usize;
            let frags = (*rx).fragment_table.as_ptr();
            let mut copied = 0usize;
            for i in 0..fcount {
                if copied >= n {
                    break;
                }
                let f = &*frags.add(i);
                let take = (f.fragment_length as usize).min(n - copied);
                buf.extend_from_slice(core::slice::from_raw_parts(
                    f.fragment_buffer as *const u8,
                    take,
                ));
                copied += take;
            }
        }
        buf
    };
    let _ = unsafe { uefi::Event::from_ptr(event).map(boot::close_event) };
    Ok(out)
}
