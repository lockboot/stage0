// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal `EFI_PCI_IO_PROTOCOL` binding. uefi/uefi-raw don't expose it, so we
//! hand-roll the vtable. Only the members the ENA driver uses are given real
//! signatures; the unused slots are kept as pointer-sized placeholders so the
//! struct layout (a firmware-provided vtable indexed by offset) stays correct.

// Map/attribute helpers are wired for the device layer that lands next.
#![allow(dead_code)]

use core::ffi::c_void;

use uefi::proto::unsafe_protocol;
use uefi::{guid, Guid, Status};

/// `EFI_PCI_IO_PROTOCOL_WIDTH` (the values the driver uses).
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum PciWidth {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
}

/// `EFI_PCI_IO_PROTOCOL_OPERATION` for `Map`.
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum PciMapOp {
    BusMasterRead = 0,
    BusMasterWrite = 1,
    BusMasterCommonBuffer = 2,
}

/// `EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION`.
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum PciAttrOp {
    Get = 0,
    Set = 1,
    Enable = 2,
    Disable = 3,
    Supported = 4,
}

/// `EFI_PCI_IO_ATTRIBUTE_BUS_MASTER`: enable the device as a PCI bus master (required
/// before any DMA / `Map`). NB 0x0400, not 0x0004 (which is VGA_PALETTE_IO).
pub const PCI_ATTR_BUS_MASTER: u64 = 0x0400;

/// BAR-relative MMIO read/write: `Mem.Read` / `Mem.Write`.
type MemFn = unsafe extern "efiapi" fn(
    this: *const PciIoProtocol,
    width: PciWidth,
    bar_index: u8,
    offset: u64,
    count: usize,
    buffer: *mut c_void,
) -> Status;

/// PCI config-space read/write: `Pci.Read` / `Pci.Write` (note: u32 offset, no BAR).
type ConfigFn = unsafe extern "efiapi" fn(
    this: *const PciIoProtocol,
    width: PciWidth,
    offset: u32,
    count: usize,
    buffer: *mut c_void,
) -> Status;

type MapFn = unsafe extern "efiapi" fn(
    this: *const PciIoProtocol,
    operation: PciMapOp,
    host_address: *const c_void,
    number_of_bytes: *mut usize,
    device_address: *mut u64,
    mapping: *mut *mut c_void,
) -> Status;

type UnmapFn = unsafe extern "efiapi" fn(this: *const PciIoProtocol, mapping: *mut c_void) -> Status;

// alloc_type / memory_type are EFI enums; u32 matches their ABI without importing them.
type AllocBufferFn = unsafe extern "efiapi" fn(
    this: *const PciIoProtocol,
    alloc_type: u32,
    memory_type: u32,
    pages: usize,
    host_address: *mut *mut c_void,
    attributes: u64,
) -> Status;

type FreeBufferFn =
    unsafe extern "efiapi" fn(this: *const PciIoProtocol, pages: usize, host_address: *mut c_void) -> Status;

type AttributesFn = unsafe extern "efiapi" fn(
    this: *const PciIoProtocol,
    operation: PciAttrOp,
    attributes: u64,
    result: *mut u64,
) -> Status;

#[repr(C)]
pub struct PciIoAccess {
    pub read: MemFn,
    pub write: MemFn,
}

#[repr(C)]
pub struct PciIoConfigAccess {
    pub read: ConfigFn,
    pub write: ConfigFn,
}

/// `EFI_PCI_IO_PROTOCOL`. Field order matches the UEFI spec exactly (it is a
/// firmware vtable). Unused members are `usize` placeholders (pointer-sized).
#[repr(C)]
pub struct PciIoProtocol {
    poll_mem: usize,
    poll_io: usize,
    pub mem: PciIoAccess,
    pub io: PciIoAccess,
    pub pci: PciIoConfigAccess,
    copy_mem: usize,
    pub map: MapFn,
    pub unmap: UnmapFn,
    pub allocate_buffer: AllocBufferFn,
    pub free_buffer: FreeBufferFn,
    flush: usize,
    get_location: usize,
    pub attributes: AttributesFn,
    get_bar_attributes: usize,
    set_bar_attributes: usize,
    pub rom_size: u64,
    pub rom_image: *mut c_void,
}

impl PciIoProtocol {
    pub const GUID: Guid = guid!("4cf5b200-68b8-4ca5-9eec-b23e3f50029a");
}

/// High-level wrapper so the protocol works with `boot::open_protocol::<PciIo>`.
#[unsafe_protocol(PciIoProtocol::GUID)]
pub struct PciIo(pub PciIoProtocol);

impl PciIo {
    /// Read PCI config dword 0: low 16 bits = vendor id, high 16 = device id.
    pub fn vendor_device(&self) -> uefi::Result<(u16, u16)> {
        let mut dw: u32 = 0;
        let st = unsafe {
            (self.0.pci.read)(
                &self.0,
                PciWidth::U32,
                0,
                1,
                (&mut dw as *mut u32).cast(),
            )
        };
        if st.is_success() {
            Ok((dw as u16, (dw >> 16) as u16))
        } else {
            Err(st.into())
        }
    }
}
