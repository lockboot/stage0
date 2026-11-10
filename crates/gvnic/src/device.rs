// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Device protocol derived from the Linux `gve` driver (drivers/net/ethernet/google/gve),
// Copyright (C) 2015-2024 Google LLC, licensed `(GPL-2.0 OR MIT)`; used here under the MIT
// terms. Reference: torvalds/linux @ 45e0a63f9c86. Section numbers (`spec §N`) refer to the
// extracted protocol notes for that tree; `gve_*.{c,h}:line` cite the reference directly.

//! gVNIC hardware layer: the bare minimum to push and poll Ethernet frames, enough for
//! EDK2's IP4/TCP4 stack to netboot over it.
//!
//! Queue format GQI_QPL ("registered pages"), ONE TX + ONE RX queue, polled (no
//! interrupts), no offloads, no RSS. Everything device-facing is BIG-endian: BAR0
//! registers, admin-queue commands, descriptors, doorbells, event counters.
//!
//! BAR0 (registers) goes through `PciIo.Mem`; BAR2 (queue doorbells) is written with direct
//! stores to the BAR's host address, as every reference driver does (Linux iowrite32be,
//! FreeBSD bus_write_4, DPDK rte_write32, iPXE's EFI build writel). GCE backs the doorbell BAR
//! as memory rather than trapping MMIO: under Intel TDX the firmware's `PciIo.Mem` path is a
//! TDVMCALL MMIO hypercall that never reaches it (writes dropped, reads 0), while a direct store
//! through the firmware's shared MMIO mapping does.
//!
//! Flow (probe): PCI enable -> version string -> register admin queue (by PCI revision) ->
//! VERIFY_DRIVER_COMPATIBILITY -> DESCRIBE_DEVICE (+ option TLVs) ->
//! CONFIGURE_DEVICE_RESOURCES -> allocate rings + QPLs -> REGISTER_PAGE_LIST (TX, RX) ->
//! CREATE_TX_QUEUE -> CREATE_RX_QUEUE -> RX doorbell -> link poll -> ExitBootServices hook.
//!
//! Data path: TX copies each frame into a fixed 2 KiB slot of the TX QPL and posts ONE
//! packet descriptor (seg_addr = QPL byte offset); completions come from the TX event
//! counter. RX buffers are QPL pages (slot i = page i, never flipped); a descriptor is
//! ready when its 3-bit seqno matches the expected one (1..7); the frame starts 2 bytes in.
//!
//! All DMA memory is `PciIo.AllocateBuffer` + `Map(CommonBuffer)`, so it is also correct
//! under memory encryption (SEV), where it must be shared with the host.

// Several fields exist only to keep device-visible buffers alive (never read back), and a
// few protocol constants are kept for reference.
#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;
use core::sync::atomic::{fence, Ordering};

use uefi::boot::{self, EventType, Tpl};
use uefi::{Event, Status};

use crate::pci::{PciAttrOp, PciIoProtocol, PciMapOp, PciWidth, PCI_ATTR_BUS_MASTER};

/// PCI identity (gve.h:26,29: PCI_VENDOR_ID_GOOGLE / PCI_DEV_ID_GVNIC).
pub const GVNIC_VENDOR_ID: u16 = 0x1ae0;
pub const GVNIC_DEVICE_ID: u16 = 0x0042;

/// BAR0 = register block, BAR2 = doorbells (array of BE32, index i at byte 4*i).
const REG_BAR: u8 = 0;
const DB_BAR: u8 = 2;

/// `struct gve_registers` offsets (gve_register.h:11-24).
mod regs {
    pub const DEVICE_STATUS: u64 = 0x00;
    pub const DRIVER_STATUS: u64 = 0x04;
    pub const MAX_TX_QUEUES: u64 = 0x08;
    pub const MAX_RX_QUEUES: u64 = 0x0c;
    pub const ADMINQ_PFN: u64 = 0x10;
    pub const ADMINQ_DOORBELL: u64 = 0x14;
    pub const ADMINQ_EVENT_COUNTER: u64 = 0x18;
    pub const DRIVER_VERSION: u64 = 0x1f;
    pub const ADMINQ_BASE_HI: u64 = 0x20;
    pub const ADMINQ_BASE_LO: u64 = 0x24;
    pub const ADMINQ_LENGTH: u64 = 0x28;
}

/// device_status bits (gve_register.h:26-31).
const DEV_STS_RESET_REQUESTED: u32 = 1 << 1;
const DEV_STS_LINK_UP: u32 = 1 << 2;
const DEV_STS_IS_RESET: u32 = 1 << 4;
/// driver_status bits (gve_register.h:33-36).
const DRV_STS_RUN: u32 = 1 << 0;
const DRV_STS_RESET: u32 = 1 << 1;

/// Admin opcodes (gve_adminq.h:13-35).
const OP_DESCRIBE_DEVICE: u32 = 0x1;
const OP_CONFIGURE_DEVICE_RESOURCES: u32 = 0x2;
const OP_REGISTER_PAGE_LIST: u32 = 0x3;
const OP_CREATE_TX_QUEUE: u32 = 0x5;
const OP_CREATE_RX_QUEUE: u32 = 0x6;
const OP_UNREGISTER_PAGE_LIST: u32 = 0x4;
const OP_DESTROY_TX_QUEUE: u32 = 0x7;
const OP_DESTROY_RX_QUEUE: u32 = 0x8;
const OP_DECONFIGURE_DEVICE_RESOURCES: u32 = 0x9;
/// TX QPL id (Linux's: TX QPLs are numbered from 0).
const TX_QPL_ID: u32 = 0;
const OP_VERIFY_DRIVER_COMPATIBILITY: u32 = 0xf;

/// Admin status codes (gve_adminq.h:47-66).
const AQ_PASSED: u32 = 0x0000_0001;
const AQ_UNIMPLEMENTED: u32 = 0xffff_fffe;

/// Device-option ids (gve_adminq.h:192-204).
const OPT_GQI_RAW_ADDRESSING: u16 = 0x1;
const OPT_GQI_RDA: u16 = 0x2;
const OPT_GQI_QPL: u16 = 0x3;
const OPT_DQO_RDA: u16 = 0x4;
const OPT_DQO_QPL: u16 = 0x7;
const OPT_JUMBO_FRAMES: u16 = 0x8;
/// GVE_SUP_JUMBO_FRAMES_MASK (gve_adminq.h:222).
const SUP_JUMBO_FRAMES: u32 = 1 << 2;

/// CONFIGURE_DEVICE_RESOURCES queue_format (gve.h:749-755).
const QUEUE_FORMAT_GQI_QPL: u8 = 2;
/// VERIFY_DRIVER_COMPATIBILITY capability bit 0 = gqi_qpl (gve_adminq.h:233-258).
const DRIVER_CAP_GQI_QPL: u64 = 1 << 0;
const DRIVER_INFO_LEN: usize = 304; // sizeof(struct gve_driver_info)

/// Version string, written byte-by-byte to DRIVER_VERSION (gve_main.c:32-40, 2631-2646).
const VERSION_STRING: &[u8] = b"GVE-1.0.0\n";

/// Polling limits (gve_adminq.c:15-17): 20 ms steps; 100 for a command, 500 for a release.
const SLEEP_MS: usize = 20;
const CMD_CHECKS: usize = 100;
const RELEASE_CHECKS: usize = 500;
const LINK_CHECKS: usize = 250; // 5 s (Linux does not wait; we log the outcome)

const PAGE: usize = 4096;
const AQ_SLOTS: u32 = (PAGE / 64) as u32; // 64 slots of 64 bytes
const BUF: usize = 2048; // RX packet_buffer_size and TX slot size (gve.h:62)
const RX_PAD: usize = 2; // GVE_RX_PAD (gve_desc.h:79-82)
const ETH_HLEN: usize = 14;
/// Largest MTU whose frame (+ RX pad) fits one 2 KiB buffer: keeps RX single-fragment and
/// TX single-descriptor (spec §9).
const MTU_CAP: u32 = (BUF - ETH_HLEN - RX_PAD) as u32;
const MTU_MIN: u32 = 68;

/// RX descriptor flags_seq (host order after BE16 decode; gve_desc.h:109-119).
const RXF_ERR: u16 = 1 << (3 + 8);
const RXF_PKT_CONT: u16 = 1 << (3 + 10);

const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_ALLOCATE_ANY_PAGES: u32 = 0;
/// EFI_PCI_IO_ATTRIBUTE_MEMORY.
const PCI_ATTR_MEMORY: u64 = 0x0200;

fn delay_ms(ms: usize) {
    boot::stall(ms * 1000);
}

// ---- big-endian field access in DMA memory (byte-wise, volatile) ---------------

unsafe fn put_be16(p: *mut u8, off: usize, v: u16) {
    for (i, b) in v.to_be_bytes().iter().enumerate() {
        p.add(off + i).write_volatile(*b);
    }
}
unsafe fn put_be32(p: *mut u8, off: usize, v: u32) {
    for (i, b) in v.to_be_bytes().iter().enumerate() {
        p.add(off + i).write_volatile(*b);
    }
}
unsafe fn put_be64(p: *mut u8, off: usize, v: u64) {
    for (i, b) in v.to_be_bytes().iter().enumerate() {
        p.add(off + i).write_volatile(*b);
    }
}
unsafe fn get_be16(p: *const u8, off: usize) -> u16 {
    u16::from_be_bytes([p.add(off).read_volatile(), p.add(off + 1).read_volatile()])
}
unsafe fn get_be32(p: *const u8, off: usize) -> u32 {
    let mut b = [0u8; 4];
    for (i, x) in b.iter_mut().enumerate() {
        *x = p.add(off + i).read_volatile();
    }
    u32::from_be_bytes(b)
}
unsafe fn get_be64(p: *const u8, off: usize) -> u64 {
    let mut b = [0u8; 8];
    for (i, x) in b.iter_mut().enumerate() {
        *x = p.add(off + i).read_volatile();
    }
    u64::from_be_bytes(b)
}

// Command buffers are plain [u8; 64] built on the stack, then copied into the AQ slot.
fn cmd_new(opcode: u32) -> [u8; 64] {
    let mut c = [0u8; 64];
    c[0..4].copy_from_slice(&opcode.to_be_bytes());
    c
}
fn cmd_u8(c: &mut [u8; 64], off: usize, v: u8) {
    c[off] = v;
}
fn cmd_be16(c: &mut [u8; 64], off: usize, v: u16) {
    c[off..off + 2].copy_from_slice(&v.to_be_bytes());
}
fn cmd_be32(c: &mut [u8; 64], off: usize, v: u32) {
    c[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
fn cmd_be64(c: &mut [u8; 64], off: usize, v: u64) {
    c[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

// ---- MMIO (BAR0 registers, BAR2 doorbells) via PciIo.Mem; device is big-endian ---

unsafe fn mmio_read32(pci: &PciIoProtocol, bar: u8, off: u64) -> u32 {
    let mut v: u32 = 0;
    let st = (pci.mem.read)(pci, PciWidth::U32, bar, off, 1, (&mut v as *mut u32).cast());
    if !st.is_success() {
        log!("  MMIO read bar{bar}@0x{off:02x} failed: {st:?}");
    }
    u32::from_be(v)
}
unsafe fn mmio_write32(pci: &PciIoProtocol, bar: u8, off: u64, val: u32) {
    let mut v = val.to_be();
    let st = (pci.mem.write)(pci, PciWidth::U32, bar, off, 1, (&mut v as *mut u32).cast());
    if !st.is_success() {
        log!("  MMIO write bar{bar}@0x{off:02x} failed: {st:?}");
    }
}
unsafe fn mmio_write16(pci: &PciIoProtocol, bar: u8, off: u64, val: u16) {
    let mut v = val.to_be();
    let st = (pci.mem.write)(pci, PciWidth::U16, bar, off, 1, (&mut v as *mut u16).cast());
    if !st.is_success() {
        log!("  MMIO write16 bar{bar}@0x{off:02x} failed: {st:?}");
    }
}
unsafe fn mmio_write8(pci: &PciIoProtocol, bar: u8, off: u64, val: u8) {
    let mut v = val;
    let _ = (pci.mem.write)(pci, PciWidth::U8, bar, off, 1, (&mut v as *mut u8).cast());
}
unsafe fn reg_rd(pci: &PciIoProtocol, off: u64) -> u32 {
    mmio_read32(pci, REG_BAR, off)
}
unsafe fn reg_wr(pci: &PciIoProtocol, off: u64, v: u32) {
    mmio_write32(pci, REG_BAR, off, v)
}
/// Ring doorbell `db_index` (BAR2 + 4*db_index) with a free-running count. Release fence
/// first, so every descriptor/payload store is visible before the device is told.
unsafe fn doorbell(db: *mut u8, db_index: u32, value: u32) {
    fence(Ordering::Release);
    (db.add(4 * db_index as usize) as *mut u32).write_volatile(value.to_be());
}

/// Host address and length of memory BAR `bar`, from `PciIo.GetBarAttributes` (its first
/// memory descriptor; host = AddrRangeMin - AddrTranslationOffset, EDK2 TO_HOST_ADDRESS).
unsafe fn bar_host_range(pci: &PciIoProtocol, bar: u8) -> Result<(u64, u64), Status> {
    let mut res: *mut c_void = core::ptr::null_mut();
    let st = (pci.get_bar_attributes)(pci, bar, core::ptr::null_mut(), &mut res);
    if !st.is_success() || res.is_null() {
        log!("GetBarAttributes(bar{bar}) failed: {st:?}");
        return Err(if st.is_success() {
            Status::DEVICE_ERROR
        } else {
            st
        });
    }
    // ACPI QWORD address-space descriptor (0x8A): ResType @3, AddrRangeMin @14,
    // AddrTranslationOffset @30, AddrLen @38 (packed).
    let p = res as *const u8;
    let rd = |o: usize| (p.add(o) as *const u64).read_unaligned();
    let found = (*p == 0x8a && *p.add(3) == 0).then(|| (rd(14).wrapping_sub(rd(30)), rd(38)));
    let _ = boot::free_pool(NonNull::new_unchecked(res as *mut u8));
    found.ok_or_else(|| {
        log!("bar{bar}: no memory descriptor");
        Status::DEVICE_ERROR
    })
}

unsafe fn cfg_r8(pci: &PciIoProtocol, off: u32) -> u8 {
    let mut v: u8 = 0;
    let _ = (pci.pci.read)(pci, PciWidth::U8, off, 1, (&mut v as *mut u8).cast());
    v
}
unsafe fn cfg_r16(pci: &PciIoProtocol, off: u32) -> u16 {
    let mut v: u16 = 0;
    let _ = (pci.pci.read)(pci, PciWidth::U16, off, 1, (&mut v as *mut u16).cast());
    v
}
unsafe fn cfg_w16(pci: &PciIoProtocol, off: u32, val: u16) {
    let mut v = val;
    let _ = (pci.pci.write)(pci, PciWidth::U16, off, 1, (&mut v as *mut u16).cast());
}

/// MSI-X table size (Message Control bits[10:0] + 1), or 0 if there is no MSI-X capability.
/// Read only: MSI-X stays DISABLED (we poll); the count sizes the notification blocks the
/// device expects in CONFIGURE_DEVICE_RESOURCES, exactly as Linux computes it.
unsafe fn msix_table_size(pci: &PciIoProtocol) -> u32 {
    let mut off = (cfg_r8(pci, 0x34) & 0xfc) as u32; // capabilities pointer
    let mut guard = 0;
    while off != 0 && guard < 48 {
        if cfg_r8(pci, off) == 0x11 {
            return (cfg_r16(pci, off + 2) & 0x7ff) as u32 + 1;
        }
        off = (cfg_r8(pci, off + 1) & 0xfc) as u32;
        guard += 1;
    }
    0
}

// ---- DMA (common buffer via PciIo) -------------------------------------------------

/// A coherent DMA region: host pointer + device bus address. Never freed (the device owns
/// it for the controller's lifetime; after a reset nothing references it).
struct Dma {
    host: *mut u8,
    dev: u64,
    mapping: *mut c_void,
    pages: usize,
}

impl Dma {
    /// Allocate `bytes` (rounded up to pages), zeroed, mapped as ONE contiguous bus-master
    /// common buffer (QPLs rely on page i being at `dev + i*4096`).
    unsafe fn alloc(pci: &PciIoProtocol, bytes: usize) -> Result<Dma, Status> {
        let pages = bytes.div_ceil(PAGE).max(1);
        let mut host: *mut c_void = core::ptr::null_mut();
        let st = (pci.allocate_buffer)(
            pci,
            EFI_ALLOCATE_ANY_PAGES,
            EFI_BOOT_SERVICES_DATA,
            pages,
            &mut host,
            0,
        );
        if !st.is_success() || host.is_null() {
            log!("  AllocateBuffer({pages} pages) failed: {st:?}");
            return Err(if st.is_success() {
                Status::OUT_OF_RESOURCES
            } else {
                st
            });
        }
        core::ptr::write_bytes(host as *mut u8, 0, pages * PAGE);
        let want = pages * PAGE;
        let mut nbytes = want;
        let mut dev: u64 = 0;
        let mut mapping: *mut c_void = core::ptr::null_mut();
        let st = (pci.map)(
            pci,
            PciMapOp::CommonBuffer,
            host as *const c_void,
            &mut nbytes,
            &mut dev,
            &mut mapping,
        );
        if !st.is_success() || nbytes != want {
            log!("  Map({want} bytes) failed: {st:?} (mapped {nbytes})");
            let _ = (pci.free_buffer)(pci, pages, host);
            return Err(if st.is_success() {
                Status::OUT_OF_RESOURCES
            } else {
                st
            });
        }
        Ok(Dma {
            host: host as *mut u8,
            dev,
            mapping,
            pages,
        })
    }
}

// ---- Admin queue (spec §3) -------------------------------------------------------------

struct AdminQueue {
    dma: Dma,
    /// Free-running producer count; the device's event counter must equal it when idle.
    prod: u32,
}

impl AdminQueue {
    /// Submit one 64-byte command and wait for it; returns the device status word.
    unsafe fn exec_status(&mut self, pci: &PciIoProtocol, cmd: &[u8; 64]) -> Result<u32, Status> {
        let tail = reg_rd(pci, regs::ADMINQ_EVENT_COUNTER);
        if tail != self.prod {
            log!("  AQ out of sync: event_counter={tail} prod={}", self.prod);
            return Err(Status::DEVICE_ERROR);
        }
        let slot = self.dma.host.add(((self.prod % AQ_SLOTS) * 64) as usize);
        for (i, b) in cmd.iter().enumerate() {
            slot.add(i).write_volatile(*b);
        }
        self.prod = self.prod.wrapping_add(1);
        fence(Ordering::Release);
        reg_wr(pci, regs::ADMINQ_DOORBELL, self.prod);
        let mut done = false;
        for _ in 0..CMD_CHECKS {
            if reg_rd(pci, regs::ADMINQ_EVENT_COUNTER) == self.prod {
                done = true;
                break;
            }
            delay_ms(SLEEP_MS);
        }
        let opcode = u32::from_be_bytes([cmd[0], cmd[1], cmd[2], cmd[3]]);
        if !done {
            log!("  AQ opcode 0x{opcode:x}: timed out");
            return Err(Status::TIMEOUT);
        }
        fence(Ordering::Acquire);
        Ok(get_be32(slot, 4))
    }

    /// Submit one command; anything but PASSED is an error (logged with the opcode).
    unsafe fn exec(&mut self, pci: &PciIoProtocol, cmd: &[u8; 64]) -> Result<(), Status> {
        let st = self.exec_status(pci, cmd)?;
        let opcode = u32::from_be_bytes([cmd[0], cmd[1], cmd[2], cmd[3]]);
        if st == AQ_PASSED {
            vlog!("  AQ opcode 0x{opcode:x}: PASSED");
            Ok(())
        } else {
            log!("  AQ opcode 0x{opcode:x}: status 0x{st:08x}");
            Err(Status::DEVICE_ERROR)
        }
    }
}

/// Register the admin queue (spec §3.2; gve_adminq.c:341-354): PFN on rev 0, else
/// length + base hi/lo + RUN.
unsafe fn register_adminq(pci: &PciIoProtocol, rev: u8, aq: &Dma) {
    if rev < 1 {
        reg_wr(pci, regs::ADMINQ_PFN, (aq.dev / PAGE as u64) as u32);
    } else {
        mmio_write16(pci, REG_BAR, regs::ADMINQ_LENGTH, PAGE as u16);
        reg_wr(pci, regs::ADMINQ_BASE_HI, (aq.dev >> 32) as u32);
        reg_wr(pci, regs::ADMINQ_BASE_LO, aq.dev as u32);
        reg_wr(pci, regs::DRIVER_STATUS, DRV_STS_RUN);
    }
}

/// Reset handshake = release the admin queue (spec §2.4; gve_adminq.c:368-397). The only
/// guarantee the device has stopped DMA. Bounded (500 x 20 ms); returns whether it completed.
unsafe fn reset(pci: &PciIoProtocol, rev: u8) -> bool {
    if rev < 1 {
        reg_wr(pci, regs::ADMINQ_PFN, 0);
        for _ in 0..RELEASE_CHECKS {
            if reg_rd(pci, regs::ADMINQ_PFN) == 0 {
                return true;
            }
            delay_ms(SLEEP_MS);
        }
    } else {
        reg_wr(pci, regs::DRIVER_STATUS, DRV_STS_RESET);
        for _ in 0..RELEASE_CHECKS {
            if reg_rd(pci, regs::DEVICE_STATUS) & DEV_STS_IS_RESET != 0 {
                return true;
            }
            delay_ms(SLEEP_MS);
        }
    }
    false
}

// ---- ExitBootServices: stop DMA before the OS owns the memory ---------------------------

/// Tear the device down at ExitBootServices, as Linux does on close + remove (gve_close ->
/// gve_destroy_rings + gve_unregister_qpls, gve_teardown_device_resources, gve_adminq_release):
/// destroy the queues, unregister both page lists, deconfigure the device resources, then reset.
/// The device must let go of every page it was given before the firmware IOMMU's own EBS
/// handler (TPL_CALLBACK, after this one at TPL_NOTIFY) converts them back to private memory --
/// RX buffers are posted into boot-services memory the OS is about to reuse. Admin-queue commands
/// use pre-allocated DMA memory and Stall-based polling only (no allocation, as EBS requires). A
/// failed command surrenders to the reset, as gve_close does. No logging (console may be gone).
unsafe extern "efiapi" fn on_exit_boot_services(_e: Event, ctx: Option<NonNull<c_void>>) {
    if let Some(c) = ctx {
        (*(c.as_ptr() as *mut Gvnic)).teardown();
    }
}

/// Arm the ExitBootServices teardown for `nic`, which must stay at this address (the SNP
/// device it lives in is leaked) for the life of boot services.
pub unsafe fn arm_exit_boot_services(nic: *mut Gvnic) {
    match boot::create_event(
        EventType::SIGNAL_EXIT_BOOT_SERVICES,
        Tpl::NOTIFY,
        Some(on_exit_boot_services),
        NonNull::new(nic.cast()),
    ) {
        Ok(_) => vlog!("ExitBootServices teardown armed"),
        Err(e) => log!(
            "ExitBootServices hook FAILED: {:?} (device left running)",
            e.status()
        ),
    }
}

// ---- Device description (spec §4.2) -----------------------------------------------------

struct Desc {
    max_registered_pages: u64,
    tx_entries: u32,
    rx_entries: u32,
    mtu: u32,
    counters: u32,
    tx_pages_per_qpl: u32,
    mac: [u8; 6],
}

/// Parse the device descriptor + option TLVs; log everything (first-boot visibility); pick
/// GQI_QPL (present, or no format option at all = Linux's default) or fail.
unsafe fn parse_describe(buf: *const u8) -> Result<Desc, Status> {
    let mut d = Desc {
        max_registered_pages: get_be64(buf, 0),
        tx_entries: get_be16(buf, 10) as u32,
        rx_entries: get_be16(buf, 12) as u32,
        mtu: get_be16(buf, 16) as u32,
        counters: get_be16(buf, 18) as u32,
        tx_pages_per_qpl: get_be16(buf, 20) as u32,
        mac: [0; 6],
    };
    for (i, m) in d.mac.iter_mut().enumerate() {
        *m = buf.add(24 + i).read_volatile();
    }
    let num_opts = get_be16(buf, 30) as usize;
    let total_len = (get_be16(buf, 32) as usize).clamp(40, PAGE);
    vlog!(
        "  describe: max_reg_pages={} tx_entries={} rx_entries={} default_queues={} mtu={} counters={} tx_pages_per_qpl={} rx_pages_per_qpl={} options={} total_len={}",
        d.max_registered_pages, d.tx_entries, d.rx_entries, get_be16(buf, 14), d.mtu,
        d.counters, d.tx_pages_per_qpl, get_be16(buf, 22), num_opts, total_len
    );

    let mut off = 40usize;
    let mut gqi_qpl_mask: Option<u32> = None;
    let mut other_formats: Vec<u16> = Vec::new();
    let mut jumbo_mtu: Option<u32> = None;
    for _ in 0..num_opts {
        if off + 8 > total_len {
            log!("  describe: option header runs past total_length");
            return Err(Status::DEVICE_ERROR);
        }
        let id = get_be16(buf, off);
        let len = get_be16(buf, off + 2) as usize;
        let req = get_be32(buf, off + 4);
        let p = off + 8;
        if p + len > total_len {
            log!("  describe: option 0x{id:x} runs past total_length");
            return Err(Status::DEVICE_ERROR);
        }
        let mask = if len >= 4 { get_be32(buf, p) } else { 0 };
        vlog!("  option 0x{id:x} len={len} required_features=0x{req:x} mask=0x{mask:x}");
        if req == 0 {
            match id {
                OPT_GQI_QPL if len >= 4 => gqi_qpl_mask = Some(mask),
                OPT_JUMBO_FRAMES if len >= 6 => jumbo_mtu = Some(get_be16(buf, p + 4) as u32),
                OPT_GQI_RAW_ADDRESSING | OPT_GQI_RDA | OPT_DQO_RDA | OPT_DQO_QPL => {
                    other_formats.push(id)
                }
                _ => {}
            }
        }
        off = p + len;
    }

    // Queue format: GQI_QPL if offered, or if no format option is present at all (Linux's
    // default, gve_adminq.c:1158-1165). Otherwise this device needs a mode we don't drive.
    let mask = match gqi_qpl_mask {
        Some(m) => m,
        None if other_formats.is_empty() => 0,
        None => {
            log!("  describe: GQI_QPL not offered (formats offered: {other_formats:x?})");
            return Err(Status::UNSUPPORTED);
        }
    };
    if !other_formats.is_empty() {
        vlog!("  describe: also offered {other_formats:x?}; using GQI_QPL");
    }
    if let (Some(j), true) = (jumbo_mtu, mask & SUP_JUMBO_FRAMES != 0) {
        d.mtu = j;
    }
    Ok(d)
}

// ---- Queues -----------------------------------------------------------------------------

struct Tx {
    ring: Dma, // entries * 16 B packet descriptors
    qpl: Dma,  // tx_pages_per_qpl pages, carved into BUF-sized slots
    entries: u32,
    slots: u32,
    req: u32,  // free-running: descriptors posted
    done: u32, // free-running: descriptors reaped
    db_index: u32,
    counter: *const u8, // &counter_array[counter_index]
    callers: Vec<*const c_void>,
}

struct Rx {
    desc: Dma, // entries * 64 B, device-written
    data: Dma, // entries * 8 B: BE64 QPL offset per slot (= i * 4096, never changed)
    qpl: Dma,  // entries pages, one buffer per page at offset 0
    entries: u32,
    cnt: u32,  // free-running: descriptors consumed
    fill: u32, // free-running: slots posted
    seq: u16,  // expected seqno, 1..7
    db_index: u32,
    skip_cont: bool, // dropping the rest of a multi-fragment packet
}

/// A bound gVNIC: one TX + one RX GQI-QPL queue, polled.
pub struct Gvnic {
    pci: *const PciIoProtocol,
    /// Host address of BAR2 (doorbells), written directly (see the module docs).
    db: *mut u8,
    /// RX QPL id (TX is [`TX_QPL_ID`]), for unregistering at teardown.
    rx_qpl_id: u32,
    /// Device MTU (L3 payload; GCP default 1460), capped so a frame fits one 2 KiB buffer.
    pub mtu: u32,
    mac: [u8; 6],
    rev: u8,
    aq: AdminQueue,
    counters: Dma,
    irq_dbs: Dma,
    qres: Dma,
    tx: Tx,
    rx: Rx,
}

impl Gvnic {
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Release everything the device holds, then reset it (see [`on_exit_boot_services`]).
    unsafe fn teardown(&mut self) {
        let pci = &*self.pci;
        let steps: [(u32, Option<u32>); 5] = [
            (OP_DESTROY_TX_QUEUE, Some(0)),
            (OP_DESTROY_RX_QUEUE, Some(0)),
            (OP_UNREGISTER_PAGE_LIST, Some(TX_QPL_ID)),
            (OP_UNREGISTER_PAGE_LIST, Some(self.rx_qpl_id)),
            (OP_DECONFIGURE_DEVICE_RESOURCES, None),
        ];
        for (op, id) in steps {
            let mut c = cmd_new(op);
            if let Some(id) = id {
                cmd_be32(&mut c, 8, id);
            }
            if self.aq.exec(pci, &c).is_err() {
                break; // surrender to the reset (gve_close)
            }
        }
        let _ = reset(pci, self.rev);
    }

    /// RX is fully posted at probe (the data ring must be prefilled before CREATE_RX_QUEUE,
    /// spec §4.7), so SNP Initialize has nothing to do here.
    pub unsafe fn init_rx(&mut self) {}

    /// Copy one received frame into `out` (capacity `cap`); `None` if nothing is pending.
    /// Errored, multi-fragment, or oversized frames are consumed and dropped.
    pub unsafe fn receive(&mut self, out: *mut u8, cap: usize) -> Option<usize> {
        let db = self.db;
        let rx = &mut self.rx;
        loop {
            let idx = (rx.cnt % rx.entries) as usize;
            let d = rx.desc.host.add(idx * 64);
            let flags_seq = get_be16(d, 62);
            if flags_seq & 0x7 != rx.seq {
                return None;
            }
            fence(Ordering::Acquire);
            let len = get_be16(d, 60) as usize;
            let cont = flags_seq & RXF_PKT_CONT != 0;
            let mut got = None;
            if rx.skip_cont {
                rx.skip_cont = cont; // drop through the last fragment
            } else if flags_seq & RXF_ERR != 0 || cont || !(RX_PAD..=BUF).contains(&len) {
                rx.skip_cont = cont;
            } else {
                let n = len - RX_PAD;
                if n <= cap {
                    let src = rx.qpl.host.add(idx * PAGE + RX_PAD);
                    core::ptr::copy_nonoverlapping(src, out, n);
                    got = Some(n);
                }
            }
            // Hand the slot back only after its data was copied out (spec §7.5).
            rx.cnt = rx.cnt.wrapping_add(1);
            rx.seq = if rx.seq == 7 { 1 } else { rx.seq + 1 };
            rx.fill = rx.fill.wrapping_add(1);
            doorbell(db, rx.db_index, rx.fill);
            if got.is_some() {
                return got;
            }
        }
    }

    /// Queue one complete Ethernet frame. `caller` is the SNP buffer, handed back by
    /// `poll_tx()` once the device has consumed the descriptor.
    pub unsafe fn transmit(
        &mut self,
        data: *const u8,
        len: usize,
        caller: *const c_void,
    ) -> Result<(), Status> {
        let tx = &mut self.tx;
        if len == 0 || len > self.mtu as usize + ETH_HLEN {
            return Err(Status::INVALID_PARAMETER);
        }
        let in_flight = tx.req.wrapping_sub(tx.done);
        if in_flight >= tx.entries.min(tx.slots) {
            return Err(Status::NOT_READY);
        }
        let slot = (tx.req % tx.slots) as usize;
        let qpl_off = slot * BUF;
        core::ptr::copy_nonoverlapping(data, tx.qpl.host.add(qpl_off), len);
        // gve_tx_pkt_desc (gve_desc.h:26-34): type_flags=STD(0), offsets 0, desc_cnt=1,
        // len = seg_len = frame length, seg_addr = QPL byte offset.
        let d = tx.ring.host.add(((tx.req % tx.entries) * 16) as usize);
        d.write_volatile(0);
        d.add(1).write_volatile(0);
        d.add(2).write_volatile(0);
        d.add(3).write_volatile(1);
        put_be16(d, 4, len as u16);
        put_be16(d, 6, len as u16);
        put_be64(d, 8, qpl_off as u64);
        tx.callers[slot] = caller;
        tx.req = tx.req.wrapping_add(1);
        doorbell(self.db, tx.db_index, tx.req);
        Ok(())
    }

    /// Reap one completed TX: the caller's buffer pointer, or `None`.
    pub unsafe fn poll_tx(&mut self) -> Option<*const c_void> {
        let tx = &mut self.tx;
        let nic_done = get_be32(tx.counter, 0);
        fence(Ordering::Acquire);
        let completed = nic_done.wrapping_sub(tx.done);
        let in_flight = tx.req.wrapping_sub(tx.done);
        if completed == 0 || completed > in_flight {
            return None;
        }
        let slot = (tx.done % tx.slots) as usize;
        tx.done = tx.done.wrapping_add(1);
        Some(tx.callers[slot])
    }
}

/// Bring the device up (spec §10.1). On failure after the admin queue is registered the
/// device is reset, so nothing is left doing DMA.
pub unsafe fn probe(pci: &PciIoProtocol) -> Result<Gvnic, Status> {
    let rev = cfg_r8(pci, 0x08);
    vlog!("PCI 1ae0:0042 revision {rev}");

    // Memory decode + bus mastering; INTx disabled (Command bit 10). MSI-X left disabled.
    let st = (pci.attributes)(
        pci,
        PciAttrOp::Enable,
        PCI_ATTR_MEMORY | PCI_ATTR_BUS_MASTER,
        core::ptr::null_mut(),
    );
    if st.is_success() {
        vlog!("memory+bus-master enable: {st:?}");
    } else {
        log!("memory+bus-master enable: {st:?}");
    }
    cfg_w16(pci, 0x04, cfg_r16(pci, 0x04) | (1 << 10));

    let num_msix = msix_table_size(pci);
    if num_msix < 3 {
        log!("MSI-X table size {num_msix} < 3 (GVE_MIN_MSIX)");
        return Err(Status::UNSUPPORTED);
    }
    let num_ntfy = (num_msix - 1) & !1;
    let max_tx = reg_rd(pci, regs::MAX_TX_QUEUES);
    let max_rx = reg_rd(pci, regs::MAX_RX_QUEUES);
    let dev_status = reg_rd(pci, regs::DEVICE_STATUS);
    vlog!("msix={num_msix} ntfy_blks={num_ntfy} max_tx={max_tx} max_rx={max_rx} device_status=0x{dev_status:x}");
    if max_tx == 0 || max_rx == 0 {
        return Err(Status::DEVICE_ERROR);
    }

    for b in VERSION_STRING {
        mmio_write8(pci, REG_BAR, regs::DRIVER_VERSION, *b);
    }

    // Before the admin queue exists, so a failure here leaves nothing to reset.
    let (db_base, db_len) = bar_host_range(pci, DB_BAR)?;

    let aq_dma = Dma::alloc(pci, PAGE)?;
    register_adminq(pci, rev, &aq_dma);
    let ec = reg_rd(pci, regs::ADMINQ_EVENT_COUNTER);
    if ec != 0 {
        log!("event_counter={ec} after AQ registration (expected 0)");
    }
    let aq = AdminQueue {
        dma: aq_dma,
        prod: ec,
    };

    match bring_up(pci, rev, num_ntfy, max_tx, aq, db_base as *mut u8, db_len) {
        Ok(nic) => Ok(nic),
        Err(e) => {
            let ok = reset(pci, rev);
            log!(
                "bring-up failed ({e:?}); device reset {}",
                if ok { "OK" } else { "TIMED OUT" }
            );
            Err(e)
        }
    }
}

/// Steps 7-19 of the bring-up checklist; the admin queue moves into the returned device.
unsafe fn bring_up(
    pci: &PciIoProtocol,
    rev: u8,
    num_ntfy: u32,
    max_tx: u32,
    mut aq: AdminQueue,
    db: *mut u8,
    db_len: u64,
) -> Result<Gvnic, Status> {
    // VERIFY_DRIVER_COMPATIBILITY (spec §4.1): PASSED or UNIMPLEMENTED both fine.
    let info = Dma::alloc(pci, DRIVER_INFO_LEN)?;
    info.host.write_volatile(1); // os_type: 1 (the only value defined)
    put_be64(info.host, 16, DRIVER_CAP_GQI_QPL);
    for (i, b) in b"lockboot-gvnic".iter().enumerate() {
        info.host.add(48 + i).write_volatile(*b);
        info.host.add(176 + i).write_volatile(*b);
    }
    let mut c = cmd_new(OP_VERIFY_DRIVER_COMPATIBILITY);
    cmd_be64(&mut c, 8, DRIVER_INFO_LEN as u64);
    cmd_be64(&mut c, 16, info.dev);
    match aq.exec_status(pci, &c)? {
        AQ_PASSED => vlog!("  verify-driver-compatibility: PASSED"),
        AQ_UNIMPLEMENTED => vlog!("  verify-driver-compatibility: UNIMPLEMENTED (ok)"),
        s => {
            log!("  verify-driver-compatibility: status 0x{s:08x}");
            return Err(Status::DEVICE_ERROR);
        }
    }

    // DESCRIBE_DEVICE (spec §4.2).
    let desc_buf = Dma::alloc(pci, PAGE)?;
    let mut c = cmd_new(OP_DESCRIBE_DEVICE);
    cmd_be64(&mut c, 8, desc_buf.dev);
    cmd_be32(&mut c, 16, 1); // descriptor version
    cmd_be32(&mut c, 20, PAGE as u32); // available length
    aq.exec(pci, &c)?;
    let d = parse_describe(desc_buf.host)?;

    let pow2 = |n: u32| n != 0 && n.is_power_of_two();
    if !pow2(d.tx_entries) || !pow2(d.rx_entries) || d.counters == 0 || d.tx_pages_per_qpl == 0 {
        log!("  describe: unusable ring/counter geometry");
        return Err(Status::DEVICE_ERROR);
    }
    let pages_needed = d.tx_pages_per_qpl as u64 + d.rx_entries as u64;
    if pages_needed > d.max_registered_pages {
        log!("  describe: need {pages_needed} QPL pages > max_registered_pages");
        return Err(Status::DEVICE_ERROR);
    }
    if d.mtu < MTU_MIN {
        log!("  describe: mtu {} < {MTU_MIN}", d.mtu);
        return Err(Status::DEVICE_ERROR);
    }
    let mtu = d.mtu.min(MTU_CAP);

    // CONFIGURE_DEVICE_RESOURCES (spec §4.3): counter array + irq-doorbell index array.
    let counters = Dma::alloc(pci, d.counters as usize * 4)?;
    let irq_dbs = Dma::alloc(pci, num_ntfy as usize * 64)?;
    let mut c = cmd_new(OP_CONFIGURE_DEVICE_RESOURCES);
    cmd_be64(&mut c, 8, counters.dev);
    cmd_be64(&mut c, 16, irq_dbs.dev);
    cmd_be32(&mut c, 24, d.counters);
    cmd_be32(&mut c, 28, num_ntfy);
    cmd_be32(&mut c, 32, 64); // irq_db_stride
    cmd_be32(&mut c, 36, 0); // ntfy_blk_msix_base_idx
    cmd_u8(&mut c, 40, QUEUE_FORMAT_GQI_QPL);
    aq.exec(pci, &c)?;

    // Rings + QPLs. Queue resources: one page, TX at 0, RX at 64.
    let qres = Dma::alloc(pci, PAGE)?;
    let tx_ring = Dma::alloc(pci, d.tx_entries as usize * 16)?;
    let tx_qpl = Dma::alloc(pci, d.tx_pages_per_qpl as usize * PAGE)?;
    let rx_desc = Dma::alloc(pci, d.rx_entries as usize * 64)?;
    let rx_data = Dma::alloc(pci, d.rx_entries as usize * 8)?;
    let rx_qpl = Dma::alloc(pci, d.rx_entries as usize * PAGE)?;
    for i in 0..d.rx_entries as usize {
        put_be64(rx_data.host, i * 8, (i * PAGE) as u64);
    }

    // REGISTER_PAGE_LIST (spec §4.5): TX id 0, RX id min(max_tx, ntfy/2) (Linux's values).
    let tx_qpl_id = TX_QPL_ID;
    let rx_qpl_id = max_tx.min(num_ntfy / 2);
    for (id, qpl, pages) in [
        (tx_qpl_id, &tx_qpl, d.tx_pages_per_qpl),
        (rx_qpl_id, &rx_qpl, d.rx_entries),
    ] {
        let list = Dma::alloc(pci, pages as usize * 8)?;
        for i in 0..pages as usize {
            put_be64(list.host, i * 8, qpl.dev + (i * PAGE) as u64);
        }
        let mut c = cmd_new(OP_REGISTER_PAGE_LIST);
        cmd_be32(&mut c, 8, id);
        cmd_be32(&mut c, 12, pages);
        cmd_be64(&mut c, 16, list.dev);
        cmd_be64(&mut c, 24, PAGE as u64);
        aq.exec(pci, &c)?;
    }

    // CREATE_TX_QUEUE (spec §4.6).
    let mut c = cmd_new(OP_CREATE_TX_QUEUE);
    cmd_be32(&mut c, 8, 0); // queue_id
    cmd_be64(&mut c, 16, qres.dev);
    cmd_be64(&mut c, 24, tx_ring.dev);
    cmd_be32(&mut c, 32, tx_qpl_id);
    cmd_be32(&mut c, 36, 0); // ntfy_id
    cmd_be16(&mut c, 48, d.tx_entries as u16);
    aq.exec(pci, &c)?;
    let tx_db = get_be32(qres.host, 0);
    let tx_ctr = get_be32(qres.host, 4);

    // CREATE_RX_QUEUE (spec §4.7). Data ring is already prefilled.
    let mut c = cmd_new(OP_CREATE_RX_QUEUE);
    cmd_be32(&mut c, 8, 0); // queue_id
    cmd_be32(&mut c, 12, 0); // index
    cmd_be32(&mut c, 20, num_ntfy / 2); // ntfy_id
    cmd_be64(&mut c, 24, qres.dev + 64);
    cmd_be64(&mut c, 32, rx_desc.dev);
    cmd_be64(&mut c, 40, rx_data.dev);
    cmd_be32(&mut c, 48, rx_qpl_id);
    cmd_be16(&mut c, 52, d.rx_entries as u16);
    cmd_be16(&mut c, 54, BUF as u16); // packet_buffer_size
    aq.exec(pci, &c)?;
    let rx_db = get_be32(qres.host, 64);
    vlog!("  queues: tx db={tx_db} counter={tx_ctr}  rx db={rx_db}");
    if tx_ctr >= d.counters {
        log!(
            "  tx counter_index {tx_ctr} out of range ({} counters)",
            d.counters
        );
        return Err(Status::DEVICE_ERROR);
    }
    // The doorbells are written through a raw pointer: keep the device's indices inside BAR2.
    for (q, idx) in [("tx", tx_db), ("rx", rx_db)] {
        if 4 * idx as u64 + 4 > db_len {
            log!("  {q} doorbell index {idx} outside BAR2 ({db_len} bytes)");
            return Err(Status::DEVICE_ERROR);
        }
    }

    // Post every RX slot (spec §7.2 step 6).
    doorbell(db, rx_db, d.rx_entries);

    // Link (spec §2.5): Linux does not wait; we poll briefly and log.
    let mut link = false;
    for _ in 0..LINK_CHECKS {
        if reg_rd(pci, regs::DEVICE_STATUS) & DEV_STS_LINK_UP != 0 {
            link = true;
            break;
        }
        delay_ms(SLEEP_MS);
    }

    // The one line a successful probe prints by default (detail: the `verbose` feature).
    let m = d.mac;
    log!(
        "1ae0:0042 rev {rev}, GQI_QPL, 1 tx/1 rx, mtu {}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}",
        d.mtu,
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5],
        if link { "up" } else { "NOT up after 5s (continuing)" }
    );

    let tx_slots = (d.tx_pages_per_qpl as usize * PAGE / BUF) as u32;
    let tx_counter = counters.host.add(tx_ctr as usize * 4) as *const u8;
    Ok(Gvnic {
        pci,
        db,
        rx_qpl_id,
        mtu,
        mac: d.mac,
        rev,
        aq,
        counters,
        irq_dbs,
        qres,
        tx: Tx {
            counter: tx_counter,
            ring: tx_ring,
            qpl: tx_qpl,
            entries: d.tx_entries,
            slots: tx_slots,
            req: 0,
            done: 0,
            db_index: tx_db,
            callers: vec![core::ptr::null(); tx_slots as usize],
        },
        rx: Rx {
            desc: rx_desc,
            data: rx_data,
            qpl: rx_qpl,
            entries: d.rx_entries,
            cnt: 0,
            fill: d.rx_entries,
            seq: 1,
            db_index: rx_db,
            skip_cont: false,
        },
    })
}
