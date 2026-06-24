// SPDX-License-Identifier: MIT OR Apache-2.0

//! ENA hardware layer (clean-room). The register map, admin-queue mechanism, and
//! admin command/completion descriptor layouts are transcribed from the *public ENA
//! device contract* (the ABI documented by the `ena_com` communication layer) -- a
//! hardware interface, not GPL driver code. Keep it that way.
//!
//! Flow: reset -> read VERSION/CAPS -> build the admin SQ/CQ/AENQ -> negotiate
//! features (DEVICE_ATTRIBUTES, MAX_QUEUES_EXT, AENQ_CONFIG, HOST_ATTRIBUTES, LLQ) ->
//! create one TX and one RX IO queue pair -> hand off to snp.rs. The byte layouts are
//! confirmed against a real c6i device: admin commands succeed and the datapath
//! carries DHCP and HTTP traffic end to end.
//!
//! Non-obvious gotcha: on Nitro v4 the firmware rejects CREATE_CQ with UNKNOWN_ERROR
//! unless the HOST_INFO page carries a non-zero driver_version (see set_host_attributes).

// The register map (`regs`) is kept complete for reference, so some offsets are
// defined but unused; and several DMA fields are held only to keep the device's
// buffers alive (never read back). Both read as dead code; neither is a bug.
#![allow(dead_code)]

use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{fence, Ordering};

use uefi::boot;
use uefi::Status;

use crate::pci::{PciAttrOp, PciMapOp, PciWidth, PciIoProtocol, PCI_ATTR_BUS_MASTER};

/// `uefi::println!` with an `ena:` prefix; no alloc, writes straight to the console.
macro_rules! log {
    ($($a:tt)*) => { uefi::println!("ena: {}", format_args!($($a)*)) };
}

/// AWS PCI vendor id. Every Nitro ENA function reports this; `supported()` gates on it.
pub const ENA_VENDOR_ID: u16 = 0x1d0f;
/// ENA PCI device ids (PF, LLQ-PF, VF, LLQ-VF). MUST gate on these, not just vendor:
/// Amazon's NVMe (EBS) controllers also report vendor 0x1d0f, so a vendor-only match
/// binds the wrong devices and reads garbage at the ENA register offsets.
pub const ENA_DEVICE_IDS: &[u16] = &[0x0ec2, 0x1ec2, 0xec20, 0xec21];

/// ENA register BAR (memory-mapped control registers).
pub const ENA_REG_BAR: u8 = 0;

/// ENA controller register offsets (bytes from the register BAR base).
pub mod regs {
    pub const VERSION: u64 = 0x00;
    pub const CONTROLLER_VERSION: u64 = 0x04;
    pub const CAPS: u64 = 0x08;
    pub const CAPS_EXT: u64 = 0x0c;
    pub const AQ_BASE_LO: u64 = 0x10;
    pub const AQ_BASE_HI: u64 = 0x14;
    pub const AQ_CAPS: u64 = 0x18;
    pub const ACQ_BASE_LO: u64 = 0x20;
    pub const ACQ_BASE_HI: u64 = 0x24;
    pub const ACQ_CAPS: u64 = 0x28;
    pub const AQ_DB: u64 = 0x2c;
    pub const ACQ_TAIL: u64 = 0x30;
    pub const AENQ_CAPS: u64 = 0x34;
    pub const AENQ_BASE_LO: u64 = 0x38;
    pub const AENQ_BASE_HI: u64 = 0x3c;
    pub const AENQ_HEAD_DB: u64 = 0x40;
    pub const AENQ_TAIL: u64 = 0x44;
    pub const DEV_CTL: u64 = 0x54;
    pub const DEV_STS: u64 = 0x58;
    pub const MMIO_REG_READ: u64 = 0x5c;
    pub const MMIO_RESP_LO: u64 = 0x60;
    pub const MMIO_RESP_HI: u64 = 0x64;
}

// DEV_CTL bits.
const DEV_CTL_RESET: u32 = 1 << 0;
// DEV_STS bits (ena_regs DEV_STS layout). RESET_IN_PROGRESS is bit 3 (0x8), NOT bit 1.
const DEV_STS_READY: u32 = 1 << 0; // 0x01
const DEV_STS_RESET_IN_PROGRESS: u32 = 1 << 3; // 0x08
// CAPS fields: reset timeout in 100ms units at bits [6:1].
const CAPS_RESET_TIMEOUT_SHIFT: u32 = 1;
const CAPS_RESET_TIMEOUT_MASK: u32 = 0x3e;

// Admin opcodes (ena_admin_aq_opcode).
const OP_CREATE_SQ: u8 = 1;
const OP_CREATE_CQ: u8 = 3;
const OP_GET_FEATURE: u8 = 8;
const OP_SET_FEATURE: u8 = 9;
// Feature ids (ena_admin_aq_feature_id).
const FEAT_DEVICE_ATTRIBUTES: u8 = 1;
const FEAT_LLQ: u8 = 4;
const FEAT_MAX_QUEUES_EXT: u8 = 7;
const FEAT_AENQ_CONFIG: u8 = 26;
const FEAT_HOST_ATTRIBUTES: u8 = 28;
/// GET_FEATURE feature_version for MAX_QUEUES_EXT (ENA_FEATURE_MAX_QUEUE_EXT_VER).
const MAX_QUEUES_EXT_VER: u8 = 1;

// IO ring geometry. The ring DEPTH is queried from the device at runtime (its reported
// max CQ depth) rather than hardcoded -- iPXE's 32 is below the modern-Nitro minimum.
// The number of buffers we actually post is DECOUPLED from the ring depth and small: a
// poll-mode bootloader only needs a few outstanding packets, so a deep ring stays cheap.
const RX_FILL: usize = 64; // RX buffers posted into the ring
const TX_FILL: u16 = 64; // TX bounce buffers / max TX in-flight
const DEPTH_MIN: u16 = 128; // ring floor (DPDK ENA_MIN_RING_DESC) if the device read is bad
const DEPTH_MAX: u16 = 1024; // sanity ceiling on the device-reported max depth
const SQ_DESC_SIZE: usize = 16; // ena_eth_io_{tx,rx}_desc are 16 bytes
const RX_CDESC_WORDS: u8 = 4; // ena_eth_io_rx_cdesc_base = 16 bytes
const TX_CDESC_WORDS: u8 = 2; // ena_eth_io_tx_cdesc = 8 bytes
// CREATE_SQ sq_identity.sq_direction [6:5].
const SQ_DIR_TX: u8 = 1 << 5;
const SQ_DIR_RX: u8 = 2 << 5;
// CREATE_SQ caps: placement_policy HOST (1) in [3:0]; is_physically_contiguous bit0.
const SQ_PLACEMENT_HOST: u8 = 0x01;
const SQ_PHYS_CONTIG: u8 = 0x01;
// CREATE_CQ poll mode (matches iPXE, the proven-working c6i config): cq_caps_1 = 0 (no
// interrupt_mode) and msix_vector = NONE. The c6i firmware accepts this once the HOST_INFO
// driver_version is set (see set_host_attributes) -- that, not the CQ command, was the gate.
const CQ_CAPS_1_POLL_MODE: u8 = 0;
const ENA_MSIX_NONE: u32 = 0xffff_ffff;

/// RX/TX bounce buffer size (must exceed the 1500-byte MTU we advertise to the stack).
const BUF_SIZE: usize = 2048;
/// ena_eth_io_rx_desc.ctrl: FIRST(0x4) | LAST(0x8) | COMP_REQ(0x10), plus the phase bit.
const RX_DESC_CTRL: u8 = 0x04 | 0x08 | 0x10;
/// ena_eth_io_tx_desc.len_ctrl bits: FIRST(26) | LAST(27) | COMP_REQ(28), plus phase(24).
const TX_LEN_CTRL_FLAGS: u32 = (1 << 26) | (1 << 27) | (1 << 28);

// Little-endian field writes/reads into descriptor DMA memory, byte-wise (the rings are
// device-shared; byte access avoids any alignment assumptions on the wider fields).
unsafe fn wr_u16(p: *mut u8, off: usize, v: u16) {
    let b = v.to_le_bytes();
    p.add(off).write_volatile(b[0]);
    p.add(off + 1).write_volatile(b[1]);
}
unsafe fn wr_u32(p: *mut u8, off: usize, v: u32) {
    for (i, b) in v.to_le_bytes().iter().enumerate() {
        p.add(off + i).write_volatile(*b);
    }
}
unsafe fn rd_u8(p: *const u8, off: usize) -> u8 {
    p.add(off).read_volatile()
}
unsafe fn rd_u16(p: *const u8, off: usize) -> u16 {
    u16::from_le_bytes([p.add(off).read_volatile(), p.add(off + 1).read_volatile()])
}

// Admin ring geometry. Entries are 64 bytes; depth must be a power of two.
const ADMIN_DEPTH: u16 = 16;
const ADMIN_ENTRY_SIZE: u32 = 64;
const AENQ_DEPTH: u16 = 2; // ENA_AENQ_COUNT
const AENQ_ENTRY_SIZE: u32 = 64; // ena_admin_aenq_entry is 64 bytes (was wrongly 16)
// AQ/ACQ caps register layout: depth in [15:0], entry-size in [31:16].
fn caps_word(depth: u16, entry_size: u32) -> u32 {
    (depth as u32) | (entry_size << 16)
}

const PAGE: usize = 4096;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_ALLOCATE_ANY_PAGES: u32 = 0;

/// Enable MSI-X AND populate the table. The OS drivers that work on c6i (Linux/OpenBSD/
/// Enable the function's MSI-X capability (set the Enable bit in Message Control). We poll
/// the rings (CQ msix_vector = NONE) and never program table entries or service interrupts,
/// so this is just to leave MSI-X in a sane enabled state. Walks the PCI cap list for id
/// 0x11. (Likely not strictly required now that HOST_INFO gates CREATE_CQ, but cheap.)
unsafe fn enable_msix(pci: &PciIoProtocol) {
    let cfg_r8 = |off: u32| -> u8 {
        let mut v: u8 = 0;
        let _ = (pci.pci.read)(pci, PciWidth::U8, off, 1, (&mut v as *mut u8).cast());
        v
    };
    let mut off = (cfg_r8(0x34) & 0xfc) as u32; // capabilities pointer (dword-aligned)
    while off != 0 {
        let cap_id = cfg_r8(off);
        let next = cfg_r8(off + 1);
        if cap_id == 0x11 {
            // Message Control is a u16 at cap+2; bit 15 = MSI-X Enable.
            let mc_off = off + 2;
            let mut mc: u16 = 0;
            let _ = (pci.pci.read)(pci, PciWidth::U16, mc_off, 1, (&mut mc as *mut u16).cast());
            mc |= 1 << 15;
            let _ = (pci.pci.write)(pci, PciWidth::U16, mc_off, 1, (&mut mc as *mut u16).cast());
            return;
        }
        off = (next & 0xfc) as u32;
    }
}

// ---- MMIO helpers (BAR 0) ------------------------------------------------------

unsafe fn reg_read32(pci: &PciIoProtocol, off: u64) -> u32 {
    let mut v: u32 = 0;
    let st = (pci.mem.read)(pci, PciWidth::U32, ENA_REG_BAR, off, 1, (&mut v as *mut u32).cast());
    if !st.is_success() {
        log!("  MMIO read @0x{off:02x} failed: {st:?}");
    }
    v
}

unsafe fn reg_write32(pci: &PciIoProtocol, off: u64, val: u32) {
    let mut v = val;
    let st = (pci.mem.write)(pci, PciWidth::U32, ENA_REG_BAR, off, 1, (&mut v as *mut u32).cast());
    if !st.is_success() {
        log!("  MMIO write @0x{off:02x} failed: {st:?}");
    }
}

fn delay_ms(ms: usize) {
    boot::stall(ms * 1000);
}

// ---- DMA (common buffer via PciIo) --------------------------------------------

/// A coherent DMA region: host-virtual pointer + device bus address.
struct Dma {
    host: *mut u8,
    dev: u64,
    mapping: *mut c_void,
    pages: usize,
}

impl Dma {
    /// Allocate `bytes` (rounded to pages), zeroed, and map it as a bus-master common
    /// buffer. Replaces iPXE malloc_phys + virt_to_bus.
    unsafe fn alloc(pci: &PciIoProtocol, bytes: usize) -> Result<Dma, Status> {
        let pages = bytes.div_ceil(PAGE);
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
            return Err(if st.is_success() { Status::OUT_OF_RESOURCES } else { st });
        }
        core::ptr::write_bytes(host as *mut u8, 0, pages * PAGE);

        let mut nbytes: usize = pages * PAGE;
        let mut dev: u64 = 0;
        let mut mapping: *mut c_void = core::ptr::null_mut();
        let st = (pci.map)(
            pci,
            PciMapOp::BusMasterCommonBuffer,
            host as *const c_void,
            &mut nbytes,
            &mut dev,
            &mut mapping,
        );
        if !st.is_success() {
            log!("  Map failed: {st:?}");
            let _ = (pci.free_buffer)(pci, pages, host);
            return Err(st);
        }
        Ok(Dma { host: host as *mut u8, dev, pages, mapping })
    }
}

// ---- Admin queue ---------------------------------------------------------------

struct AdminQueue {
    sq: Dma,
    cq: Dma,
    aenq: Dma, // held so its DMA stays mapped for the device; we poll, never read it
    sq_tail: u16,
    cq_head: u16,
    sq_phase: u8,
    cq_phase: u8,
    cmd_id: u16,
}

impl AdminQueue {
    unsafe fn create(pci: &PciIoProtocol) -> Result<AdminQueue, Status> {
        let sq = Dma::alloc(pci, ADMIN_DEPTH as usize * ADMIN_ENTRY_SIZE as usize)?;
        let cq = Dma::alloc(pci, ADMIN_DEPTH as usize * ADMIN_ENTRY_SIZE as usize)?;
        let aenq = Dma::alloc(pci, AENQ_DEPTH as usize * AENQ_ENTRY_SIZE as usize)?;
        log!("  admin DMA: sq dev=0x{:x} cq dev=0x{:x} aenq dev=0x{:x}", sq.dev, cq.dev, aenq.dev);

        // Exact ena_com_admin_init order: AQ base, ACQ base, AQ caps, ACQ caps, THEN the
        // AENQ (base, caps, head doorbell). The openbsd-ena writeup found the device only
        // wires a subsystem if its registers are written in this init window/order.
        reg_write32(pci, regs::AQ_BASE_LO, sq.dev as u32);
        reg_write32(pci, regs::AQ_BASE_HI, (sq.dev >> 32) as u32);
        reg_write32(pci, regs::ACQ_BASE_LO, cq.dev as u32);
        reg_write32(pci, regs::ACQ_BASE_HI, (cq.dev >> 32) as u32);
        fence(Ordering::SeqCst);
        reg_write32(pci, regs::AQ_CAPS, caps_word(ADMIN_DEPTH, ADMIN_ENTRY_SIZE));
        reg_write32(pci, regs::ACQ_CAPS, caps_word(ADMIN_DEPTH, ADMIN_ENTRY_SIZE));
        fence(Ordering::SeqCst);
        // AENQ: base, then caps, then head doorbell (q_depth = all slots initially free).
        reg_write32(pci, regs::AENQ_BASE_LO, aenq.dev as u32);
        reg_write32(pci, regs::AENQ_BASE_HI, (aenq.dev >> 32) as u32);
        fence(Ordering::SeqCst);
        reg_write32(pci, regs::AENQ_CAPS, caps_word(AENQ_DEPTH, AENQ_ENTRY_SIZE));
        reg_write32(pci, regs::AENQ_HEAD_DB, AENQ_DEPTH as u32);
        fence(Ordering::SeqCst);

        Ok(AdminQueue {
            sq,
            cq,
            aenq,
            sq_tail: 0,
            cq_head: 0,
            sq_phase: 1,
            cq_phase: 1,
            cmd_id: 0,
        })
    }

    /// Submit a 64-byte command, ring the doorbell, poll the completion ring for the
    /// matching phase, and copy out the 64-byte completion entry. Returns the raw
    /// completion bytes (caller parses) and the admin `status` byte.
    unsafe fn submit(&mut self, pci: &PciIoProtocol, cmd: &[u8; 64]) -> Result<[u8; 64], Status> {
        // Stamp command id + phase into the common descriptor (bytes 0..4):
        //   [0..2] command_id, [2] opcode (already set by caller), [3] flags(phase bit0).
        let id = self.cmd_id;
        self.cmd_id = self.cmd_id.wrapping_add(1);
        let slot = (self.sq_tail % ADMIN_DEPTH) as usize;
        let dst = self.sq.host.add(slot * ADMIN_ENTRY_SIZE as usize);
        core::ptr::copy_nonoverlapping(cmd.as_ptr(), dst, 64);
        // command_id (u16, little-endian) at offset 0.
        dst.add(0).write_volatile(id as u8);
        dst.add(1).write_volatile((id >> 8) as u8);
        // flags: set phase bit, preserve caller's other flag bits.
        let flags = (*cmd)[3] | (self.sq_phase & 1);
        dst.add(3).write_volatile(flags);
        fence(Ordering::SeqCst);

        // Advance tail (free-running, wraps the ring; phase flips on wrap).
        self.sq_tail = self.sq_tail.wrapping_add(1);
        if self.sq_tail % ADMIN_DEPTH == 0 {
            self.sq_phase ^= 1;
        }
        reg_write32(pci, regs::AQ_DB, self.sq_tail as u32);
        fence(Ordering::SeqCst);

        // Poll the completion ring for an entry whose phase matches what we expect.
        let cslot = (self.cq_head % ADMIN_DEPTH) as usize;
        let centry = self.cq.host.add(cslot * ADMIN_ENTRY_SIZE as usize);
        let deadline_ticks = 1000; // ~1s at 1ms granularity
        let mut waited = 0;
        loop {
            fence(Ordering::SeqCst);
            let cflags = centry.add(3).read_volatile();
            if (cflags & 1) == (self.cq_phase & 1) {
                break;
            }
            if waited >= deadline_ticks {
                log!("  !! admin completion timeout (cq_head={} phase={})", self.cq_head, self.cq_phase);
                return Err(Status::TIMEOUT);
            }
            delay_ms(1);
            waited += 1;
        }

        let status = centry.add(2).read_volatile();

        let mut out = [0u8; 64];
        for (i, b) in out.iter_mut().enumerate() {
            *b = centry.add(i).read_volatile();
        }

        // Advance completion head; flip expected phase on wrap.
        self.cq_head = self.cq_head.wrapping_add(1);
        if self.cq_head % ADMIN_DEPTH == 0 {
            self.cq_phase ^= 1;
        }

        if status != 0 {
            let ext = (out[5] as u16) << 8 | out[4] as u16;
            log!("  !! admin cmd opcode={} failed: status={status} ext=0x{ext:04x}", (*cmd)[2]);
            return Err(Status::DEVICE_ERROR);
        }
        Ok(out)
    }
}

// ---- IO queues -----------------------------------------------------------------

/// A created IO queue (CQ or SQ): device index + MMIO doorbell offset + its DMA ring.
struct IoQueue {
    idx: u16,
    db_off: u32,
    dma: Dma,
}

/// Write a 64-bit device address into an `ena_common_mem_addr` field at `off`:
/// addr_lo (u32) then addr_hi (u16) then 2 reserved bytes.
fn write_mem_addr(buf: &mut [u8; 64], off: usize, dev: u64) {
    buf[off..off + 4].copy_from_slice(&(dev as u32).to_le_bytes());
    buf[off + 4..off + 6].copy_from_slice(&((dev >> 32) as u16).to_le_bytes());
}

/// CREATE_CQ: allocate the completion ring and register it. Returns the assigned
/// cq index and the CQ head doorbell MMIO offset (from the admin response).
unsafe fn create_cq(
    pci: &PciIoProtocol,
    admin: &mut AdminQueue,
    depth: u16,
    entry_words: u8,
    msix_vector: u32,
) -> Result<IoQueue, Status> {
    let dma = Dma::alloc(pci, depth as usize * entry_words as usize * 4)?;
    log!("  create_cq: dev=0x{:x} words={entry_words} depth={depth} vec={msix_vector}", dma.dev);
    let mut cmd = [0u8; 64];
    cmd[2] = OP_CREATE_CQ;
    cmd[4] = CQ_CAPS_1_POLL_MODE; // cq_caps_1: poll mode, no interrupt (see const)
    cmd[5] = entry_words & 0x1f; // cq_caps_2.cq_entry_size_words
    cmd[6..8].copy_from_slice(&depth.to_le_bytes()); // cq_depth
    cmd[8..12].copy_from_slice(&msix_vector.to_le_bytes()); // msix_vector (real index, MSI-X on)
    write_mem_addr(&mut cmd, 12, dma.dev); // cq_ba
    let resp = admin.submit(pci, &cmd)?;
    let idx = u16::from_le_bytes([resp[8], resp[9]]);
    let db_off = u32::from_le_bytes([resp[16], resp[17], resp[18], resp[19]]);
    Ok(IoQueue { idx, db_off, dma })
}

/// CREATE_SQ: allocate the submission ring and register it against `cq_idx`.
/// Returns the assigned sq index and the SQ tail doorbell MMIO offset.
unsafe fn create_sq(
    pci: &PciIoProtocol,
    admin: &mut AdminQueue,
    depth: u16,
    cq_idx: u16,
    direction: u8,
) -> Result<IoQueue, Status> {
    let dma = Dma::alloc(pci, depth as usize * SQ_DESC_SIZE)?;
    let mut cmd = [0u8; 64];
    cmd[2] = OP_CREATE_SQ;
    cmd[4] = direction; // sq_identity.sq_direction
    cmd[6] = SQ_PLACEMENT_HOST; // sq_caps_2.placement_policy
    cmd[7] = SQ_PHYS_CONTIG; // sq_caps_3.is_physically_contiguous
    cmd[8..10].copy_from_slice(&cq_idx.to_le_bytes());
    cmd[10..12].copy_from_slice(&depth.to_le_bytes());
    write_mem_addr(&mut cmd, 12, dma.dev); // sq_ba (head_writeback at 20 left zero)
    let resp = admin.submit(pci, &cmd)?;
    let idx = u16::from_le_bytes([resp[8], resp[9]]);
    let db_off = u32::from_le_bytes([resp[12], resp[13], resp[14], resp[15]]);
    Ok(IoQueue { idx, db_off, dma })
}

/// Configure the AENQ groups like Linux does: read the supported groups, then enable them
/// except KEEP_ALIVE (bit 4), which we don't drain. (Not load-bearing for bring-up -- the
/// CREATE_CQ gate is HOST_INFO driver_version, not this -- but matches the reference.)
unsafe fn set_aenq_config(pci: &PciIoProtocol, admin: &mut AdminQueue) -> Result<(), Status> {
    // GET_FEATURE(AENQ_CONFIG): supported_groups at response [8].
    let mut g = [0u8; 64];
    g[2] = OP_GET_FEATURE;
    g[17] = FEAT_AENQ_CONFIG;
    let supported = match admin.submit(pci, &g) {
        Ok(r) => u32::from_le_bytes([r[8], r[9], r[10], r[11]]),
        Err(_) => 0x0f,
    };
    let enabled = supported & 0x0f; // link/fatal/warning/notification, not keep-alive
    log!("AENQ: supported=0x{supported:08x} enabling=0x{enabled:08x}");
    let mut cmd = [0u8; 64];
    cmd[2] = OP_SET_FEATURE;
    cmd[17] = FEAT_AENQ_CONFIG;
    cmd[24..28].copy_from_slice(&enabled.to_le_bytes()); // ena_admin_feature_aenq_desc.enabled_groups
    admin.submit(pci, &cmd)?;
    Ok(())
}

/// SET_FEATURE(HOST_ATTRIBUTES): register a host-info page (os_info_ba at [20..28]).
/// The page can stay mostly zero; the device just needs a valid DMA address (we set a
/// plausible ENA spec version). The buffer is leaked (never freed) so it stays valid.
unsafe fn set_host_attributes(pci: &PciIoProtocol, admin: &mut AdminQueue) -> Result<(), Status> {
    let info = Dma::alloc(pci, PAGE)?;
    // ena_admin_host_info. os_type (u32 at 0) must be known (0 -> ILLEGAL_PARAMETER);
    // ena_spec_version (u16 at 184) = major 2, minor 0. CRITICAL on c6i/Nitro-v4: the
    // firmware gates CREATE_CQ on a real driver_version (u32 at 172) -- a zero version
    // (what a from-scratch driver leaves) makes CREATE_CQ fail with UNKNOWN_ERROR even
    // though HOST_ATTRIBUTES itself succeeds. driver_version major byte must be >= 2
    // (per the iPXE c6i fix). Layout: major[7:0] minor[15:8] sub_minor[23:16].
    wr_u32(info.host, 0, 1); // ENA_ADMIN_OS_LINUX
    wr_u32(info.host, 172, 0x0000_0002); // driver_version 2.0.0 (major 2)
    wr_u16(info.host, 184, 0x0200);
    let mut cmd = [0u8; 64];
    cmd[2] = OP_SET_FEATURE;
    cmd[17] = FEAT_HOST_ATTRIBUTES;
    write_mem_addr(&mut cmd, 20, info.dev); // os_info_ba
    admin.submit(pci, &cmd)?;
    core::mem::forget(info); // keep the page mapped for the device's lifetime
    Ok(())
}

// ---- Device + datapath ---------------------------------------------------------

/// A live ENA device: MMIO handle, MAC, and one RX + one TX queue pair with their
/// buffers and ring cursors. All DMA is leaked for the device's lifetime.
pub struct Ena {
    pci: *const PciIoProtocol,
    mac: [u8; 6],
    pub mtu: u32,
    depth: u16, // IO ring depth, queried from the device (see DEPTH_MIN/MAX)
    _admin: AdminQueue, // kept so its DMA isn't freed
    rx_cq: IoQueue,
    rx_sq: IoQueue,
    tx_cq: IoQueue,
    tx_sq: IoQueue,
    rx_bufs: Vec<Dma>,
    tx_bufs: Vec<Dma>,
    rx_sq_tail: u16,
    rx_sq_phase: u8,
    rx_cq_head: u16,
    rx_cq_phase: u8,
    tx_sq_tail: u16,
    tx_sq_phase: u8,
    tx_cq_head: u16,
    tx_cq_phase: u8,
    tx_caller: [*const c_void; TX_FILL as usize],
}

impl Ena {
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    unsafe fn db(&self, off: u32, val: u32) {
        reg_write32(&*self.pci, off as u64, val);
    }

    /// Post RX buffer `buf_idx` into the RX SQ and ring its doorbell (req_id = buf_idx,
    /// so the completion identifies which buffer holds the packet).
    unsafe fn post_rx(&mut self, buf_idx: usize) {
        let slot = (self.rx_sq_tail % self.depth) as usize;
        let d = self.rx_sq.dma.host.add(slot * SQ_DESC_SIZE);
        let dev = self.rx_bufs[buf_idx].dev;
        wr_u16(d, 0, BUF_SIZE as u16); // length
        d.add(2).write_volatile(0);
        d.add(3).write_volatile(RX_DESC_CTRL | (self.rx_sq_phase & 1)); // ctrl
        wr_u16(d, 4, buf_idx as u16); // req_id
        wr_u16(d, 6, 0);
        wr_u32(d, 8, dev as u32); // buff_addr_lo
        wr_u16(d, 12, (dev >> 32) as u16); // buff_addr_hi
        wr_u16(d, 14, 0);
        fence(Ordering::SeqCst);
        self.rx_sq_tail = self.rx_sq_tail.wrapping_add(1);
        if self.rx_sq_tail % self.depth == 0 {
            self.rx_sq_phase ^= 1;
        }
        self.db(self.rx_sq.db_off, self.rx_sq_tail as u32);
    }

    /// Post all RX buffers (called from SNP Initialize).
    pub unsafe fn init_rx(&mut self) {
        for i in 0..self.rx_bufs.len() {
            self.post_rx(i);
        }
        log!("rx: posted {} buffers", self.rx_bufs.len());
    }

    /// Receive one frame into `out` (cap bytes); returns the byte count, or None if the
    /// RX completion ring is empty. Refills the consumed buffer.
    pub unsafe fn receive(&mut self, out: *mut u8, cap: usize) -> Option<usize> {
        let slot = (self.rx_cq_head % self.depth) as usize;
        let c = self.rx_cq.dma.host.add(slot * (RX_CDESC_WORDS as usize * 4));
        if (rd_u8(c, 3) & 1) != (self.rx_cq_phase & 1) {
            return None; // status bit24 (byte3 bit0) = phase: not yet written
        }
        fence(Ordering::SeqCst);
        let length = rd_u16(c, 4) as usize;
        let req_id = rd_u16(c, 6) as usize;
        let n = length.min(cap);
        if req_id < self.rx_bufs.len() {
            core::ptr::copy_nonoverlapping(self.rx_bufs[req_id].host, out, n);
        }
        self.rx_cq_head = self.rx_cq_head.wrapping_add(1);
        if self.rx_cq_head % self.depth == 0 {
            self.rx_cq_phase ^= 1;
        }
        if req_id < self.rx_bufs.len() {
            self.post_rx(req_id); // recycle
        }
        Some(n)
    }

    /// Queue `len` bytes from `data` for transmit (copied into a bounce buffer).
    /// `caller` is handed back by `poll_tx` once the hardware completes it.
    pub unsafe fn transmit(&mut self, data: *const u8, len: usize, caller: *const c_void) -> Result<(), Status> {
        // Limited by the bounce-buffer count, not the ring depth (buffers are decoupled).
        if self.tx_sq_tail.wrapping_sub(self.tx_cq_head) >= TX_FILL {
            return Err(Status::NOT_READY); // caller must GetStatus to drain completions
        }
        let bslot = (self.tx_sq_tail % TX_FILL) as usize; // bounce buffer index
        let slot = (self.tx_sq_tail % self.depth) as usize; // SQ descriptor slot
        let n = len.min(BUF_SIZE);
        core::ptr::copy_nonoverlapping(data, self.tx_bufs[bslot].host, n);
        let dev = self.tx_bufs[bslot].dev;
        let d = self.tx_sq.dma.host.add(slot * SQ_DESC_SIZE);
        let phase = (self.tx_sq_phase as u32 & 1) << 24;
        wr_u32(d, 0, (n as u32 & 0xffff) | phase | TX_LEN_CTRL_FLAGS); // len_ctrl
        wr_u32(d, 4, 0); // meta_ctrl
        wr_u32(d, 8, dev as u32); // buff_addr_lo
        wr_u32(d, 12, (dev >> 32) as u32 & 0xffff); // buff_addr_hi, header_length = 0
        fence(Ordering::SeqCst);
        self.tx_caller[bslot] = caller;
        self.tx_sq_tail = self.tx_sq_tail.wrapping_add(1);
        if self.tx_sq_tail % self.depth == 0 {
            self.tx_sq_phase ^= 1;
        }
        self.db(self.tx_sq.db_off, self.tx_sq_tail as u32);
        Ok(())
    }

    /// Reap one completed transmit; returns the `caller` token, or None. TX completes in
    /// submission order on a single SQ, so the completion slot matches the submit slot.
    pub unsafe fn poll_tx(&mut self) -> Option<*const c_void> {
        let slot = (self.tx_cq_head % self.depth) as usize;
        let c = self.tx_cq.dma.host.add(slot * (TX_CDESC_WORDS as usize * 4));
        if (rd_u8(c, 3) & 1) != (self.tx_cq_phase & 1) {
            return None; // tx cdesc flags.phase (byte3 bit0)
        }
        let caller = self.tx_caller[(self.tx_cq_head % TX_FILL) as usize];
        self.tx_cq_head = self.tx_cq_head.wrapping_add(1);
        if self.tx_cq_head % self.depth == 0 {
            self.tx_cq_phase ^= 1;
        }
        Some(caller)
    }
}

// ---- Device probe --------------------------------------------------------------

/// Reset the device, read identity, set up the admin queue, and read DEVICE_ATTRIBUTES
/// (MAC + max MTU). Prints each milestone. `pci` must outlive the returned `Ena`.
pub unsafe fn probe(pci: &PciIoProtocol) -> Result<Ena, Status> {
    // Record which ENA variant we bound (PCI config dword 0 = vendor | device<<16).
    let mut vd: u32 = 0;
    let _ = (pci.pci.read)(pci, PciWidth::U32, 0, 1, (&mut vd as *mut u32).cast());
    log!("PCI vendor=0x{:04x} device=0x{:04x}", vd as u16, (vd >> 16) as u16);

    // Enable bus mastering before any DMA.
    let st = (pci.attributes)(pci, PciAttrOp::Enable, PCI_ATTR_BUS_MASTER, core::ptr::null_mut());
    log!("bus-master enable: {st:?}");

    // Leave the function's MSI-X capability enabled (we still poll; CQ vector = NONE).
    enable_msix(pci);

    let version = reg_read32(pci, regs::VERSION);
    let caps = reg_read32(pci, regs::CAPS);
    log!("VERSION=0x{version:08x} CAPS=0x{caps:08x}");

    reset(pci, caps)?;

    // Set up the MMIO "readless" response buffer (Linux does this unconditionally in
    // ena_com_mmio_reg_read_request_init). We read registers directly (confirmed reliable
    // on Nitro), but the device wants a valid mmio_resp address registered.
    let resp = Dma::alloc(pci, PAGE)?;
    reg_write32(pci, regs::MMIO_RESP_LO, resp.dev as u32);
    reg_write32(pci, regs::MMIO_RESP_HI, (resp.dev >> 32) as u32);
    fence(Ordering::SeqCst);
    core::mem::forget(resp); // keep mapped for the device's lifetime

    let mut admin = AdminQueue::create(pci)?;

    // GET_FEATURE(DEVICE_ATTRIBUTES): direct feature (no control buffer).
    // ena_admin_get_feat_cmd byte layout:
    //   [0..4]  aq_common_desc (id/opcode/flags filled by submit)
    //   [4..16] control_buffer (length=0, addr=0 for a direct feature)
    //   [16]    feat_common.flags (select=0 => current value)
    //   [17]    feat_common.feature_id
    //   [18]    feat_common.feature_version
    let mut cmd = [0u8; 64];
    cmd[2] = OP_GET_FEATURE;
    cmd[17] = FEAT_DEVICE_ATTRIBUTES;
    cmd[18] = 0;
    let resp = admin.submit(pci, &cmd)?;

    // get_feat_resp: 8-byte acq_common_desc, then device_attr_feature_desc.
    //   mac_addr[6] at +32, max_mtu(u32) at +40.
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&resp[32..38]);
    let mtu = u32::from_le_bytes([resp[40], resp[41], resp[42], resp[43]]);
    log!("DEVICE_ATTRIBUTES: mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} max_mtu={mtu}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Init SET_FEATUREs the firmware requires before IO-queue creation (matches iPXE):
    // configure async-event groups, then register the host-info page (whose driver_version
    // is what actually un-gates CREATE_CQ on Nitro v4). Logged best-effort so a failure
    // here localizes the cause rather than masquerading as a queue error.
    match set_aenq_config(pci, &mut admin) {
        Ok(()) => {}
        Err(e) => log!("!! set AENQ config failed: {e:?}"),
    }
    match set_host_attributes(pci, &mut admin) {
        Ok(()) => log!("host attributes set"),
        Err(e) => log!("!! set host attributes failed: {e:?}"),
    }

    // Query MAX_QUEUES_EXT for the device's real max CQ depth; we size our rings from it
    // (iPXE's fixed 32 is below the modern-Nitro minimum). Falls back to DEPTH_MAX.
    let mut dev_cq_depth: u16 = DEPTH_MAX;
    {
        let mut q = [0u8; 64];
        q[2] = OP_GET_FEATURE;
        q[17] = FEAT_MAX_QUEUES_EXT;
        q[18] = MAX_QUEUES_EXT_VER;
        match admin.submit(pci, &q) {
            Ok(r) => {
                // GET_FEATURE response: feature data at [8]; queue_ext_feature_desc =
                // version[8] + reserved[9..12] + fields at [12]. Depths: tx_cq @ [32],
                // rx_cq @ [40] (fields offset +20 / +28).
                let u32at = |o: usize| u32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
                let (txd, rxd) = (u32at(32), u32at(40));
                log!(
                    "MAX_QUEUES_EXT: tx_cq_num={} rx_cq_num={} tx_cq_depth={txd} rx_cq_depth={rxd}",
                    u32at(16), u32at(24)
                );
                dev_cq_depth = txd.min(rxd).min(u32::from(u16::MAX)) as u16;
            }
            Err(e) => log!("!! MAX_QUEUES_EXT query failed: {e:?}"),
        }
    }

    // Negotiate LLQ (feature 4): on Nitro v4+ (c6i) the firmware appears to gate IO queue
    // creation on the placement-policy handshake even for host-memory queues. Read the
    // supported control fields, then SET_FEATURE the Linux defaults. Best-effort.
    {
        let mut g = [0u8; 64];
        g[2] = OP_GET_FEATURE;
        g[17] = FEAT_LLQ;
        match admin.submit(pci, &g) {
            Ok(r) => {
                // ena_admin_feature_llq_desc at [8]. supported control fields:
                let u32at = |o: usize| u32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
                let u16at = |o: usize| u16::from_le_bytes([r[o], r[o + 1]]);
                log!(
                    "LLQ: num={} depth={} hdr_loc_sup=0x{:x} entry_sz_sup=0x{:x} desc_num_sup=0x{:x} stride_sup=0x{:x}",
                    u32at(8), u32at(12), u16at(16), u16at(20), u16at(24), u16at(28)
                );
                // SET_FEATURE(LLQ) with Linux's defaults: inline header (1), 128B entry
                // (1), 2 descs-before-header (2), multiple-descs-per-entry stride (2).
                // ena_admin_feature_llq_desc enabled fields in the SET command (data @ [20]).
                let mut s = [0u8; 64];
                s[2] = OP_SET_FEATURE;
                s[17] = FEAT_LLQ;
                s[30..32].copy_from_slice(&1u16.to_le_bytes()); // header_location_ctrl_enabled
                s[34..36].copy_from_slice(&1u16.to_le_bytes()); // entry_size_ctrl_enabled
                s[38..40].copy_from_slice(&2u16.to_le_bytes()); // desc_num_before_header_enabled
                s[42..44].copy_from_slice(&2u16.to_le_bytes()); // descriptors_stride_ctrl_enabled
                match admin.submit(pci, &s) {
                    Ok(_) => log!("LLQ SET ok"),
                    Err(e) => log!("!! LLQ SET failed: {e:?}"),
                }
            }
            Err(e) => log!("!! LLQ query failed: {e:?}"),
        }
    }

    // Ring depth from the device max, bounded for sanity. SQ and CQ share it.
    let depth = dev_cq_depth.clamp(DEPTH_MIN, DEPTH_MAX);
    log!("using IO ring depth {depth} (device max {dev_cq_depth})");

    // Create one TX and one RX IO queue pair (TX first, matching iPXE). Order: CQ
    // first, then its SQ (the SQ references the CQ by index). Doorbells come back in
    // the responses. We poll the rings (msix vector = none).
    log!("creating IO queues (depth {depth})...");
    let tx_cq = create_cq(pci, &mut admin, depth, TX_CDESC_WORDS, ENA_MSIX_NONE)?;
    let tx_sq = create_sq(pci, &mut admin, depth, tx_cq.idx, SQ_DIR_TX)?;
    log!("  tx: cq idx={} db=0x{:x}  sq idx={} db=0x{:x}", tx_cq.idx, tx_cq.db_off, tx_sq.idx, tx_sq.db_off);
    let rx_cq = create_cq(pci, &mut admin, depth, RX_CDESC_WORDS, ENA_MSIX_NONE)?;
    let rx_sq = create_sq(pci, &mut admin, depth, rx_cq.idx, SQ_DIR_RX)?;
    log!("  rx: cq idx={} db=0x{:x}  sq idx={} db=0x{:x}", rx_cq.idx, rx_cq.db_off, rx_sq.idx, rx_sq.db_off);

    // RX + TX buffers: a small fixed fill, decoupled from the (possibly deep) ring.
    let mut rx_bufs = Vec::with_capacity(RX_FILL);
    let mut tx_bufs = Vec::with_capacity(TX_FILL as usize);
    for _ in 0..RX_FILL {
        rx_bufs.push(Dma::alloc(pci, BUF_SIZE)?);
    }
    for _ in 0..TX_FILL {
        tx_bufs.push(Dma::alloc(pci, BUF_SIZE)?);
    }
    log!("IO queues created OK; {} rx + {} tx buffers allocated", rx_bufs.len(), tx_bufs.len());

    Ok(Ena {
        pci: pci as *const PciIoProtocol,
        mac,
        mtu,
        depth,
        _admin: admin,
        rx_cq,
        rx_sq,
        tx_cq,
        tx_sq,
        rx_bufs,
        tx_bufs,
        rx_sq_tail: 0,
        rx_sq_phase: 1,
        rx_cq_head: 0,
        rx_cq_phase: 1,
        tx_sq_tail: 0,
        tx_sq_phase: 1,
        tx_cq_head: 0,
        tx_cq_phase: 1,
        tx_caller: [core::ptr::null(); TX_FILL as usize],
    })
}

/// Reset sequence: assert DEV_CTL.RESET, wait for RESET_IN_PROGRESS, deassert, wait
/// for it to clear, confirm READY. `caps` supplies the reset timeout (100ms units).
unsafe fn reset(pci: &PciIoProtocol, caps: u32) -> Result<(), Status> {
    let timeout_units = ((caps & CAPS_RESET_TIMEOUT_MASK) >> CAPS_RESET_TIMEOUT_SHIFT).max(1);
    let timeout_ms = timeout_units as usize * 100;
    let sts0 = reg_read32(pci, regs::DEV_STS);
    log!("reset: DEV_STS=0x{sts0:08x} (ready={}) timeout={timeout_ms}ms", sts0 & DEV_STS_READY);

    reg_write32(pci, regs::DEV_CTL, DEV_CTL_RESET);
    fence(Ordering::SeqCst);
    if !wait_sts(pci, DEV_STS_RESET_IN_PROGRESS, DEV_STS_RESET_IN_PROGRESS, timeout_ms) {
        log!("!! reset never entered RESET_IN_PROGRESS");
        return Err(Status::DEVICE_ERROR);
    }
    log!("reset: in progress");

    reg_write32(pci, regs::DEV_CTL, 0);
    fence(Ordering::SeqCst);
    if !wait_sts(pci, DEV_STS_RESET_IN_PROGRESS, 0, timeout_ms) {
        log!("!! reset never cleared RESET_IN_PROGRESS");
        return Err(Status::DEVICE_ERROR);
    }
    let sts = reg_read32(pci, regs::DEV_STS);
    log!("reset: done DEV_STS=0x{sts:08x} (ready={})", sts & DEV_STS_READY);
    Ok(())
}

/// Poll DEV_STS until `(sts & mask) == want`, up to `timeout_ms`. Returns false on timeout.
unsafe fn wait_sts(pci: &PciIoProtocol, mask: u32, want: u32, timeout_ms: usize) -> bool {
    let mut waited = 0;
    loop {
        if (reg_read32(pci, regs::DEV_STS) & mask) == want {
            return true;
        }
        if waited >= timeout_ms {
            return false;
        }
        delay_ms(1);
        waited += 1;
    }
}
