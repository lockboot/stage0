// SPDX-License-Identifier: MIT OR Apache-2.0

//! A local-APIC timer tick for firmware whose own tick never arrives.
//!
//! GCE's firmware (the `ovmf_x64_csm` family) drives the UEFI tick from the 8254 PIT through
//! the 8259 PIC (OVMF `8254TimerDxe`; upstream OVMF moved every build to `LocalApicTimerDxe`
//! in 89bd992b1f). An Intel TDX guest receives interrupts only through its virtual x2APIC, so
//! IRQ0 is never delivered: the PIT counts, but no timer event ever fires -- and EDK2's network
//! stack (MNP receive polling, DHCP retransmits, TCP timers) runs on timer events. Measured on
//! GCE c3-standard-4: 0 ticks of a 10 ms periodic event in 300 ms under TDX, 30 on Shielded.
//!
//! [`ensure`] checks whether the firmware tick is alive and, only if it is dead, does what
//! `LocalApicTimerDxe` would: program the local APIC timer periodic at the firmware's own
//! timer period on a free vector, and from its interrupt call the firmware timer driver's
//! `GenerateSoftInterrupt()`, which runs the registered tick handler (`CoreTimerTick`) for one
//! period. The firmware's tick bookkeeping is untouched; it just gets its interrupts. The
//! LAPIC timer is masked again at ExitBootServices, so the OS starts with it as it was.
//!
//! The interrupt handler follows `LocalApicTimerDxe`'s structure, including its use of OVMF's
//! NestedInterruptTplLib (ported below as [`nested_raise_tpl`] / [`nested_restore_tpl`]):
//! RestoreTPL() re-enables interrupts while it dispatches event notifications, so a burst of
//! ticks arriving just as an outer RestoreTPL() finishes would otherwise nest without bound and
//! exhaust the stack.

use core::arch::asm;
use core::ffi::c_void;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use uefi::boot::{self, EventType, OpenProtocolAttributes, OpenProtocolParams, Tpl};
use uefi::proto::unsafe_protocol;
use uefi::{Event, Status};
use uefi_raw::table::boot::Tpl as RawTpl;

/// `EFI_TIMER_ARCH_PROTOCOL` (PI spec vol. 2).
#[repr(C)]
struct TimerArchProtocol {
    register_handler: usize,
    set_timer_period: usize,
    get_timer_period: unsafe extern "efiapi" fn(*mut TimerArchProtocol, *mut u64) -> Status,
    generate_soft_interrupt: unsafe extern "efiapi" fn(*mut TimerArchProtocol) -> Status,
}

/// `EFI_CPU_INTERRUPT_HANDLER`: (interrupt type, EFI_SYSTEM_CONTEXT -- a pointer union).
type InterruptHandler = unsafe extern "efiapi" fn(isize, *mut c_void);

/// `EFI_CPU_ARCH_PROTOCOL` (PI spec vol. 2), up to the member used.
#[repr(C)]
struct CpuArchProtocol {
    flush_data_cache: usize,
    enable_interrupt: usize,
    disable_interrupt: usize,
    get_interrupt_state: usize,
    init: usize,
    register_interrupt_handler:
        unsafe extern "efiapi" fn(*mut CpuArchProtocol, isize, Option<InterruptHandler>) -> Status,
}

#[unsafe_protocol("26baccb3-6f42-11d4-bce7-0080c73c8881")]
struct TimerArch(TimerArchProtocol);

#[unsafe_protocol("26baccb1-6f42-11d4-bce7-0080c73c8881")]
struct CpuArch(CpuArchProtocol);

/// Vectors tried for the tick, first free one wins (RegisterInterruptHandler refuses a vector
/// that already has a handler, e.g. the 8259's 0x68..0x77).
const VECTORS: core::ops::RangeInclusive<isize> = 0x40..=0xef;

/// How long the liveness probe waits for one firmware tick.
const PROBE_MS: usize = 50;

// x2APIC MSRs (Intel SDM vol. 3 10.12.1.2) and their xAPIC MMIO offsets (MSR - 0x800) << 4.
const APIC_BASE_MSR: u32 = 0x1b;
const X2APIC_ENABLE: u64 = 1 << 10;
const REG_EOI: u32 = 0x80b;
const REG_LVT_TIMER: u32 = 0x832;
const REG_INIT_COUNT: u32 = 0x838;
const REG_CUR_COUNT: u32 = 0x839;
const REG_DIVIDE: u32 = 0x83e;
const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;
const DIVIDE_BY_1: u32 = 0b1011;

/// The timer arch protocol the ISR ticks, and the xAPIC MMIO base (null in x2APIC mode).
static TIMER: AtomicPtr<TimerArchProtocol> = AtomicPtr::new(ptr::null_mut());
/// The LAPIC timer registers as the firmware left them, restored at ExitBootServices:
/// LVT timer, initial count, divide configuration.
static SAVED_LVT: AtomicU32 = AtomicU32::new(0);
static SAVED_INIT: AtomicU32 = AtomicU32::new(0);
static SAVED_DIVIDE: AtomicU32 = AtomicU32::new(0);
static ENGAGED: AtomicBool = AtomicBool::new(false);
static XAPIC_MMIO: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static PROBE_TICKS: AtomicU32 = AtomicU32::new(0);

unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | lo as u64
}

unsafe fn wrmsr(msr: u32, v: u64) {
    asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32,
         options(nomem, nostack));
}

unsafe fn apic_read(reg: u32) -> u32 {
    let mmio = XAPIC_MMIO.load(Ordering::Relaxed);
    if mmio.is_null() {
        rdmsr(reg) as u32
    } else {
        (mmio.add(((reg - 0x800) << 4) as usize) as *const u32).read_volatile()
    }
}

unsafe fn apic_write(reg: u32, v: u32) {
    let mmio = XAPIC_MMIO.load(Ordering::Relaxed);
    if mmio.is_null() {
        wrmsr(reg, v as u64)
    } else {
        (mmio.add(((reg - 0x800) << 4) as usize) as *mut u32).write_volatile(v)
    }
}

unsafe extern "efiapi" fn probe_tick(_e: Event, _c: Option<NonNull<c_void>>) {
    PROBE_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Count firmware timer ticks of a 10 ms periodic event over `ms` milliseconds of stall.
fn ticks_in(ms: usize) -> Option<u32> {
    let ev = unsafe {
        boot::create_event(
            EventType::TIMER | EventType::NOTIFY_SIGNAL,
            Tpl::CALLBACK,
            Some(probe_tick),
            None,
        )
    }
    .ok()?;
    let start = PROBE_TICKS.load(Ordering::Relaxed);
    let armed = boot::set_timer(&ev, boot::TimerTrigger::Periodic(100_000)).is_ok();
    boot::stall(ms * 1000);
    let n = PROBE_TICKS.load(Ordering::Relaxed).wrapping_sub(start);
    let _ = boot::close_event(ev);
    armed.then_some(n)
}

// ---- NestedInterruptTplLib, ported --------------------------------------------------------
// From EDK2 OvmfPkg/Library/NestedInterruptTplLib (Tpl.c, Iret.c), Copyright (C) 2022, Fen
// Systems Ltd., SPDX-License-Identifier: BSD-2-Clause-Patent. Same algorithm; the shared state
// (NESTED_INTERRUPT_STATE) is only touched with interrupts disabled on the boot CPU.

/// `IsrState->InProgressRestoreTPL` / `IsrState->DeferredRestoreTPL`.
static IN_PROGRESS_RESTORE_TPL: AtomicUsize = AtomicUsize::new(0);
static DEFERRED_RESTORE_TPL: AtomicBool = AtomicBool::new(false);

/// The prefix of `EFI_SYSTEM_CONTEXT_X64` up to `Rflags` (MdePkg Protocol/DebugSupport.h).
#[repr(C)]
struct SystemContextX64 {
    exception_data: u64,
    fx_save_state: [u8; 512],
    dr: [u64; 6], // Dr0-3, Dr6, Dr7
    cr: [u64; 6], // Cr0-4, Cr8
    rflags: u64,
}
const RFLAGS_IF: u64 = 1 << 9;

unsafe fn boot_services() -> *mut uefi_raw::table::boot::BootServices {
    match uefi::table::system_table_raw() {
        Some(st) => (*st.as_ptr()).boot_services,
        None => ptr::null_mut(),
    }
}

/// `NestedInterruptRaiseTPL`: raise to TPL_HIGH_LEVEL from inside an interrupt handler
/// (interrupts are already disabled); returns the TPL the interrupt occurred at.
unsafe fn nested_raise_tpl(bs: *mut uefi_raw::table::boot::BootServices) -> RawTpl {
    ((*bs).raise_tpl)(RawTpl::HIGH_LEVEL)
}

/// `NestedInterruptRestoreTPL`: lower back to `interrupted`, deferring to an outer instance of
/// this handler when that is the only way to avoid an unbounded stack of RestoreTPL() frames.
unsafe fn nested_restore_tpl(
    bs: *mut uefi_raw::table::boot::BootServices,
    interrupted: RawTpl,
    ctx: *mut SystemContextX64,
) {
    // The interrupt hit an outer handler's RestoreTPL() at the point it had finished
    // dispatching (same TPL): return still at TPL_HIGH_LEVEL with interrupts disabled, and let
    // that outer handler perform the RestoreTPL() (the "DEFERRAL INVOCATION POINT").
    if interrupted.0 == IN_PROGRESS_RESTORE_TPL.load(Ordering::Relaxed) {
        DEFERRED_RESTORE_TPL.store(true, Ordering::Relaxed);
        (*ctx).rflags &= !RFLAGS_IF; // DisableInterruptsOnIret
        return;
    }
    // Otherwise the outer RestoreTPL() (if any) is still dispatching at a lower TPL: restore here,
    // as often as inner handlers defer to us. Bounded by the number of distinct TPLs.
    loop {
        let saved = IN_PROGRESS_RESTORE_TPL.swap(interrupted.0, Ordering::Relaxed);
        ((*bs).restore_tpl)(interrupted); // re-enables interrupts below TPL_HIGH_LEVEL
        asm!("cli", options(nomem, nostack));
        // DEFERRAL RETURN POINT
        IN_PROGRESS_RESTORE_TPL.store(saved, Ordering::Relaxed);
        if !DEFERRED_RESTORE_TPL.swap(false, Ordering::Relaxed) {
            return;
        }
    }
}

/// The LAPIC timer interrupt, shaped like `LocalApicTimerDxe`'s TimerInterruptHandler: raise
/// to TPL_HIGH_LEVEL, EOI, one firmware tick (GenerateSoftInterrupt raises/restores HIGH->HIGH,
/// so it dispatches nothing itself), then the nested-safe restore that dispatches events.
unsafe extern "efiapi" fn on_tick(_vector: isize, ctx: *mut c_void) {
    let bs = boot_services();
    if bs.is_null() {
        apic_write(REG_EOI, 0);
        return;
    }
    let interrupted = nested_raise_tpl(bs);
    apic_write(REG_EOI, 0);
    let t = TIMER.load(Ordering::Acquire);
    if !t.is_null() {
        let _ = ((*t).generate_soft_interrupt)(t);
    }
    nested_restore_tpl(bs, interrupted, ctx as *mut SystemContextX64);
}

/// Put the LAPIC timer back before the OS takes over.
unsafe extern "efiapi" fn on_exit_boot_services(_e: Event, _c: Option<NonNull<c_void>>) {
    restore_lapic();
}

/// Stop our tick and put the LAPIC timer registers back exactly as the firmware left them.
unsafe fn restore_lapic() {
    if !ENGAGED.swap(false, Ordering::AcqRel) {
        return;
    }
    apic_write(REG_LVT_TIMER, LVT_MASKED); // stop interrupts first
    apic_write(REG_DIVIDE, SAVED_DIVIDE.load(Ordering::Relaxed));
    apic_write(REG_LVT_TIMER, SAVED_LVT.load(Ordering::Relaxed));
    apic_write(REG_INIT_COUNT, SAVED_INIT.load(Ordering::Relaxed));
}

fn open<P: uefi::proto::ProtocolPointer + 'static>() -> Option<boot::ScopedProtocol<P>> {
    let handle = boot::get_handle_for_protocol::<P>().ok()?;
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()
}

/// Make sure the UEFI timer ticks: a no-op when the firmware's own tick is alive, otherwise
/// supply one from the local APIC timer. Call once, early (before anything event-driven).
pub fn ensure() {
    match ticks_in(PROBE_MS) {
        Some(n) if n > 0 => return,
        Some(_) => {}
        None => {
            crate::slog!("stage0: timer: cannot probe the firmware tick (create/set_timer failed)");
            return;
        }
    }
    match unsafe { install() } {
        Ok(msg) => {
            let n = ticks_in(PROBE_MS).unwrap_or(0);
            crate::slog!("stage0: timer: firmware tick dead; {msg}: {n} ticks in {PROBE_MS} ms");
        }
        Err(why) => crate::slog!("stage0: timer: firmware tick dead and no LAPIC tick: {why}"),
    }
}

unsafe fn install() -> Result<alloc::string::String, &'static str> {
    let mut timer = open::<TimerArch>().ok_or("no EFI_TIMER_ARCH_PROTOCOL")?;
    let mut cpu = open::<CpuArch>().ok_or("no EFI_CPU_ARCH_PROTOCOL")?;
    let timer_p: *mut TimerArchProtocol = &mut timer.0;
    let cpu_p: *mut CpuArchProtocol = &mut cpu.0;

    // The firmware's tick period (100 ns units); each GenerateSoftInterrupt advances it by this.
    let mut period: u64 = 0;
    if !((*timer_p).get_timer_period)(timer_p, &mut period).is_success() || period == 0 {
        return Err("firmware timer period unavailable or 0");
    }

    let base = rdmsr(APIC_BASE_MSR);
    if base & X2APIC_ENABLE == 0 {
        XAPIC_MMIO.store((base & 0xffff_f000) as *mut u8, Ordering::Relaxed);
    }

    SAVED_LVT.store(apic_read(REG_LVT_TIMER), Ordering::Relaxed);
    SAVED_INIT.store(apic_read(REG_INIT_COUNT), Ordering::Relaxed);
    SAVED_DIVIDE.store(apic_read(REG_DIVIDE), Ordering::Relaxed);
    ENGAGED.store(true, Ordering::Release);

    // Calibrate the LAPIC timer (divide by 1, masked one-shot) against a 10 ms stall.
    apic_write(REG_DIVIDE, DIVIDE_BY_1);
    apic_write(REG_LVT_TIMER, LVT_MASKED);
    apic_write(REG_INIT_COUNT, u32::MAX);
    boot::stall(10_000);
    let per_10ms = u32::MAX - apic_read(REG_CUR_COUNT);
    apic_write(REG_INIT_COUNT, 0);
    if per_10ms == 0 {
        restore_lapic();
        return Err("LAPIC timer does not count");
    }
    let count = (per_10ms as u64 * period / 100_000).clamp(1, u32::MAX as u64) as u32;

    // Arm the ExitBootServices mask before the tick can run.
    boot::create_event(
        EventType::SIGNAL_EXIT_BOOT_SERVICES,
        Tpl::NOTIFY,
        Some(on_exit_boot_services),
        None,
    )
    .map_err(|_| {
        restore_lapic();
        "cannot create the ExitBootServices event"
    })?;

    TIMER.store(timer_p, Ordering::Release);
    let vector = VECTORS
        .clone()
        .find(|&v| ((*cpu_p).register_interrupt_handler)(cpu_p, v, Some(on_tick)).is_success())
        .ok_or_else(|| {
            restore_lapic();
            "no free interrupt vector"
        })?;
    apic_write(REG_LVT_TIMER, LVT_PERIODIC | vector as u32);
    apic_write(REG_INIT_COUNT, count);

    // Both are architectural protocols that live as long as boot services; keep them open.
    core::mem::forget(timer);
    core::mem::forget(cpu);
    Ok(alloc::format!(
        "LAPIC tick on vector {vector:#x} ({}, {count} counts per {} us)",
        if XAPIC_MMIO.load(Ordering::Relaxed).is_null() {
            "x2APIC"
        } else {
            "xAPIC"
        },
        period / 10
    ))
}
