// SPDX-License-Identifier: MIT OR Apache-2.0

//! Log lines on stage0's timeline: `[    S.mmm] gvnic: ...`, the same stamp as stage0's `slog!`.
//!
//! stage0 passes its epoch as this image's LoadOptions: the free-running cycle counter's value
//! at its t = 0 and its calibrated cycles per millisecond, each a little-endian u64 (stage0
//! `timing::epoch`). This driver reads the same counter (x86_64 `rdtsc`, aarch64
//! `cntvct_el0`), so no second calibration. Without an epoch the stamp is `[    ?.???]`.

use core::sync::atomic::{AtomicU64, Ordering};

static START: AtomicU64 = AtomicU64::new(0);
static CYCLES_PER_MS: AtomicU64 = AtomicU64::new(0);

/// Take the epoch from this image's LoadOptions (16 bytes; anything else leaves it unset).
pub fn init(load_options: Option<&[u8]>) {
    if let Some(o) = load_options {
        if o.len() == 16 {
            let le = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
            START.store(le(&o[..8]), Ordering::Relaxed);
            CYCLES_PER_MS.store(le(&o[8..]), Ordering::Relaxed);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn raw() -> u64 {
    // SAFETY: `rdtsc` is unprivileged and always present on x86_64 UEFI hosts.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn raw() -> u64 {
    let v: u64;
    // SAFETY: CNTVCT_EL0 is the EL0-readable virtual counter; the read is side-effect free.
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// The current stamp, formatted like stage0's (`{:>5}.{:03}` seconds).
pub struct Stamp;

impl core::fmt::Display for Stamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let per_ms = CYCLES_PER_MS.load(Ordering::Relaxed);
        if per_ms == 0 {
            return write!(f, "{:>5}.???", "?");
        }
        let ms = raw().wrapping_sub(START.load(Ordering::Relaxed)) / per_ms;
        write!(f, "{:>5}.{:03}", ms / 1000, ms % 1000)
    }
}

/// Always printed: errors, and the one-line probe summary.
macro_rules! log {
    ($($a:tt)*) => {
        uefi::println!("[{}] gvnic: {}", $crate::clock::Stamp, format_args!($($a)*))
    };
}

/// Step-by-step detail, compiled in only with the `verbose` feature.
#[cfg(feature = "verbose")]
macro_rules! vlog {
    ($($a:tt)*) => { log!($($a)*) };
}

/// No-op form; still references the arguments so they don't trip unused warnings.
#[cfg(not(feature = "verbose"))]
macro_rules! vlog {
    ($($a:tt)*) => {{
        let _ = format_args!($($a)*);
    }};
}
