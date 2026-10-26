//! The system CSPRNG.

use std::io;
use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

/// Fills the whole buffer from the system-preferred RNG, or fails (never a partial fill reported as success).
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        // SAFETY: `chunk` is valid for writes of `chunk.len()` bytes (at most u32::MAX); no algorithm handle is
        // passed, as BCRYPT_USE_SYSTEM_PREFERRED_RNG requires.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(io::Error::other(format!("BCryptGenRandom failed (NTSTATUS {status:#010x})")));
        }
    }
    Ok(())
}
