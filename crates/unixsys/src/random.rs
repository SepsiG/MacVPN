//! The kernel's CSPRNG: `getentropy` on macOS (256 bytes per call), `getrandom(2)` on Linux (retried on `EINTR` and
//! short reads).

use std::io;

/// Fills `buf` from the kernel's CSPRNG.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    imp::fill(buf)
}

/// 32 random bytes (tokens, keys).
pub fn random_32() -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::io;

    pub fn fill(buf: &mut [u8]) -> io::Result<()> {
        for chunk in buf.chunks_mut(256) {
            // SAFETY: `chunk` is writable for its length (at most 256, getentropy's limit), passed alongside.
            if unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;

    pub fn fill(buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let rest = &mut buf[filled..];
            // SAFETY: `rest` is writable for its length, passed alongside; flags 0 = the urandom pool, blocking
            // only until it is initialized at boot.
            let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            filled += n as usize;
        }
        Ok(())
    }
}
