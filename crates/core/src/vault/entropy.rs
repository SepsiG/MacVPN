//! The source of randomness for keys, salts and nonces. Core has no `unsafe` and therefore no `getentropy`; the
//! app passes `platform-mac`'s `SystemEntropy`, the tests a deterministic [`FixedEntropy`].

use sha2::{Digest, Sha256};
use std::io;
use std::sync::Mutex;

/// Cryptographically secure random bytes.
pub trait Entropy: Send + Sync {
    /// Fills the whole buffer, or fails (never a partial fill that is reported as success).
    fn fill(&self, buf: &mut [u8]) -> io::Result<()>;
}

/// Deterministic, for tests only: the stream `SHA-256(seed ‖ counter)`, so known-answer vectors are possible.
/// The stream continues between calls. **Never** use it for real keys.
#[doc(hidden)]
pub struct FixedEntropy {
    seed: u64,
    state: Mutex<(u64, Vec<u8>)>,
}

impl FixedEntropy {
    pub fn new(seed: u64) -> FixedEntropy {
        FixedEntropy { seed, state: Mutex::new((0, Vec::new())) }
    }
}

impl Entropy for FixedEntropy {
    fn fill(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (counter, pool) = &mut *state;
        for byte in buf.iter_mut() {
            if pool.is_empty() {
                let mut h = Sha256::new();
                h.update(self.seed.to_be_bytes());
                h.update(counter.to_be_bytes());
                *counter += 1;
                pool.extend(h.finalize().iter().rev());
            }
            *byte = pool.pop().unwrap_or_default();
        }
        Ok(())
    }
}
