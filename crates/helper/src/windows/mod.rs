//! The Windows backend. Phase 1 has none yet: the helper says so and exits with 1.

use crate::shared::l10n::tr;
use std::io::Write as _;

/// The Windows helper's entry point; returns the exit code.
pub fn main() -> i32 {
    let _ = writeln!(std::io::stderr(), "{}", tr("Not available on this system yet", &[]));
    1
}
