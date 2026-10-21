//! The error of a platform call.

use macvpn_core::l10n;
use std::fmt;

/// Why a platform call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// This platform does not offer the facility (yet). `what` names it for the code (e.g. `"native VPN"`); the
    /// message never shows it.
    Unsupported { what: &'static str },
    /// An already localized message.
    Failed(String),
}

impl PlatformError {
    /// The user-facing message: `Not available on this system yet` (localized) or the carried message.
    pub fn message(&self) -> String {
        match self {
            PlatformError::Unsupported { .. } => l10n::tr("Not available on this system yet", &[]),
            PlatformError::Failed(message) => message.clone(),
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for PlatformError {}

impl From<PlatformError> for String {
    fn from(error: PlatformError) -> String {
        match error {
            PlatformError::Failed(message) => message,
            unsupported => unsupported.message(),
        }
    }
}
