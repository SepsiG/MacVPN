//! The operating system a build targets. It selects the per-OS OpenVPN platform tier and (with the l10n variants)
//! the per-OS wording.
//!
//! No `cfg` attribute: the host comes from `std::env::consts::OS`, a compile-time constant.

/// An operating system MacVPN's code can be built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TargetOs {
    MacOs,
    Windows,
    Linux,
}

impl TargetOs {
    /// Every value, in a fixed order.
    pub const ALL: [TargetOs; 3] = [TargetOs::MacOs, TargetOs::Windows, TargetOs::Linux];

    /// The OS this binary was compiled for: `macos` → `MacOs`, `windows` → `Windows`, anything else → `Linux`.
    pub fn host() -> TargetOs {
        match std::env::consts::OS {
            "macos" => TargetOs::MacOs,
            "windows" => TargetOs::Windows,
            _ => TargetOs::Linux,
        }
    }

    /// The name used as the l10n variant key: `macos`, `windows` or `linux`.
    pub fn as_str(self) -> &'static str {
        match self {
            TargetOs::MacOs => "macos",
            TargetOs::Windows => "windows",
            TargetOs::Linux => "linux",
        }
    }

    /// The inverse of [`TargetOs::as_str`] (exact, case-sensitive).
    pub fn parse(s: &str) -> Option<TargetOs> {
        TargetOs::ALL.into_iter().find(|os| os.as_str() == s)
    }
}
