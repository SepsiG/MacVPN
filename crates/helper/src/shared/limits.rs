//! The size limits of the root layer's protocol (the same on every OS).

/// The source config is at most 1 MB.
pub const SRC_MAX: u64 = 1_048_576;
/// The longest secrets section after the config (the app sends a few hundred bytes).
pub const SECRETS_MAX: u64 = 64 * 1024;
/// The longest stdin accepted (the header, the largest config, the secrets, one byte to detect excess).
pub const STDIN_MAX: u64 = SRC_MAX + SECRETS_MAX + 16;
