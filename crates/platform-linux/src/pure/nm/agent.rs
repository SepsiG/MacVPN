//! The agent's pure rules: the hints, the answer's shape, the default secret mode.
use macvpn_core::nm_plan::SecretMode;

/// Spike L0-4 sets this (resolved point 8): `Agent` unless GNOME Shell's agent prompts first.
// L0-4 (part 2, lab 2026-10-30): branch A confirmed: NM asks LinVPN's agent first for its own activations.
pub const DEFAULT_SECRET_MODE: SecretMode = SecretMode::Agent;

/// How long a pending dynamic challenge (CRV1) waits for the user's code, in seconds: inside NM's 120 s agent
/// timeout, with 10 s of margin.
// L0-4 (part 2, lab 2026-10-30): a code answered 105 s after the request still connected; 110 s stays.
pub const CRV1_DEADLINE_SECS: u64 = 110;

/// The secret NM-openvpn asks for with a dynamic challenge, and the key the agent answers it under.
pub const CHALLENGE_RESPONSE: &str = "challenge-response";

/// At most this many characters of the server's challenge text reach the prompt.
pub const MESSAGE_MAX_CHARS: usize = 512;

const HINT_MESSAGE: &str = "x-vpn-message:";
const HINT_CHALLENGE: &str = "x-dynamic-challenge:challenge-response";
const HINT_CHALLENGE_ECHO: &str = "x-dynamic-challenge-echo:challenge-response";

/// A dynamic challenge (CRV1) in NM's hints: `(echo, message)`; the message is [`message`]'s, empty without one.
pub fn dynamic_challenge(hints: &[String]) -> Option<(bool, String)> {
    let echo = if hints.iter().any(|h| h == HINT_CHALLENGE_ECHO) {
        true
    } else if hints.iter().any(|h| h == HINT_CHALLENGE) {
        false
    } else {
        return None;
    };
    Some((echo, message(hints).unwrap_or_default()))
}

/// The server's text of the first `x-vpn-message:` hint, cleaned for the prompt (it is untrusted server input):
/// every control character removed (`macvpn_core::mfa::has_control`'s rule), at most [`MESSAGE_MAX_CHARS`]
/// characters.
pub fn message(hints: &[String]) -> Option<String> {
    let raw = hints.iter().find_map(|h| h.strip_prefix(HINT_MESSAGE))?;
    let mut buf = [0u8; 4];
    Some(
        raw.chars()
            .filter(|c| !macvpn_core::mfa::has_control(c.encode_utf8(&mut buf)))
            .take(MESSAGE_MAX_CHARS)
            .collect(),
    )
}
