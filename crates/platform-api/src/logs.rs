//! The system log stream of the native VPN components (the native debug log collection).

/// A running `log stream`.
pub trait StreamHandle: Send {
    fn stop(&self);
}

/// Starts the system's log stream of the native VPN components (on macOS `log stream --style compact --predicate
/// …`); its lines and its end come through the callbacks.
pub trait LogStreamSpawner: Send + Sync {
    /// The command as the collection's header shows it after `$ ` (on macOS the exact `log stream` command line).
    fn command_line(&self) -> String;

    /// The platform has such a stream (macOS: `log stream`). `false` (WinVPN): a debug connect starts no
    /// collection, and the native kinds' Log tab reads the platform's own log instead.
    fn is_available(&self) -> bool {
        true
    }

    fn spawn(
        &self,
        on_lines: Box<dyn FnMut(Vec<String>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> Result<Box<dyn StreamHandle>, String>;
}
