//! Table-driven, three-tier OpenVPN validation (port of `OpenVPNValidator`). The root layer runs it too.
//!
//! Rules, in order, per line:
//! 1. control character -> error (inside blocks too); a line longer than [`MAX_LINE_BYTES`] -> "Line too long"
//!    (inside blocks and comments too: OpenVPN would read the rest as a new line);
//! 2. inside a data block: a trimmed line starting with `</` closes the block, and if it is not exactly `</tag>`
//!    (lower-cased) "Invalid closing tag"; other lines are skipped;
//! 3. empty lines and lines starting with `#` or `;` are skipped;
//! 4. `<connection>` opens a connection block (top level only; no `<connection>` inside it). Its lines go through
//!    the same directive check, but only the `connection_allowed` directives are allowed (as in OpenVPN), and only
//!    the `connection_blocks` data blocks may open. Only `</connection>` closes it; any other `</…>` in it is
//!    "Invalid closing tag";
//! 5. an opening tag `^<[A-Za-z0-9-]+>$` must be in `allowed_blocks`, otherwise "Inline block not allowed" (but it
//!    is still treated as a block and its content skipped);
//! 6. directive = first token (space/tab separated), must match `^(--)?[A-Za-z0-9-]+$`, otherwise "Invalid
//!    directive"; lower-cased, `--` dropped;
//! 7. tier by [`OpenVPNValidator::tier_for`] (table: `argument_specs` = SAFE, `risky_reasons` and the OS's
//!    [`platform_reasons`] = RISKY, `forbidden` (on Windows also [`FORBIDDEN_WINDOWS`]) = FORBIDDEN; an unknown
//!    name matching `FORBIDDEN_PATTERN` is FORBIDDEN, otherwise RISKY; the entry points without an OS use
//!    [`TargetOs::host`]):
//!    - FORBIDDEN -> "Forbidden directive";
//!    - RISKY -> error in a `<connection>` block; the arguments must pass `is_harmless_argument` (no leading `-`,
//!      `..`, absolute path, `~`, `file:`, shell metacharacter, `/` only in a CIDR; on Windows no `:` but in an
//!      IPv6 address: `is_harmless_argument_for`), otherwise "Invalid argument";
//!      a valid line is a risky finding (not an error): `validate_full` reports only the unacknowledged names;
//!
//!    more than [`MAX_PARMS`] tokens on a line -> "Wrong number of arguments";
//!
//!    7b. `setenv` separately: `setenv opt <directive> ...` -> the directive goes through the same check, once (a
//!    second `setenv opt` -> "setenv not allowed: opt"); `setenv NAME [value]` -> NAME must match
//!    `^[A-Za-z_][A-Za-z0-9_]*$` and not be in the denylist (these values reach the root DNS hook), and on Windows
//!    be in the allowlist ([`SETENV_WINDOWS_ALLOWED_NAMES`], [`SETENV_WINDOWS_ALLOWED_PREFIXES`]), otherwise "setenv
//!    not allowed"; `setenv` without argument, or `setenv opt` without directive -> error;
//! 8. arguments (SAFE): a mirror of OpenVPN's `parse_line` (space/tab boundaries, `"…"`/`'…'` only at a token
//!    start, the closing quote ends the token, `#`/`;` at a token start comments out the rest); a backslash or an
//!    unterminated quote -> "Invalid argument"; a `file_referencing` directive with an argument other than
//!    `[inline]` -> file reference error; `http-proxy`'s 3rd argument only `auto`/`auto-nct`/`[inline]`,
//!    `socks-proxy`'s 3rd only `[inline]`; the argument count and every argument is checked by `argument_specs`
//!    ("Wrong number of arguments" / "Invalid argument"). Messages quote only the directive name, never an
//!    argument;
//! 9. a block open at the end -> "Unclosed inline block"; no valid `remote` (top level or in a connection block)
//!    -> a line-0 issue.

use super::{ConfigValidator, control_character_message, has_control_character, matches, numbered_lines};
use crate::l10n::{self, Arg};
use crate::models::ValidationIssue;
use crate::swift_str::{self, ascii_lowercased, trim_space_tab};
use crate::target_os::TargetOs;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

/// The tier of an OpenVPN directive (see `docs/openvpn-directives.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenVPNTier {
    /// Allowed, with argument checks (`argument_specs`).
    Safe,
    /// Does not cross the root privilege boundary but changes how the connection or the system behaves: allowed
    /// only if acknowledged by name for the connection. Every unknown directive is here.
    Risky,
    /// Never allowed: runs or loads code, reads/writes arbitrary files as root, or opens a control channel.
    Forbidden,
}

impl OpenVPNTier {
    pub fn raw_value(self) -> &'static str {
        match self {
            OpenVPNTier::Safe => "safe",
            OpenVPNTier::Risky => "risky",
            OpenVPNTier::Forbidden => "forbidden",
        }
    }
}

/// An occurrence of a risky directive that needs acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RiskyFinding {
    pub directive: String,
    pub line: i64,
    /// The English `L10n` key (short reason).
    pub reason_key: &'static str,
}

impl RiskyFinding {
    pub fn reason(&self) -> String {
        l10n::tr(self.reason_key, &[])
    }
}

/// The full OpenVPN validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVPNValidation {
    /// Blocking issues (forbidden, invalid, not allowed): cannot be fixed by acknowledging.
    pub issues: Vec<ValidationIssue>,
    /// Every risky occurrence, in order (acknowledged ones too).
    pub risky: Vec<RiskyFinding>,
    /// The names of the risky directives not acknowledged yet, sorted.
    pub unacknowledged: Vec<String>,
}

impl OpenVPNValidation {
    /// The names of the risky directives (sorted, unique).
    pub fn risky_names(&self) -> Vec<String> {
        let set: BTreeSet<&str> = self.risky.iter().map(|r| r.directive.as_str()).collect();
        set.into_iter().map(str::to_string).collect()
    }

    /// The blocking issues plus one issue per unacknowledged risky line, sorted by line (stable); line-0 (whole
    /// file) issues stay at the end.
    pub fn all_issues(&self) -> Vec<ValidationIssue> {
        let open: HashSet<&str> = self.unacknowledged.iter().map(String::as_str).collect();
        let extra = self.risky.iter().filter(|r| open.contains(r.directive.as_str())).map(|r| {
            ValidationIssue::new(
                r.line,
                l10n::tr("Risky directive, acknowledgement required: %@", &[Arg::Str(&r.directive)]),
            )
        });
        let mut all: Vec<ValidationIssue> = self.issues.iter().cloned().chain(extra).collect();
        all.sort_by_key(|i| if i.line == 0 { i64::MAX } else { i.line });
        all
    }
}

/// The result of checking one directive line.
#[derive(Debug, Clone, Default)]
pub(crate) struct LineResult {
    pub messages: Vec<String>,
    pub directive: Option<String>,
    /// A risky directive (name, reason key), if the line is otherwise valid.
    pub risky: Option<(String, &'static str)>,
}

/// The rule of one directive argument.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ArgRule {
    /// A regex the whole argument must match.
    Pattern(&'static str),
    /// An integer in the range (digits only).
    Number(i64, i64),
    /// Free text (with spaces if quoted); the backslash is already rejected by the tokenizer.
    Text,
}

/// Argument count range and per-position rules; `rest` applies to the arguments beyond `rules`.
#[derive(Debug, Clone)]
pub(crate) struct ArgSpec {
    pub min: usize,
    pub max: usize,
    pub rules: Vec<ArgRule>,
    pub rest: Option<ArgRule>,
}

impl ArgSpec {
    fn new(min: usize, max: usize, rules: Vec<ArgRule>) -> ArgSpec {
        ArgSpec { min, max, rules, rest: None }
    }

    fn with_rest(min: usize, max: usize, rules: Vec<ArgRule>, rest: ArgRule) -> ArgSpec {
        ArgSpec { min, max, rules, rest: Some(rest) }
    }

    fn rule(&self, index: usize) -> Option<ArgRule> {
        self.rules.get(index).copied().or(self.rest)
    }
}

/// A token of an OpenVPN config line: the text (without quotes) and whether it was quoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub text: String,
    pub quoted: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenVPNValidator;

// MARK: FORBIDDEN

/// Never allowed, not even acknowledged. Reasons per group in `docs/openvpn-directives.md`.
pub static FORBIDDEN: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut s = HashSet::new();
    // Script hooks and command execution.
    s.extend([
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "ipchange",
        "tls-verify",
        "auth-user-pass-verify",
        "client-connect",
        "client-disconnect",
        "client-crresponse",
        "learn-address",
        "dns-updown",
        "iproute",
        "script-security",
    ]);
    // Code loading (pkcs11-* cannot work without the provider library, and the provider loads code).
    s.extend([
        "plugin",
        "providers",
        "engine",
        "pkcs11-providers",
        "pkcs11-id",
        "pkcs11-id-management",
        "pkcs11-cert-private",
        "pkcs11-pin-cache",
        "pkcs11-private-mode",
        "pkcs11-protected-authentication",
        "show-pkcs11-ids",
    ]);
    // Config and directory changes; after chroot MacVPN's hooks and password files are out of reach.
    s.extend(["config", "cd", "chroot"]);
    // Output, control channel, status file (MacVPN sets these itself, or decides from the log).
    s.extend([
        "daemon",
        "log",
        "log-append",
        "syslog",
        "echo",
        "parameter",
        "writepid",
        "status",
        "tmp-dir",
        "management",
        "management-client",
        "management-client-auth",
        "management-client-group",
        "management-client-pf",
        "management-client-user",
        "management-external-cert",
        "management-external-key",
        "management-forget-disconnect",
        "management-hold",
        "management-log-cache",
        "management-query-passwords",
        "management-query-proxy",
        "management-query-remote",
        "management-signal",
        "management-up-down",
    ]);
    // Reading or writing an arbitrary file or directory as root.
    s.extend([
        "dev-node",
        "tls-export-cert",
        "client-config-dir",
        "replay-persist",
        "ifconfig-pool-persist",
        "tls-crypt-v2-verify",
        "capath",
        "genkey",
        "port-share",
        "auth-gen-token-secret",
    ]);
    s
});

/// An unknown name (in no table) that probably means a command, a file or a control channel by its shape:
/// FORBIDDEN, not RISKY.
pub const FORBIDDEN_PATTERN: &str =
    "^(management|pkcs11|plugin|script)|-(verify|up|down|connect|disconnect|script|dir|file|persist|path|exec|cmd)$";

// MARK: RISKY

pub const REASON_PRIVILEGE_DROP: &str =
    "Drops root privileges after start: reconnecting may fail; MacVPN still restores DNS when the connection ends";
/// The 1.4 text of [`REASON_PRIVILEGE_DROP`], outdated since root layer 9's DNS manager restores DNS from its
/// ledger even when the unprivileged down hook cannot. No table uses it; kept because its text is in the l10n
/// baseline.
pub const REASON_PRIVILEGE_DROP_1_4: &str =
    "Drops root privileges after start: reconnecting may fail, and DNS is restored only when MacVPN disconnects";
pub const REASON_NO_EXEC: &str =
    "OpenVPN will not configure the interface or the routes: the tunnel may carry no traffic";
pub const REASON_HOOKS: &str = "Changes when MacVPN's DNS hooks run";
pub const REASON_SERVER: &str = "Server-side option, not meant for a client connection";
pub const REASON_LISTENS: &str = "Makes this Mac accept incoming VPN connections (listens on the network as root)";
pub const REASON_PUSHED: &str = "Normally sent by the server or used internally by OpenVPN, not set in a client config";
pub const REASON_REMOVED: &str = "Removed from OpenVPN: the connection will fail to start";
pub const REASON_DEBUG: &str = "Debugging option that deliberately disrupts the connection";
pub const REASON_WEAKENS: &str = "Weakens the security of the tunnel (deprecated or insecure mode)";
pub const REASON_ROUTING: &str = "Allows routing that can bypass or loop the tunnel";
pub const REASON_PLATFORM: &str = "Not supported on macOS (Windows or Linux only)";
pub const REASON_PLATFORM_WINDOWS: &str = "Not supported on Windows (Linux only)";
pub const REASON_PLATFORM_LINUX: &str = "Not supported on Linux";
/// No table uses it since 2b (the Windows tier forbids these names); kept because its text is in the l10n baseline.
pub const REASON_SERVICE_OWNED: &str = "Set by the VPN service itself, not by a connection's config";
pub const REASON_STANDALONE: &str = "Standalone mode: OpenVPN prints information or exits instead of connecting";
pub const REASON_UNKNOWN: &str = "Unknown to MacVPN: its effect cannot be checked";

/// Known RISKY directives -> reason (`L10n` key), on every OS. The OS-specific ones are in [`platform_reasons`].
pub static RISKY_REASONS: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut t = HashMap::new();
    for d in ["user", "group"] {
        t.insert(d, REASON_PRIVILEGE_DROP);
    }
    for d in ["route-noexec", "ifconfig-noexec"] {
        t.insert(d, REASON_NO_EXEC);
    }
    for d in ["up-restart", "down-pre"] {
        t.insert(d, REASON_HOOKS);
    }
    for d in ["mode", "server", "server-bridge", "server-ipv6", "tls-server", "client-to-client"] {
        t.insert(d, REASON_LISTENS);
    }
    let server = [
        "duplicate-cn",
        "max-clients",
        "max-routes-per-client",
        "ccd-exclusive",
        "client-nat",
        "connect-freq",
        "connect-freq-initial",
        "hash-size",
        "bcast-buffers",
        "stale-routes-check",
        "verify-client-cert",
        "client-cert-not-required",
        "username-as-common-name",
        "override-username",
        "auth-user-pass-optional",
        "auth-gen-token",
        "ifconfig-pool",
        "ifconfig-pool-linear",
        "ifconfig-ipv6-pool",
        "ifconfig-push",
        "ifconfig-ipv6-push",
        "iroute",
        "iroute-ipv6",
        "push",
        "push-reset",
        "push-remove",
        "disable",
        "vlan-tagging",
        "vlan-accept",
        "vlan-pvid",
        "tls-crypt-v2-max-age",
    ];
    for d in server {
        t.insert(d, REASON_SERVER);
    }
    t.insert("ifconfig-push-constraint", REASON_SERVER);
    for d in ["key-derivation", "protocol-flags", "peer-id", "push-continuation", "http-proxy-override"] {
        t.insert(d, REASON_PUSHED);
    }
    for d in ["compat-names", "no-name-remapping", "mtu-dynamic"] {
        t.insert(d, REASON_REMOVED);
    }
    t.insert("gremlin", REASON_DEBUG);
    for d in ["allow-deprecated-insecure-static-crypto", "compat-mode", "no-replay", "no-iv", "key-method"] {
        t.insert(d, REASON_WEAKENS);
    }
    t.insert("allow-recursive-routing", REASON_ROUTING);
    let standalone = [
        "help",
        "version",
        "show-adapters",
        "show-ciphers",
        "show-digests",
        "show-engines",
        "show-gateway",
        "show-groups",
        "show-net",
        "show-net-up",
        "show-tls",
        "show-valid-subnets",
        "show-curves",
        "test-crypto",
        "mktun",
        "rmtun",
    ];
    for d in standalone {
        t.insert(d, REASON_STANDALONE);
    }
    t
});

// MARK: The platform tier

/// The directives another OS's OpenVPN owns (1.4's table: not supported on macOS).
const NOT_ON_MACOS: [&str; 8] = [
    "win-sys",
    "service",
    "cryptoapicert",
    "allow-nonadmin",
    "setcon",
    "msg-channel",
    "rdns-internal",
    "dhcp-internal",
];

static PLATFORM_MACOS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| NOT_ON_MACOS.into_iter().map(|d| (d, REASON_PLATFORM)).collect());

/// Windows: the WinVPN Service runs `openvpn.exe` as SYSTEM and sets these itself. `win-sys` would make OpenVPN run
/// `route.exe` / `netsh.exe` from a folder of the config's choosing, `service` / `msg-channel` hand it an event or a
/// pipe, `allow-nonadmin` changes a TAP adapter's permissions (TAP-Windows6 is installed), `rdns-internal` /
/// `dhcp-internal` are internal, `windows-driver` is chosen by the service per connection (DCO or TAP-Windows6;
/// OpenVPN 2.7 ignores the directive anyway), `cryptoapicert` would read the computer's certificate store as SYSTEM (decision 3 of the 2b plan).
/// FORBIDDEN, never acknowledgeable.
pub static FORBIDDEN_WINDOWS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "win-sys",
        "service",
        "msg-channel",
        "allow-nonadmin",
        "rdns-internal",
        "dhcp-internal",
        "windows-driver",
        "cryptoapicert",
    ]
    .into()
});

/// Windows: `setcon` is SELinux (Linux only).
static PLATFORM_WINDOWS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| [("setcon", REASON_PLATFORM_WINDOWS)].into());

pub const REASON_IGNORED_LINUX: &str = "Ignored by NetworkManager on Linux";

/// Linux (LinVPN, spike L0-1 "Proposed Linux tier"): NetworkManager's OpenVPN service builds OpenVPN's command line
/// from its own `vpn.data` keys only, so these are dropped: RISKY with their own reason (the user acknowledges that
/// they have no effect). The tuning row, the TLS and peer-check details NM has no key for, the routing details
/// `nm_plan` cannot express, and the other OSes' names (`NOT_ON_MACOS` but `setcon`). Not here: the names NM or
/// `nm_plan` expresses, and the ones NM already does itself or that are no-ops on Linux (`nobind`, `persist-*`,
/// `auth-nocache`, `resolv-retry`, the Windows-only SAFE options, …): they stay SAFE, so everyday profiles need no
/// acknowledgement. `lport 0` (= NM's own `--nobind`, written by pfSense and OPNsense exports) gives no finding
/// either (`check_unwrapped`). The refusals (a server check NM cannot express, a route past the tunnel, …) are
/// `nm_plan::openvpn`'s reasons, not tiers: the config stays valid for macOS and Windows.
const IGNORED_ON_LINUX: [&str; 69] = [
    // Tuning: MTU and buffers, sockets, timers, process.
    "link-mtu",
    "udp-mtu",
    "tun-mtu-extra",
    "tun-mtu-max",
    "max-packet-size",
    "mtu-test",
    "sndbuf",
    "rcvbuf",
    "txqueuelen",
    "fast-io",
    "tcp-nodelay",
    "socket-flags",
    "mark",
    "bind",
    "bind-dev",
    "local",
    "lport",
    "passtos",
    "nice",
    "mlock",
    "shaper",
    "replay-window",
    "hand-window",
    "tran-window",
    "tls-timeout",
    "reneg-bytes",
    "reneg-pkts",
    "inactive",
    "session-timeout",
    "connect-retry",
    "connect-retry-max",
    "proto-force",
    "persist-local-ip",
    "persist-remote-ip",
    "multihome",
    "preresolve",
    "ip-remote-hint",
    "remap-usr1",
    "up-delay",
    "tls-exit",
    "prng",
    "keying-material-exporter",
    "force-tls-key-material-export",
    "use-prediction-resistance",
    "http-proxy-option",
    "http-proxy-timeout",
    "tcp-queue-limit",
    "ping-timer-rem",
    // TLS and peer-check details: OpenVPN's default applies.
    "tls-groups",
    "ecdh-curve",
    "tls-ciphersuites",
    "tls-cert-profile",
    "x509-track",
    "x509-username-field",
    "auth-token",
    "auth-token-user",
    "comp-noadapt",
    // Routing details NM cannot express.
    "route-gateway",
    "route-ipv6-gateway",
    "route-table",
    "ifconfig-ipv6",
    "block-ipv6",
    // The other OSes' OpenVPN (`setcon` has its own reason below).
    "win-sys",
    "service",
    "cryptoapicert",
    "allow-nonadmin",
    "msg-channel",
    "rdns-internal",
    "dhcp-internal",
];

static PLATFORM_LINUX: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut t: HashMap<&'static str, &'static str> =
        IGNORED_ON_LINUX.into_iter().map(|d| (d, REASON_IGNORED_LINUX)).collect();
    // An SELinux context for the OpenVPN daemon: NetworkManager's OpenVPN service cannot pass it.
    t.insert("setcon", REASON_PLATFORM_LINUX);
    t
});

/// The platform tier: directives this OS refuses or that need an acknowledgement here, with the reason (`L10n`
/// key). Consulted after [`RISKY_REASONS`]; it overrides the SAFE table (Linux: the names NetworkManager ignores
/// keep their argument checks, see `check_unwrapped`, but are RISKY).
pub fn platform_reasons(os: TargetOs) -> &'static HashMap<&'static str, &'static str> {
    match os {
        TargetOs::MacOs => &PLATFORM_MACOS,
        TargetOs::Windows => &PLATFORM_WINDOWS,
        TargetOs::Linux => &PLATFORM_LINUX,
    }
}

// MARK: SAFE helpers

pub static FILE_REFERENCING: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "ca",
        "cert",
        "key",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "pkcs12",
        "secret",
        "extra-certs",
        "dh",
        "crl-verify",
        "askpass",
        "auth-user-pass",
        "http-proxy-user-pass",
    ]
    .into()
});

pub static ALLOWED_BLOCKS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "ca",
        "cert",
        "key",
        "extra-certs",
        "dh",
        "pkcs12",
        "secret",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "peer-fingerprint",
        "auth-user-pass",
        "crl-verify",
        "http-proxy-user-pass",
        "verify-hash",
    ]
    .into()
});

/// The directives allowed in a `<connection>` block: the OpenVPN manual's list (bind, connect-retry,
/// connect-retry-max, connect-timeout, explicit-exit-notify, float, fragment, http-proxy, http-proxy-option,
/// link-mtu, local, lport, mssfix, mtu-disc, nobind, port, proto, remote, rport, socks-proxy, tun-mtu,
/// tun-mtu-extra) intersected with the SAFE list.
pub static CONNECTION_ALLOWED: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "bind",
        "connect-retry",
        "connect-retry-max",
        "connect-timeout",
        "explicit-exit-notify",
        "float",
        "fragment",
        "http-proxy",
        "http-proxy-option",
        "link-mtu",
        "udp-mtu",
        "local",
        "lport",
        "mssfix",
        "mtu-disc",
        "nobind",
        "port",
        "proto",
        "remote",
        "rport",
        "socks-proxy",
        "tun-mtu",
        "tun-mtu-extra",
    ]
    .into()
});

/// The data blocks that may open inside a `<connection>` block (the inline pair of the connection options).
pub static CONNECTION_BLOCKS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| ["http-proxy-user-pass"].into());

/// `setenv` name: any shell identifier, except the denylist.
const SETENV_NAME_PATTERN: &str = "^[A-Za-z_][A-Za-z0-9_]*$";

/// Exact (case-insensitive) names that could influence the root DNS hook, bash, the dynamic linker or the
/// programs the hook calls; or that the hook reads itself.
pub const SETENV_DENIED_NAMES: [&str; 36] = [
    "BASH_ENV",
    "ENV",
    "PATH",
    "IFS",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "CDPATH",
    "GLOBIGNORE",
    "HOME",
    "TMPDIR",
    "OPENSSL_CONF",
    "TZDIR",
    "LANG",
    "NLSPATH",
    "LOCPATH",
    "GCONV_PATH",
    "HOSTALIASES",
    "RES_OPTIONS",
    "LOCALDOMAIN",
    "BASH_XTRACEFD",
    "BASH_LOADABLES_PATH",
    "EXECIGNORE",
    "PROMPT_COMMAND",
    "ZDOTDIR",
    "SHELL",
    "TERMINFO",
    "POSIXLY_CORRECT",
    "TMOUT",
    "PATH_LOCALE",
    "GREP_OPTIONS",
    "OPENSSL_MODULES",
    "OPENSSL_ENGINES",
    "SCRIPT_TYPE",
    "DEV",
    "IFCONFIG_LOCAL",
];
/// Prefixes, case-insensitive.
pub const SETENV_DENIED_PREFIXES: [&str; 11] =
    ["BASH_FUNC", "DYLD_", "LD_", "MALLOC_", "PYTHON", "PERL", "RUBY", "SSL_CERT_", "LC_", "FOREIGN_OPTION_", "SUDO_"];
/// Prefixes, case-sensitive (macOS framework variables, e.g. `MallocStackLoggingDirectory`,
/// `NSObjCMessageLoggingEnabled`).
pub const SETENV_DENIED_CASE_SENSITIVE_PREFIXES: [&str; 5] = ["Malloc", "NS", "CF", "__CF", "OBJC_"];

/// On Windows, the only `setenv` names (case-insensitive), besides [`SETENV_WINDOWS_ALLOWED_PREFIXES`]. OpenVPN
/// runs `route.exe` and `netsh.exe` as SYSTEM with its env set as their whole environment (`env_block`), so a name
/// such as `SystemRoot`, `windir` or `__COMPAT_LAYER` would steer Windows' own DLLs in a SYSTEM process; which
/// variables those read is not a closed list, so Windows takes an allowlist: the names OpenVPN interprets itself
/// (`options.c`, `setenv`) and informational names seen in provider profiles.
pub const SETENV_WINDOWS_ALLOWED_NAMES: [&str; 6] = [
    "FORWARD_COMPATIBLE",
    "PUSH_PEER_INFO",
    "SERVER_POLL_TIMEOUT",
    "REMOTE_RANDOM_HOSTNAME",
    "CLIENT_CERT",
    "CONFIG_VERSION",
];
/// On Windows, the allowed `setenv` name prefixes (case-insensitive): the peer-info variables `push-peer-info`
/// sends to the server (`UV_` user, `IV_` client info).
pub const SETENV_WINDOWS_ALLOWED_PREFIXES: [&str; 2] = ["UV_", "IV_"];

/// The most tokens on one line, the directive included: OpenVPN's `MAX_PARMS` (`options.h`). `parse_line` silently
/// drops the tokens after these, so a longer line is refused.
pub const MAX_PARMS: usize = 16;

/// The longest line in bytes (after a CR at its end is dropped). OpenVPN reads a configuration line into a 257-byte
/// buffer (`OPTION_LINE_SIZE` + 1), an inline block's line into a 256-byte one (`read_inline_file`), and reads the
/// rest of a longer line as a new line: in an inline block that rest could close the block, and the lines after it
/// would be directives to OpenVPN but block content to the validator. 255 bytes and the line end fit both.
pub const MAX_LINE_BYTES: usize = 255;

// Argument rules. Where the full grammar is overkill, a strict character set: no leading `-`, and `/` only in a
// mask / CIDR (route-ipv6, ifconfig-ipv6).
const HOST: ArgRule = ArgRule::Pattern("^[A-Za-z0-9_][A-Za-z0-9_.:%-]*$");
const PORT: ArgRule = ArgRule::Number(0, 65535);
const UINT: ArgRule = ArgRule::Number(0, u32::MAX as i64);
const PROTO: ArgRule = ArgRule::Pattern("^(udp|tcp|udp4|udp6|tcp4|tcp6|tcp-client|tcp4-client|tcp6-client)$");
const CIPHER: ArgRule = ArgRule::Pattern("^[A-Za-z0-9?][A-Za-z0-9_:.+?-]*$");
const TLS_CIPHER: ArgRule = ArgRule::Pattern("^[A-Za-z0-9!?@+][A-Za-z0-9_:.+?!@=-]*$");
const IPV4: ArgRule = ArgRule::Pattern("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");
const INLINE: ArgRule = ArgRule::Pattern("^\\[inline\\]$");
const DIRECTION: ArgRule = ArgRule::Pattern("^[01]$");
const BASE64ISH: ArgRule = ArgRule::Pattern("^[A-Za-z0-9+=_.-][A-Za-z0-9+/=_.-]*$");
const WORD: ArgRule = ArgRule::Pattern("^[A-Za-z0-9_+][A-Za-z0-9_.:+=@-]*$");
const TEXT: ArgRule = ArgRule::Text;

/// `oneOf("a|b")` = `^(a|b)$` (written out, as the patterns must be static).
macro_rules! one_of {
    ($values:literal) => {
        ArgRule::Pattern(concat!("^(", $values, ")$"))
    };
}

fn flag() -> ArgSpec {
    ArgSpec::new(0, 0, vec![])
}

/// Directive -> argument count and argument rules. Its key set is the SAFE tier.
pub(crate) static ARGUMENT_SPECS: LazyLock<HashMap<&'static str, ArgSpec>> = LazyLock::new(|| {
    let mut t: HashMap<&'static str, ArgSpec> = HashMap::new();
    let flags1 = [
        "client",
        "tls-client",
        "pull",
        "nobind",
        "float",
        "persist-key",
        "persist-tun",
        "persist-remote-ip",
        "remote-random",
        "auth-nocache",
        "ncp-disable",
        "mute-replay-warnings",
        "route-nopull",
        "block-ipv6",
        "tun-ipv6",
        "fast-io",
        "push-peer-info",
        "single-session",
        "http-proxy-retry",
        "disable-occ",
        "opt-verify",
        "remote-random-hostname",
        "machine-readable-output",
        "suppress-timestamps",
        "ping-timer-rem",
        "block-outside-dns",
        "ifconfig-nowarn",
    ];
    let flags2 = [
        "allow-pull-fqdn",
        "disable-dco",
        "mlock",
        "errors-to-stderr",
        "passtos",
        "tcp-nodelay",
        "multihome",
        "persist-local-ip",
        "mtu-test",
        "tls-exit",
        "force-tls-key-material-export",
        "use-prediction-resistance",
        "comp-noadapt",
        "register-dns",
        "dhcp-renew",
        "dhcp-release",
        "dhcp-pre-release",
        "pause-exit",
        "socks-proxy-retry",
        "up-delay",
        "askpass",
    ];
    for d in flags1.into_iter().chain(flags2) {
        t.insert(d, flag());
    }
    t.insert("bind", ArgSpec::new(0, 1, vec![one_of!("ipv6only")]));
    t.insert("dev", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^(tun|tap|utun[0-9]*|tun[0-9]+|tap[0-9]+)$")]));
    t.insert("dev-type", ArgSpec::new(1, 1, vec![one_of!("tun|tap")]));
    t.insert("proto", ArgSpec::new(1, 1, vec![PROTO]));
    t.insert("proto-force", ArgSpec::new(1, 1, vec![one_of!("udp|tcp|udp4|udp6|tcp4|tcp6")]));
    t.insert("remote", ArgSpec::new(1, 3, vec![HOST, PORT, PROTO]));
    t.insert("local", ArgSpec::new(1, 1, vec![HOST]));
    for d in ["port", "rport", "lport"] {
        t.insert(d, ArgSpec::new(1, 1, vec![PORT]));
    }
    t.insert("resolv-retry", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^(infinite|[0-9]{1,9})$")]));
    t.insert("connect-retry", ArgSpec::new(1, 2, vec![UINT, UINT]));
    let numbers = [
        "connect-retry-max",
        "connect-timeout",
        "server-poll-timeout",
        "tls-timeout",
        "hand-window",
        "reneg-bytes",
        "reneg-pkts",
        "mute",
        "ping",
        "ping-restart",
        "ping-exit",
        "route-metric",
        "tun-mtu-extra",
        "link-mtu",
        "udp-mtu",
        "sndbuf",
        "rcvbuf",
        "txqueuelen",
        "mark",
        "tran-window",
        "tun-mtu-max",
        "max-packet-size",
        "session-timeout",
        "route-table",
        "tap-sleep",
        "status-version",
        "tcp-queue-limit",
        "shaper",
        "http-proxy-timeout",
    ];
    for d in numbers {
        t.insert(d, ArgSpec::new(1, 1, vec![UINT]));
    }
    t.insert("max-routes", ArgSpec::new(0, 1, vec![UINT]));
    t.insert("explicit-exit-notify", ArgSpec::new(0, 1, vec![UINT]));
    // `preresolve [hint]`; `ip-remote-hint` is its old name (options.c: the same branch).
    for d in ["preresolve", "ip-remote-hint"] {
        t.insert(d, ArgSpec::new(0, 1, vec![HOST]));
    }
    t.insert("remap-usr1", ArgSpec::new(1, 1, vec![one_of!("SIGHUP|SIGTERM")]));
    t.insert("nice", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^-?[0-9]{1,2}$")]));
    t.insert("bind-dev", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")]));
    t.insert("lladdr", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")]));
    t.insert("socket-flags", ArgSpec::new(1, 1, vec![one_of!("TCP_NODELAY")]));
    t.insert("remote-cert-tls", ArgSpec::new(1, 1, vec![one_of!("client|server")]));
    t.insert("ns-cert-type", ArgSpec::new(1, 1, vec![one_of!("client|server")]));
    t.insert("remote-cert-ku", ArgSpec::with_rest(1, 8, vec![], ArgRule::Pattern("^[0-9A-Fa-f]{1,4}$")));
    t.insert("remote-cert-eku", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^[A-Za-z0-9][A-Za-z0-9 ._-]*$")]));
    t.insert("verify-x509-name", ArgSpec::new(1, 2, vec![TEXT, one_of!("subject|name|name-prefix")]));
    t.insert("peer-fingerprint", ArgSpec::new(0, 1, vec![ArgRule::Pattern("^([0-9A-Fa-f:]+|\\[inline\\])$")]));
    t.insert(
        "verify-hash",
        ArgSpec::new(1, 2, vec![ArgRule::Pattern("^([0-9A-Fa-f:]+|\\[inline\\])$"), one_of!("SHA1|SHA256")]),
    );
    t.insert("x509-track", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^\\+?[A-Za-z0-9_.-]+$")]));
    t.insert("x509-username-field", ArgSpec::with_rest(1, 8, vec![], ArgRule::Pattern("^(ext:)?[A-Za-z0-9_.-]+$")));
    t.insert(
        "keying-material-exporter",
        ArgSpec::new(2, 2, vec![ArgRule::Pattern("^EXPORTER[A-Za-z0-9_.-]*$"), ArgRule::Number(16, 4095)]),
    );
    for d in [
        "ca",
        "cert",
        "key",
        "extra-certs",
        "dh",
        "pkcs12",
        "tls-crypt",
        "tls-crypt-v2",
        "crl-verify",
        "auth-user-pass",
        "http-proxy-user-pass",
    ] {
        t.insert(d, ArgSpec::new(0, 1, vec![INLINE]));
    }
    t.insert("tls-auth", ArgSpec::new(0, 2, vec![INLINE, DIRECTION]));
    t.insert("secret", ArgSpec::new(0, 2, vec![INLINE, DIRECTION]));
    t.insert("key-direction", ArgSpec::new(1, 1, vec![DIRECTION]));
    t.insert("auth-retry", ArgSpec::new(1, 1, vec![one_of!("none|nointeract|interact")]));
    t.insert("auth-token", ArgSpec::new(1, 1, vec![BASE64ISH]));
    t.insert("auth-token-user", ArgSpec::new(1, 1, vec![BASE64ISH]));
    t.insert("static-challenge", ArgSpec::new(2, 3, vec![TEXT, DIRECTION, one_of!("scrv1|concat")]));
    for d in ["cipher", "ciphers", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "auth", "ecdh-curve"] {
        t.insert(d, ArgSpec::new(1, 1, vec![CIPHER]));
    }
    t.insert(
        "tls-version-min",
        ArgSpec::new(1, 2, vec![ArgRule::Pattern("^[0-9](\\.[0-9])?$"), one_of!("or-highest")]),
    );
    t.insert("tls-version-max", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^[0-9](\\.[0-9])?$")]));
    for d in ["tls-cipher", "tls-ciphersuites", "tls-groups"] {
        t.insert(d, ArgSpec::new(1, 1, vec![TLS_CIPHER]));
    }
    t.insert("tls-cert-profile", ArgSpec::new(1, 1, vec![one_of!("legacy|preferred|suiteb|insecure")]));
    t.insert("reneg-sec", ArgSpec::new(1, 2, vec![UINT, UINT]));
    t.insert("comp-lzo", ArgSpec::new(0, 1, vec![one_of!("yes|no|adaptive")]));
    t.insert("compress", ArgSpec::new(0, 1, vec![one_of!("lzo|lz4|lz4-v2|stub|stub-v2|migrate")]));
    t.insert("allow-compression", ArgSpec::new(1, 1, vec![one_of!("yes|no|asym")]));
    t.insert("verb", ArgSpec::new(1, 1, vec![ArgRule::Number(0, 11)]));
    t.insert("replay-window", ArgSpec::new(1, 2, vec![UINT, UINT]));
    t.insert("keepalive", ArgSpec::new(2, 2, vec![UINT, UINT]));
    t.insert("inactive", ArgSpec::new(1, 2, vec![UINT, UINT]));
    let gateway_flags = one_of!("local|autolocal|def1|bypass-dhcp|bypass-dns|block-local|ipv6|!ipv4");
    t.insert("redirect-gateway", ArgSpec::with_rest(0, 8, vec![], gateway_flags));
    t.insert("redirect-private", ArgSpec::with_rest(0, 8, vec![], gateway_flags));
    t.insert(
        "route",
        ArgSpec::new(
            1,
            4,
            vec![
                HOST,
                ArgRule::Pattern("^([0-9]{1,3}(\\.[0-9]{1,3}){3}|default)$"),
                HOST,
                ArgRule::Pattern("^([0-9]{1,9}|default)$"),
            ],
        ),
    );
    t.insert(
        "route-ipv6",
        ArgSpec::new(
            1,
            3,
            vec![
                ArgRule::Pattern("^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$"),
                ArgRule::Pattern("^([0-9A-Fa-f:.]+|default|vpn_gateway|net_gateway|remote_host)$"),
                ArgRule::Pattern("^([0-9]{1,9}|default)$"),
            ],
        ),
    );
    t.insert("route-gateway", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^([0-9]{1,3}(\\.[0-9]{1,3}){3}|dhcp)$")]));
    t.insert("route-ipv6-gateway", ArgSpec::new(1, 1, vec![ArgRule::Pattern("^[0-9A-Fa-f:.]+$")]));
    t.insert("route-delay", ArgSpec::new(0, 2, vec![UINT, UINT]));
    t.insert("pull-filter", ArgSpec::new(2, 2, vec![one_of!("accept|ignore|reject"), TEXT]));
    // The lower-case form of the type passes too (OpenVPN decides if it is valid); a PROXY_* value may be a URL.
    // `(?i-u:…)`: ASCII-only case folding, like Foundation (U+017F / U+212A do not match).
    t.insert(
        "dhcp-option",
        ArgSpec::with_rest(
            1,
            16,
            vec![ArgRule::Pattern(
                "^(?i-u:DNS|DNS6|DOMAIN|DOMAIN-SEARCH|ADAPTER_DOMAIN_SUFFIX|WINS|NBDD|NTP|NBT|NBS|DISABLE-NBT|PROXY_[A-Z_]+)$",
            )],
            ArgRule::Pattern("^[A-Za-z0-9_\\[][A-Za-z0-9_.:/?=&%+@~\\[\\]-]*$"),
        ),
    );
    // `dns search-domains d…`, `dns server n address|resolve-domains|dnssec|transport|sni …`; n: -128…127.
    t.insert(
        "dns",
        ArgSpec::with_rest(
            2,
            16,
            vec![one_of!("search-domains|server")],
            ArgRule::Pattern("^(-[0-9]{1,3}|[A-Za-z0-9_\\[][A-Za-z0-9_.:\\[\\]-]*)$"),
        ),
    );
    t.insert("ifconfig", ArgSpec::new(2, 2, vec![IPV4, IPV4]));
    t.insert(
        "ifconfig-ipv6",
        ArgSpec::new(1, 2, vec![ArgRule::Pattern("^[0-9A-Fa-f:.]+/[0-9]{1,3}$"), ArgRule::Pattern("^[0-9A-Fa-f:.]+$")]),
    );
    t.insert("topology", ArgSpec::new(1, 1, vec![one_of!("net30|p2p|subnet")]));
    t.insert("tun-mtu", ArgSpec::new(1, 2, vec![UINT, UINT]));
    t.insert("fragment", ArgSpec::new(1, 2, vec![UINT, one_of!("mtu")]));
    t.insert("mssfix", ArgSpec::new(0, 2, vec![UINT, one_of!("mtu|fixed")]));
    t.insert("mtu-disc", ArgSpec::new(1, 1, vec![one_of!("no|maybe|yes")]));
    t.insert("setenv-safe", ArgSpec::new(1, 2, vec![ArgRule::Pattern("^[A-Za-z0-9_]+$"), TEXT]));
    t.insert("ignore-unknown-option", ArgSpec::with_rest(1, 64, vec![], ArgRule::Pattern("^[A-Za-z0-9-]+$")));
    t.insert("socks-proxy", ArgSpec::new(1, 3, vec![HOST, PORT, INLINE]));
    t.insert(
        "http-proxy",
        ArgSpec::new(1, 4, vec![HOST, PORT, one_of!("auto|auto-nct|\\[inline\\]"), one_of!("none|basic|ntlm|ntlm2")]),
    );
    t.insert("http-proxy-option", ArgSpec::with_rest(1, 3, vec![one_of!("VERSION|AGENT|CUSTOM-HEADER")], TEXT));
    t.insert("route-method", ArgSpec::new(1, 1, vec![one_of!("adaptive|ipapi|exe")]));
    t.insert("ip-win32", ArgSpec::new(1, 3, vec![one_of!("manual|dynamic|netsh|ipapi|exe|adaptive"), UINT, UINT]));
    t.insert("windows-driver", ArgSpec::new(1, 1, vec![one_of!("tap-windows6|wintun|ovpn-dco")]));
    t.insert("prng", ArgSpec::new(0, 2, vec![WORD, UINT]));
    t
});

/// The argument spec of a SAFE directive (one table for every OS; `os` stays for the callers: the Windows tier
/// forbids some of these names before this is consulted).
fn argument_spec_for(_os: TargetOs, directive: &str) -> Option<&'static ArgSpec> {
    map_get(&ARGUMENT_SPECS, directive)
}

/// The reason key of a RISKY directive on `os` (an unknown one: [`REASON_UNKNOWN`]).
fn risky_reason_for(os: TargetOs, directive: &str) -> &'static str {
    map_get(&RISKY_REASONS, directive)
        .or_else(|| map_get(platform_reasons(os), directive))
        .copied()
        .unwrap_or(REASON_UNKNOWN)
}

/// Set membership with Swift `Set<String>` semantics (canonical equivalence).
fn set_contains(set: &HashSet<&'static str>, s: &str) -> bool {
    set.contains(s) || (!s.is_ascii() && set.iter().any(|k| swift_str::eq(k, s)))
}

fn map_get<'a, V>(map: &'a HashMap<&'static str, V>, s: &str) -> Option<&'a V> {
    map.get(s)
        .or_else(|| if s.is_ascii() { None } else { map.iter().find(|(k, _)| swift_str::eq(k, s)).map(|(_, v)| v) })
}

fn hint() -> String {
    l10n::tr(" – delete the line or comment it out (#)", &[])
}

impl OpenVPNValidator {
    /// SAFE directives on this OS (the `argument_specs` keys). `setenv` is SAFE by its own rule.
    pub fn allowed() -> HashSet<&'static str> {
        Self::allowed_for(TargetOs::host())
    }

    /// SAFE directives on `os` (the `argument_specs` keys; Windows leaves out `FORBIDDEN_WINDOWS`, every OS its
    /// platform tier: on Linux the names NetworkManager ignores).
    pub fn allowed_for(os: TargetOs) -> HashSet<&'static str> {
        let mut names: HashSet<&'static str> = ARGUMENT_SPECS.keys().copied().collect();
        if os == TargetOs::Windows {
            names.retain(|d| !FORBIDDEN_WINDOWS.contains(d));
        }
        names.retain(|d| !platform_reasons(os).contains_key(d));
        names
    }

    /// The names that have an argument spec (SAFE).
    pub fn argument_spec_names() -> HashSet<&'static str> {
        Self::allowed()
    }

    pub fn has_argument_spec(directive: &str) -> bool {
        let host = TargetOs::host();
        argument_spec_for(host, directive).is_some()
            && !(host == TargetOs::Windows && set_contains(&FORBIDDEN_WINDOWS, directive))
            && map_get(platform_reasons(host), directive).is_none()
    }

    /// The tier of a directive on this OS ([`OpenVPNValidator::tier_for`] with [`TargetOs::host`]).
    pub fn tier(directive: &str) -> OpenVPNTier {
        Self::tier_for(TargetOs::host(), directive)
    }

    /// The tier of a directive on `os`: the tables; for an unknown name `FORBIDDEN_PATTERN`, otherwise RISKY.
    pub fn tier_for(os: TargetOs, directive: &str) -> OpenVPNTier {
        if set_contains(&FORBIDDEN, directive) {
            return OpenVPNTier::Forbidden;
        }
        if os == TargetOs::Windows && set_contains(&FORBIDDEN_WINDOWS, directive) {
            return OpenVPNTier::Forbidden;
        }
        // The platform tier before the SAFE table: on Linux the names NetworkManager ignores have an argument spec.
        if map_get(platform_reasons(os), directive).is_some() {
            return OpenVPNTier::Risky;
        }
        if directive == "setenv" || argument_spec_for(os, directive).is_some() {
            return OpenVPNTier::Safe;
        }
        if map_get(&RISKY_REASONS, directive).is_some() {
            return OpenVPNTier::Risky;
        }
        if matches(directive, FORBIDDEN_PATTERN) { OpenVPNTier::Forbidden } else { OpenVPNTier::Risky }
    }

    pub fn is_denied_setenv_name(name: &str) -> bool {
        let upper = name.to_uppercase();
        if SETENV_DENIED_NAMES.iter().any(|n| swift_str::eq(n, &upper)) {
            return true;
        }
        if SETENV_DENIED_PREFIXES.iter().any(|p| swift_str::has_prefix(&upper, p)) {
            return true;
        }
        SETENV_DENIED_CASE_SENSITIVE_PREFIXES.iter().any(|p| swift_str::has_prefix(name, p))
    }

    /// Windows: whether a `setenv` name is in [`SETENV_WINDOWS_ALLOWED_NAMES`] or starts with one of
    /// [`SETENV_WINDOWS_ALLOWED_PREFIXES`] (both case-insensitive, as Windows environment names are). The denylist
    /// ([`Self::is_denied_setenv_name`]) applies too.
    pub fn is_allowed_windows_setenv_name(name: &str) -> bool {
        let upper = name.to_ascii_uppercase();
        SETENV_WINDOWS_ALLOWED_NAMES.contains(&upper.as_str())
            || SETENV_WINDOWS_ALLOWED_PREFIXES.iter().any(|p| upper.len() > p.len() && upper.starts_with(p))
    }

    /// The rule for the arguments of RISKY (and unknown) directives: they cannot smuggle in a file, a path or a
    /// command. No leading `-`, `..`, `/` (only in a CIDR), `~`, `file:`, and no shell metacharacter
    /// (`` ` $ ; | & < > `` and backslash).
    pub fn is_harmless_argument(arg: &str) -> bool {
        if arg.is_empty()
            || swift_str::has_prefix(arg, "-")
            || swift_str::has_prefix(arg, "~")
            || swift_str::contains(arg, "..")
        {
            return false;
        }
        if swift_str::contains(&ascii_lowercased(arg), "file:") {
            return false;
        }
        if arg.bytes().any(|b| b"`$;|&<>\\".contains(&b)) {
            return false;
        }
        if swift_str::contains(arg, "/") {
            return super::wireguard::is_cidr(arg);
        }
        true
    }

    /// [`OpenVPNValidator::is_harmless_argument`] on `os`. On Windows a `:` is refused too, except in an IPv6
    /// address or prefix (security review L-9): `C:name` names a file relative to drive C's current folder (for the
    /// WinVPN Service, which runs `openvpn.exe` as SYSTEM, `C:\name`), `name:stream` an alternate data stream.
    pub fn is_harmless_argument_for(os: TargetOs, arg: &str) -> bool {
        if !Self::is_harmless_argument(arg) {
            return false;
        }
        if os != TargetOs::Windows || !arg.contains(':') {
            return true;
        }
        let address = arg.split_once('/').map_or(arg, |(a, _)| a);
        address.parse::<std::net::Ipv6Addr>().is_ok()
    }

    /// The `ConfigValidator` interface: without acknowledgements, the risky lines are issues too.
    pub fn validate_text(&self, text: &str) -> Vec<ValidationIssue> {
        self.validate_full(text, &HashSet::new()).all_issues()
    }

    /// Full result: blocking issues, risky findings and the risky names not acknowledged yet. `acknowledged_risky`
    /// can only accept RISKY names: a FORBIDDEN name in it has no effect. The tiers of this OS
    /// ([`OpenVPNValidator::validate_full_for`] with [`TargetOs::host`]).
    pub fn validate_full(&self, text: &str, acknowledged_risky: &HashSet<String>) -> OpenVPNValidation {
        self.validate_full_for(TargetOs::host(), text, acknowledged_risky)
    }

    /// [`OpenVPNValidator::validate_full`] with the tiers of `os`.
    pub fn validate_full_for(
        &self,
        os: TargetOs,
        text: &str,
        acknowledged_risky: &HashSet<String>,
    ) -> OpenVPNValidation {
        let mut issues: Vec<ValidationIssue> = Vec::new();
        let mut risky: Vec<RiskyFinding> = Vec::new();
        let mut in_block: Option<String> = None; // data block (content skipped)
        let mut block_line = 0;
        let mut connection_line: Option<i64> = None; // open <connection> block
        let mut has_remote = false;
        for (line_no, raw_line) in numbered_lines(text) {
            if has_control_character(raw_line) {
                issues.push(ValidationIssue::new(line_no, control_character_message()));
                continue;
            }
            if raw_line.len() > MAX_LINE_BYTES {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Line too long", &[])));
                continue;
            }
            let line = trim_space_tab(raw_line);
            if let Some(block) = &in_block {
                if swift_str::has_prefix(line, "</") {
                    if !swift_str::eq(&ascii_lowercased(line), &format!("</{block}>")) {
                        issues.push(ValidationIssue::new(line_no, l10n::tr("Invalid closing tag", &[])));
                    }
                    in_block = None;
                }
                continue;
            }
            if connection_line.is_some() && swift_str::has_prefix(line, "</") {
                if swift_str::eq(&ascii_lowercased(line), "</connection>") {
                    connection_line = None;
                } else {
                    issues.push(ValidationIssue::new(line_no, l10n::tr("Invalid closing tag", &[])));
                }
                continue;
            }
            if matches(line, "^<[A-Za-z0-9-]+>$") {
                let name = ascii_lowercased(&line[1..line.len() - 1]);
                if name == "connection" && connection_line.is_none() {
                    connection_line = Some(line_no);
                    continue;
                }
                let permitted = if connection_line.is_none() { &*ALLOWED_BLOCKS } else { &*CONNECTION_BLOCKS };
                if !permitted.contains(name.as_str()) {
                    issues.push(ValidationIssue::new(
                        line_no,
                        l10n::tr("Inline block not allowed: %@", &[Arg::Str(&name)]),
                    ));
                }
                in_block = Some(name);
                block_line = line_no;
                continue;
            }
            if line.is_empty() || swift_str::has_prefix(line, "#") || swift_str::has_prefix(line, ";") {
                continue;
            }
            let result = Self::check_line(os, line, connection_line.is_some());
            for m in &result.messages {
                issues.push(ValidationIssue::new(line_no, m.clone()));
            }
            if let Some((directive, reason_key)) = result.risky
                && result.messages.is_empty()
            {
                risky.push(RiskyFinding { directive, line: line_no, reason_key });
            }
            if result.directive.as_deref() == Some("remote") && result.messages.is_empty() {
                has_remote = true;
            }
        }
        if let Some(block) = &in_block {
            issues.push(ValidationIssue::new(block_line, l10n::tr("Unclosed inline block: %@", &[Arg::Str(block)])));
        }
        if let Some(line) = connection_line {
            issues.push(ValidationIssue::new(line, l10n::tr("Unclosed inline block: %@", &[Arg::Str("connection")])));
        }
        if !has_remote {
            issues.push(ValidationIssue::new(0, l10n::tr("Missing remote directive", &[])));
        }
        let names: BTreeSet<&str> = risky.iter().map(|r| r.directive.as_str()).collect();
        let unacknowledged = names
            .into_iter()
            .filter(|n| !acknowledged_risky.contains(*n) || Self::tier_for(os, n) != OpenVPNTier::Risky)
            .map(str::to_string)
            .collect();
        OpenVPNValidation { issues, risky, unacknowledged }
    }

    /// The directive name from the first token: optional `--`, then a `[A-Za-z0-9]`-initial `[A-Za-z0-9-]` name
    /// (lower-cased). `None`: invalid (e.g. a bare `--`, `---x`).
    pub(crate) fn directive_name(token: &str) -> Option<String> {
        if !matches(token, "^(--)?[A-Za-z0-9][A-Za-z0-9-]*$") {
            return None;
        }
        let name = ascii_lowercased(token);
        Some(name.strip_prefix("--").map(str::to_string).unwrap_or(name))
    }

    /// Checks one (trimmed, non-empty, non-comment) directive line.
    pub(crate) fn check_line(os: TargetOs, line: &str, in_connection: bool) -> LineResult {
        let first = swift_str::prefix_while(line, |c| c != " " && c != "\t");
        if Self::directive_name(first).is_none() {
            return LineResult { messages: vec![l10n::tr("Invalid directive", &[])], ..Default::default() };
        }
        let tokens = Self::tokenize(line);
        let valid_head = tokens
            .as_ref()
            .and_then(|t| t.first())
            .is_some_and(|head| !head.quoted && swift_str::eq(&head.text, first));
        let Some(tokens) = tokens.filter(|_| valid_head) else {
            let lower = ascii_lowercased(first);
            let directive = lower.strip_prefix("--").map(str::to_string).unwrap_or(lower);
            if Self::tier_for(os, &directive) == OpenVPNTier::Forbidden {
                let message = l10n::tr("Forbidden directive: %@", &[Arg::Str(&directive)]) + &hint();
                return LineResult { messages: vec![message], directive: Some(directive), risky: None };
            }
            let message = l10n::tr("Invalid argument: %@", &[Arg::Str(&directive)]);
            return LineResult { messages: vec![message], directive: Some(directive), risky: None };
        };
        let texts: Vec<String> = tokens.into_iter().map(|t| t.text).collect();
        Self::check_directive(os, &texts, in_connection)
    }

    /// A mirror of OpenVPN's `parse_line`: space/tab separate tokens; `"` or `'` starts a quote only at a token
    /// start, and the closing quote ends the token; `#` or `;` at a token start comments out the rest. A
    /// backslash (an escape in OpenVPN) or an unterminated quote gives `None`: these are rejected.
    pub(crate) fn tokenize(line: &str) -> Option<Vec<Token>> {
        let mut tokens = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut in_token = false;
        let mut quote: Option<u8> = None;
        let finish = |tokens: &mut Vec<Token>, current: &mut Vec<u8>, quoted: bool| {
            tokens.push(Token { text: String::from_utf8_lossy(current).into_owned(), quoted });
            current.clear();
        };
        for &byte in line.as_bytes() {
            if byte == 0x5C {
                return None;
            }
            if let Some(q) = quote {
                if byte == q {
                    quote = None;
                    finish(&mut tokens, &mut current, true);
                    in_token = false;
                } else {
                    current.push(byte);
                }
                continue;
            }
            if byte == 0x20 || byte == 0x09 {
                if in_token {
                    finish(&mut tokens, &mut current, false);
                    in_token = false;
                }
                continue;
            }
            if !in_token {
                if byte == 0x23 || byte == 0x3B {
                    break;
                }
                if byte == 0x22 || byte == 0x27 {
                    quote = Some(byte);
                    continue;
                }
                in_token = true;
            }
            current.push(byte);
        }
        if quote.is_some() {
            return None;
        }
        if in_token {
            finish(&mut tokens, &mut current, false);
        }
        Some(tokens)
    }

    /// Checks a directive line split into tokens. `setenv opt <directive> ...` is unwrapped once, as OpenVPN does
    /// (`add_option`: `p += 2`), and the inner directive is checked by [`Self::check_unwrapped`]; a second
    /// `setenv opt` is refused there, so there is no recursion.
    pub(crate) fn check_directive(os: TargetOs, tokens: &[String], in_connection: bool) -> LineResult {
        if tokens.len() > MAX_PARMS {
            let directive = Self::directive_name(&tokens[0]);
            let message = match &directive {
                Some(d) => l10n::tr("Wrong number of arguments: %@", &[Arg::Str(d)]),
                None => l10n::tr("Invalid directive", &[]),
            };
            return LineResult { messages: vec![message], directive, risky: None };
        }
        Self::check_unwrapped(os, tokens, in_connection, true)
    }

    /// [`Self::check_directive`] after the token cap; `may_unwrap`: whether `setenv opt` may still be unwrapped.
    fn check_unwrapped(os: TargetOs, tokens: &[String], in_connection: bool, may_unwrap: bool) -> LineResult {
        let Some(directive) = Self::directive_name(&tokens[0]) else {
            return LineResult { messages: vec![l10n::tr("Invalid directive", &[])], ..Default::default() };
        };
        let fail =
            |message: String| LineResult { messages: vec![message], directive: Some(directive.clone()), risky: None };
        let not_in_connection =
            || fail(l10n::tr("Directive not allowed in a <connection> block: %@", &[Arg::Str(&directive)]));
        if directive == "setenv" {
            if in_connection {
                return not_in_connection();
            }
            if tokens.len() < 2 {
                return fail(l10n::tr("setenv: missing argument", &[]));
            }
            if swift_str::eq(&ascii_lowercased(&tokens[1]), "opt") {
                if !may_unwrap {
                    return fail(l10n::tr("setenv not allowed: %@", &[Arg::Str("opt")]) + &hint());
                }
                if tokens.len() < 3 {
                    return fail(l10n::tr("setenv opt: missing directive", &[]));
                }
                let mut inner = Self::check_unwrapped(os, &tokens[2..], false, false);
                inner.directive = Some(directive);
                return inner;
            }
            if !matches(&tokens[1], SETENV_NAME_PATTERN) {
                return fail(l10n::tr("setenv not allowed", &[]) + &hint());
            }
            if Self::is_denied_setenv_name(&tokens[1])
                || (os == TargetOs::Windows && !Self::is_allowed_windows_setenv_name(&tokens[1]))
            {
                return fail(l10n::tr("setenv not allowed: %@", &[Arg::Str(&tokens[1])]) + &hint());
            }
            if tokens.len() > 3 {
                return fail(l10n::tr("Wrong number of arguments: %@", &[Arg::Str(&directive)]));
            }
            if tokens.len() == 3 && !Self::argument_matches(&tokens[2], ArgRule::Text) {
                return fail(l10n::tr("Invalid argument: %@", &[Arg::Str(&directive)]));
            }
            return LineResult { directive: Some(directive), ..Default::default() };
        }
        let args = &tokens[1..];
        // `script-security 0|1` runs no user script, and MacVPN's command-line `--script-security 2` comes after
        // the config, overriding it: SAFE (but, as in OpenVPN, not in a `<connection>` block). 2 and 3 (and
        // anything else) stay FORBIDDEN.
        if directive == "script-security"
            && args.len() == 1
            && (swift_str::eq(&args[0], "0") || swift_str::eq(&args[0], "1"))
        {
            if in_connection {
                return not_in_connection();
            }
            return LineResult { directive: Some(directive), ..Default::default() };
        }
        // `connection` is valid only as an inline block (`<connection>…</connection>`); the one-line form (a file
        // name) is not.
        if directive == "connection" {
            return fail(l10n::tr("Invalid directive", &[]));
        }
        // A SAFE directive the platform ignores (Linux: NetworkManager drops it): checked as SAFE below, then
        // reported as RISKY with the platform's reason, in a `<connection>` block too (where OpenVPN allows it).
        // `lport 0` asks for what NetworkManager does anyway (`--nobind`): no finding.
        let ignored = argument_spec_for(os, &directive)
            .and_then(|_| map_get(platform_reasons(os), &directive))
            .copied()
            .filter(|_| !(directive == "lport" && args.len() == 1 && swift_str::eq(&args[0], "0")));
        match Self::tier_for(os, &directive) {
            OpenVPNTier::Forbidden => {
                return fail(l10n::tr("Forbidden directive: %@", &[Arg::Str(&directive)]) + &hint());
            }
            OpenVPNTier::Risky if argument_spec_for(os, &directive).is_some() => {}
            OpenVPNTier::Risky => {
                if in_connection {
                    return not_in_connection();
                }
                if !args.iter().all(|a| Self::is_harmless_argument_for(os, a)) {
                    return fail(l10n::tr("Invalid argument: %@", &[Arg::Str(&directive)]));
                }
                let reason = risky_reason_for(os, &directive);
                return LineResult {
                    messages: vec![],
                    directive: Some(directive.clone()),
                    risky: Some((directive, reason)),
                };
            }
            OpenVPNTier::Safe => {}
        }
        let Some(spec) = argument_spec_for(os, &directive) else {
            return fail(l10n::tr("Invalid directive", &[]));
        };
        if in_connection && !CONNECTION_ALLOWED.contains(directive.as_str()) {
            return not_in_connection();
        }
        let file_reference =
            || fail(l10n::tr("External file reference, use an inline block: %@", &[Arg::Str(&directive)]));
        if FILE_REFERENCING.contains(directive.as_str())
            && let Some(a) = args.first()
            && !swift_str::eq(a, "[inline]")
        {
            return file_reference();
        }
        if directive == "http-proxy"
            && args.len() >= 3
            && !["auto", "auto-nct", "[inline]"].iter().any(|v| swift_str::eq(v, &args[2]))
        {
            return file_reference();
        }
        if directive == "socks-proxy" && args.len() >= 3 && !swift_str::eq(&args[2], "[inline]") {
            return file_reference();
        }
        if !(spec.min..=spec.max).contains(&args.len()) {
            return fail(l10n::tr("Wrong number of arguments: %@", &[Arg::Str(&directive)]));
        }
        for (i, arg) in args.iter().enumerate() {
            match spec.rule(i) {
                Some(rule) if Self::argument_matches(arg, rule) => {}
                _ => return fail(l10n::tr("Invalid argument: %@", &[Arg::Str(&directive)])),
            }
        }
        let risky = ignored.map(|reason| (directive.clone(), reason));
        LineResult { messages: vec![], directive: Some(directive), risky }
    }

    pub(crate) fn argument_matches(arg: &str, rule: ArgRule) -> bool {
        match rule {
            ArgRule::Pattern(p) => matches(arg, p),
            ArgRule::Number(lo, hi) => {
                if !matches(arg, "^[0-9]{1,10}$") {
                    return false;
                }
                arg.parse::<i64>().is_ok_and(|n| (lo..=hi).contains(&n))
            }
            ArgRule::Text => !arg.is_empty() && !arg.as_bytes().contains(&0x5C),
        }
    }
}

/// What a config says, read the way [`OpenVPNValidator::validate_full`] reads it: the directive lines (outside
/// data blocks, top level and inside `<connection>`), tokenized by [`OpenVPNValidator::tokenize`], and the names
/// of the data blocks (lower-cased). Lines the tokenizer rejects are left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfigOutline {
    pub directives: Vec<Vec<String>>,
    pub blocks: BTreeSet<String>,
    /// The lines of the `<key>` blocks (the private key).
    pub key: String,
    /// The certificate and PKCS#12 blocks (`ca`, `cert`, `extra-certs`, `pkcs12`) in config order: the block name
    /// and its lines.
    pub data: Vec<(String, String)>,
}

/// The data blocks [`ConfigOutline::data`] collects.
const OUTLINE_DATA_BLOCKS: [&str; 4] = ["ca", "cert", "extra-certs", "pkcs12"];

impl OpenVPNValidator {
    pub(crate) fn outline(text: &str) -> ConfigOutline {
        let mut outline = ConfigOutline::default();
        let mut in_block: Option<String> = None;
        let mut in_connection = false;
        for (_, raw_line) in numbered_lines(text) {
            if has_control_character(raw_line) {
                continue;
            }
            let line = trim_space_tab(raw_line);
            if let Some(block) = &in_block {
                if swift_str::has_prefix(line, "</") {
                    in_block = None;
                } else if block == "key" {
                    outline.key.push_str(line);
                    outline.key.push('\n');
                } else if let Some((_, text)) = outline.data.last_mut().filter(|(name, _)| name == block) {
                    text.push_str(line);
                    text.push('\n');
                }
                continue;
            }
            if in_connection && swift_str::has_prefix(line, "</") {
                in_connection = false;
                continue;
            }
            if matches(line, "^<[A-Za-z0-9-]+>$") {
                let name = ascii_lowercased(&line[1..line.len() - 1]);
                if name == "connection" && !in_connection {
                    in_connection = true;
                    continue;
                }
                outline.blocks.insert(name.clone());
                if OUTLINE_DATA_BLOCKS.contains(&name.as_str()) {
                    outline.data.push((name.clone(), String::new()));
                }
                in_block = Some(name);
                continue;
            }
            if line.is_empty() || swift_str::has_prefix(line, "#") || swift_str::has_prefix(line, ";") {
                continue;
            }
            let Some(tokens) = Self::tokenize(line) else { continue };
            let mut texts: Vec<String> = tokens.into_iter().map(|t| t.text).collect();
            if let Some(name) = texts.first().and_then(|t| Self::directive_name(t)) {
                texts[0] = name;
                outline.directives.push(texts);
            }
        }
        outline
    }
}

impl ConfigValidator for OpenVPNValidator {
    fn validate(&self, text: &str) -> Vec<ValidationIssue> {
        self.validate_text(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P2-M1: neither the token cap nor the one-level unwrap depends on the other; each alone keeps a deep
    /// `setenv opt` chain from growing the stack (the line-length cap in `validate_full_for` comes before both).
    #[test]
    fn deep_setenv_opt_chains_do_not_recurse() {
        let result = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let mut tokens: Vec<String> =
                    std::iter::repeat_n(["setenv", "opt"], 100_000).flatten().map(String::from).collect();
                tokens.extend(["verb".to_string(), "3".to_string()]);
                let capped = OpenVPNValidator::check_directive(TargetOs::MacOs, &tokens, false);
                let unwrapped = OpenVPNValidator::check_unwrapped(TargetOs::Windows, &tokens, false, true);
                (capped, unwrapped)
            })
            .unwrap()
            .join()
            .unwrap();
        for r in [result.0, result.1] {
            assert_eq!(r.messages.len(), 1);
            assert_eq!(r.directive.as_deref(), Some("setenv"));
            assert_eq!(r.risky, None);
        }
    }
}
