//! The navigation allowlist of every web view: only the app's own pages load. A link, a redirect, a
//! `location = …` or a form that leaves the app's origin is cancelled, so no window ever shows a foreign page with
//! the app's IPC bridge (the capabilities are per window, not per origin). External pages (the user guide, a
//! release page, a web sign-in) open in the default browser (NSWorkspace, ShellExecute), never in a web view.

use macvpn_core::TargetOs;
use tauri::Url;

/// Where the embedded UI is served in a release build (`custom-protocol` feature): the scheme and the host.
pub type Origin = (&'static str, &'static str);

/// macOS (WKWebView): the custom protocol itself, `tauri://localhost`.
pub const MACOS_ORIGIN: Origin = ("tauri", "localhost");
/// Windows (WebView2 serves a custom protocol under a special host): `https://tauri.localhost`, because every
/// window is created with `use_https_scheme` (`tauri.windows.conf.json` and [`uses_https_scheme`]). Linux (phase
/// 4) would serve the custom protocol as macOS does.
pub const WINDOWS_ORIGIN: Origin = ("https", "tauri.localhost");

/// The Vite dev server (`build.devUrl` in tauri.conf.json), only in dev builds (`cfg(dev)`: without the
/// `custom-protocol` feature; a debug build with the embedded UI, such as the smoke build, does not allow it).
const DEV_ORIGIN: (&str, &str, u16) = ("http", "127.0.0.1", 1420);

/// The running product's origin (by its OS, so this module needs no OS `cfg`).
pub fn app_origin() -> Origin {
    origin_for(crate::platform::get().product().os)
}

fn origin_for(os: TargetOs) -> Origin {
    match os {
        TargetOs::Windows => WINDOWS_ORIGIN,
        TargetOs::MacOs | TargetOs::Linux => MACOS_ORIGIN,
    }
}

/// Whether a web view may navigate to `url` (the `on_navigation` handler of every window).
pub fn is_allowed(url: &Url) -> bool {
    is_allowed_with(url, app_origin(), cfg!(dev))
}

/// Whether the windows are created with `use_https_scheme` (Windows: the app origin is `https://tauri.localhost`;
/// macOS: `false`, the default, which changes nothing there).
pub fn uses_https_scheme() -> bool {
    app_origin().0 == "https"
}

fn is_allowed_with(url: &Url, (app_scheme, app_host): Origin, dev: bool) -> bool {
    if url.scheme() == app_scheme
        && url.host_str() == Some(app_host)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
    {
        return true;
    }
    let (scheme, host, port) = DEV_ORIGIN;
    dev && url.scheme() == scheme
        && url.host_str() == Some(host)
        && url.port() == Some(port)
        && url.username().is_empty()
        && url.password().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(url: &str, dev: bool) -> bool {
        is_allowed_with(&Url::parse(url).unwrap(), MACOS_ORIGIN, dev)
    }

    fn allowed_on_windows(url: &str, dev: bool) -> bool {
        is_allowed_with(&Url::parse(url).unwrap(), WINDOWS_ORIGIN, dev)
    }

    #[test]
    fn the_app_origin_is_allowed() {
        for dev in [false, true] {
            assert!(allowed("tauri://localhost", dev));
            assert!(allowed("tauri://localhost/index.html", dev));
            assert!(allowed("tauri://localhost/index.html?window=manage#log", dev));
        }
    }

    #[test]
    fn the_dev_server_only_in_dev_builds() {
        assert!(allowed("http://127.0.0.1:1420/", true));
        assert!(allowed("http://127.0.0.1:1420/index.html", true));
        assert!(!allowed("http://127.0.0.1:1420/", false));
        assert!(!allowed("http://127.0.0.1:1421/", true));
        assert!(!allowed("http://localhost:1420/", true));
        assert!(!allowed("https://127.0.0.1:1420/", true));
        assert!(!allowed("http://127.0.0.1/", true));
    }

    #[test]
    fn everything_else_is_refused() {
        for dev in [false, true] {
            for url in [
                "https://example.com/",
                "http://example.com/",
                "https://localhost/",
                "http://localhost/",
                "tauri://localhost.example.com/",
                "tauri://example.com/",
                "tauri://localhost:8080/",
                "tauri://user@localhost/",
                "tauri://user:pass@localhost/",
                "ipc://localhost/",
                "http://ipc.localhost/",
                "asset://localhost/etc/passwd",
                "file:///etc/passwd",
                "about:blank",
                "data:text/html,<script>alert(1)</script>",
                "javascript:alert(1)",
                "blob:tauri://localhost/1234",
                "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
                "mailto:someone@example.com",
            ] {
                assert!(!allowed(url, dev), "{url} (dev: {dev})");
            }
        }
    }

    #[test]
    fn the_windows_app_origin_is_https_tauri_localhost() {
        for dev in [false, true] {
            assert!(allowed_on_windows("https://tauri.localhost", dev));
            assert!(allowed_on_windows("https://tauri.localhost/index.html", dev));
            assert!(allowed_on_windows("https://tauri.localhost/index.html?window=manage#log", dev));
            for url in [
                "tauri://localhost/index.html",
                "http://tauri.localhost/index.html",
                "https://tauri.localhost:8443/index.html",
                "https://user@tauri.localhost/",
                "https://user:pass@tauri.localhost/",
                "https://tauri.localhost.example.com/",
                "https://evil.tauri.localhost/",
                "https://localhost/",
                "https://ipc.localhost/",
                "http://ipc.localhost/",
                "https://asset.localhost/x",
                "https://example.com/",
                "file:///C:/Windows/win.ini",
                "about:blank",
                "javascript:alert(1)",
                "ms-settings:appsfeatures",
            ] {
                assert!(!allowed_on_windows(url, dev), "{url} (dev: {dev})");
            }
        }
        assert!(allowed_on_windows("http://127.0.0.1:1420/", true));
        assert!(!allowed_on_windows("http://127.0.0.1:1420/", false));
    }

    #[test]
    fn the_origin_follows_the_product_os() {
        assert_eq!(origin_for(TargetOs::MacOs), MACOS_ORIGIN);
        assert_eq!(origin_for(TargetOs::Windows), WINDOWS_ORIGIN);
    }

    #[test]
    fn the_macos_origin_refuses_the_windows_one() {
        for dev in [false, true] {
            assert!(!allowed("https://tauri.localhost/index.html", dev));
            assert!(!allowed("http://tauri.localhost/index.html", dev));
        }
    }

    #[test]
    fn this_build_follows_its_cfg() {
        let dev_server = Url::parse("http://127.0.0.1:1420/").unwrap();
        assert_eq!(is_allowed(&dev_server), cfg!(dev));
        let (own, other) = if cfg!(windows) {
            ("https://tauri.localhost/index.html", "tauri://localhost/index.html")
        } else {
            ("tauri://localhost/index.html", "https://tauri.localhost/index.html")
        };
        assert!(is_allowed(&Url::parse(own).unwrap()));
        assert!(!is_allowed(&Url::parse(other).unwrap()));
        assert_eq!(uses_https_scheme(), cfg!(windows));
        assert!(!is_allowed(&Url::parse("https://example.com/").unwrap()));
    }
}
