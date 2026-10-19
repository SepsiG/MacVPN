//! The navigation allowlist of every web view: only the app's own pages load. A link, a redirect, a
//! `location = …` or a form that leaves the app's origin is cancelled, so no window ever shows a foreign page with
//! the app's IPC bridge (the capabilities are per window, not per origin). External pages (the user guide, a
//! release page, a web sign-in) open in the default browser through NSWorkspace, never in a web view.

use tauri::Url;

/// The release origin: the embedded UI over the custom protocol (`custom-protocol` feature).
const APP_SCHEME: &str = "tauri";
const APP_HOST: &str = "localhost";

/// The Vite dev server (`build.devUrl` in tauri.conf.json), only in dev builds (`cfg(dev)`: without the
/// `custom-protocol` feature; a debug build with the embedded UI, such as the smoke build, does not allow it).
const DEV_ORIGIN: (&str, &str, u16) = ("http", "127.0.0.1", 1420);

/// Whether a web view may navigate to `url` (the `on_navigation` handler of every window).
pub fn is_allowed(url: &Url) -> bool {
    is_allowed_with(url, cfg!(dev))
}

fn is_allowed_with(url: &Url, dev: bool) -> bool {
    if url.scheme() == APP_SCHEME
        && url.host_str() == Some(APP_HOST)
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
        is_allowed_with(&Url::parse(url).unwrap(), dev)
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
    fn this_build_follows_its_cfg() {
        let dev_server = Url::parse("http://127.0.0.1:1420/").unwrap();
        assert_eq!(is_allowed(&dev_server), cfg!(dev));
        assert!(is_allowed(&Url::parse("tauri://localhost/index.html").unwrap()));
        assert!(!is_allowed(&Url::parse("https://example.com/").unwrap()));
    }
}
