//! `mvpn status`: the JSON array the app parses (`[{"id":…,"kind":…,"state":…,"iface":…,"ip":…,"since":…}]`),
//! byte for byte as the bash version printed it. The backend computes each connection's [`StatusLine`]; this
//! module only renders them.

/// One connection as `mvpn status` reports it. The backend passes checked values only: `id` a UUID, `kind` one of
/// the root layer's kinds, `iface` ASCII letters and digits, `ip` hex digits, `:` and `.`, `since` digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    pub id: String,
    pub kind: String,
    pub state: &'static str,
    /// Empty: `null`.
    pub iface: String,
    /// Empty: `null`.
    pub ip: String,
    /// The start time (Unix seconds, digits); `None`: `null`.
    pub since: Option<String>,
}

fn json_str(v: &str) -> String {
    if v.is_empty() { "null".into() } else { format!("\"{v}\"") }
}

/// `status_all`'s output: the lines in the given order, then a line end.
pub fn render(states: &[StatusLine]) -> String {
    let mut out = String::from("[");
    let mut sep = "";
    for st in states {
        out.push_str(&format!(
            "{sep}{{\"id\":\"{}\",\"kind\":\"{}\",\"state\":\"{}\",\"iface\":{},\"ip\":{},\"since\":{}}}",
            st.id,
            st.kind,
            st.state,
            json_str(&st.iface),
            json_str(&st.ip),
            st.since.as_deref().unwrap_or("null")
        ));
        sep = ",";
    }
    out.push_str("]\n");
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The exact text 1.4.0's `status::render` printed for three fixed run directories (an OpenVPN run whose
    /// process is gone, with its interface and address files; an SSTP run with a malformed start time; a WireGuard
    /// run whose interface has no utun mapping), captured before the JSON half moved here. The macOS backend's
    /// test renders the same directories into the same text.
    pub(crate) const GOLDEN_1_4: &str = concat!(
        "[{\"id\":\"0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\",\"kind\":\"openvpn\",\"state\":\"failed\",",
        "\"iface\":\"utun7\",\"ip\":\"10.8.0.2\",\"since\":1700000000},",
        "{\"id\":\"1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\",\"kind\":\"sstp\",\"state\":\"failed\",",
        "\"iface\":null,\"ip\":null,\"since\":null},",
        "{\"id\":\"2F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\",\"kind\":\"wireguard\",\"state\":\"failed\",",
        "\"iface\":\"mv12345678\",\"ip\":null,\"since\":1700000123}]\n"
    );

    fn line(id: &str, kind: &str, iface: &str, ip: &str, since: Option<&str>) -> StatusLine {
        StatusLine {
            id: id.into(),
            kind: kind.into(),
            state: "failed",
            iface: iface.into(),
            ip: ip.into(),
            since: since.map(String::from),
        }
    }

    #[test]
    fn three_fixed_lines_render_as_in_1_4() {
        let lines = [
            line("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "openvpn", "utun7", "10.8.0.2", Some("1700000000")),
            line("1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "sstp", "", "", None),
            line("2F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "wireguard", "mv12345678", "", Some("1700000123")),
        ];
        assert_eq!(render(&lines), GOLDEN_1_4);
        assert!(macvpn_core::status::parse_status(&render(&lines)).is_ok_and(|v| v.len() == 3));
    }

    #[test]
    fn states_and_the_empty_list() {
        assert_eq!(render(&[]), "[]\n");
        let mut up = line("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "wireguard", "utun4", "fd00::2", None);
        up.state = "connected";
        assert_eq!(
            render(&[up]),
            "[{\"id\":\"0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\",\"kind\":\"wireguard\",\"state\":\"connected\",\"iface\":\"utun4\",\"ip\":\"fd00::2\",\"since\":null}]\n"
        );
    }
}
