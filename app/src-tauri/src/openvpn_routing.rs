//! OpenVPN's "Send all traffic over VPN" in the editor (LinVPN decisions 7 and 8, L-b resolved point 4): the
//! choice lives in the config text itself, so the editor reads it from the text and rewrites the text, and Save,
//! Cancel and the validator treat the change as any other text edit. The logic is `macvpn_core::openvpn_routing`;
//! these two commands only translate the UI's ids (`server`, `always`, `never`). Only the Connections window's
//! capability grants them; they read and return text only (no state, no system call).

use macvpn_app_core::editor::MAX_CONFIG_BYTES;
use macvpn_core::openvpn_routing::{self, Routing};

fn id(routing: Routing) -> &'static str {
    match routing {
        Routing::ServerDecides => "server",
        Routing::Always => "always",
        Routing::Never => "never",
    }
}

fn parse(id: &str) -> Result<Routing, String> {
    match id {
        "server" => Ok(Routing::ServerDecides),
        "always" => Ok(Routing::Always),
        "never" => Ok(Routing::Never),
        _ => Err("invalid routing value".into()),
    }
}

/// What the config says: `server`, `always` or `never`. A text over the editor's limit (which the editor refuses
/// to save anyway) reads as `server`.
#[tauri::command]
pub fn openvpn_routing_read(config: String) -> &'static str {
    if config.len() > MAX_CONFIG_BYTES {
        return id(Routing::ServerDecides);
    }
    id(openvpn_routing::read(&config))
}

/// The config text with `routing`'s line (the core's rewrite); an unknown value or a text over the editor's limit
/// is refused.
#[tauri::command]
pub fn openvpn_routing_write(config: String, routing: String) -> Result<String, String> {
    let routing = parse(&routing)?;
    if config.len() > MAX_CONFIG_BYTES {
        return Err("the config is too large".into());
    }
    Ok(openvpn_routing::write(&config, routing))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "client\nremote vpn.example.com 1194\ndev tun\n";

    #[test]
    fn openvpn_routing_reads_the_ids() {
        assert_eq!(openvpn_routing_read(format!("{BASE}redirect-gateway def1\n")), "always");
        assert_eq!(openvpn_routing_read(BASE.into()), "server");
        assert_eq!(openvpn_routing_read(format!("{BASE}pull-filter ignore \"redirect-gateway\"\n")), "never");
    }

    #[test]
    fn openvpn_routing_writes_the_cores_text() {
        let always = format!("{BASE}redirect-gateway def1\n");
        assert_eq!(
            openvpn_routing_write(always.clone(), "never".into()),
            Ok(openvpn_routing::write(&always, Routing::Never))
        );
        assert_eq!(openvpn_routing_write(BASE.into(), "always".into()), Ok(always.clone()));
        assert_eq!(openvpn_routing_write(always, "server".into()), Ok(BASE.to_string()));
    }

    #[test]
    fn openvpn_routing_refuses_an_unknown_value() {
        for bad in ["", "Always", "full", "split", "server "] {
            assert!(openvpn_routing_write(BASE.into(), bad.into()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn openvpn_routing_refuses_a_config_over_the_editors_limit() {
        let mut big = String::from(BASE);
        big.push_str(&"#".repeat(MAX_CONFIG_BYTES));
        assert!(openvpn_routing_write(big.clone(), "always".into()).is_err());
        assert_eq!(openvpn_routing_read(big), "server");
        let mut fits = String::from(BASE);
        fits.push_str(&"#".repeat(MAX_CONFIG_BYTES - BASE.len()));
        assert!(openvpn_routing_write(fits, "always".into()).is_ok());
    }
}
