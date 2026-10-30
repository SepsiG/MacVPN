//! The per-OS Tauri config (Task 10): `tauri.conf.json` holds what every OS shares, `tauri.macos.conf.json`,
//! `tauri.windows.conf.json` and `tauri.linux.conf.json` are merged over it by the Tauri CLI (JSON merge patch).
//! Reads the JSON files only.

use serde_json::Value;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn config(name: &str) -> Value {
    json(&Path::new(env!("CARGO_MANIFEST_DIR")).join(name))
}

/// RFC 7396: an object patch merges key by key (`null` removes), anything else replaces the target.
fn merge_patch(target: &Value, patch: &Value) -> Value {
    let Value::Object(patch) = patch else { return patch.clone() };
    let mut out = match target {
        Value::Object(t) => t.clone(),
        _ => serde_json::Map::new(),
    };
    for (key, value) in patch {
        if value.is_null() {
            out.remove(key);
        } else {
            let merged = merge_patch(out.get(key).unwrap_or(&Value::Null), value);
            out.insert(key.clone(), merged);
        }
    }
    Value::Object(out)
}

#[test]
fn merge_patch_follows_rfc_7396() {
    let target = serde_json::json!({"a": "b", "c": {"d": "e", "f": "g"}, "l": [1, 2]});
    let patch = serde_json::json!({"a": "z", "c": {"f": null}, "l": [3], "n": {"x": 1}});
    assert_eq!(merge_patch(&target, &patch), serde_json::json!({"a": "z", "c": {"d": "e"}, "l": [3], "n": {"x": 1}}));
}

/// Base + macOS is the 1.4.0 config the bundler used (Task 1's baseline), the version normalized.
#[test]
fn macos_config_is_the_1_4_0_config() {
    let mut merged = merged_config("tauri.macos.conf.json");
    assert!(merged["version"].is_string());
    merged["version"] = Value::String("@VERSION@".into());
    assert_eq!(merged, json(&root().join("scripts/bundle-baseline/1.4.0/tauri-config.json")));
}

/// The base holds no macOS-only setting; the macOS identity is the default.
#[test]
fn base_config_is_shared() {
    let base = config("tauri.conf.json");
    assert_eq!(base["productName"], "MacVPN");
    assert_eq!(base["mainBinaryName"], "MacVPN");
    assert_eq!(base["identifier"], "local.macvpn");
    assert!(base["app"].get("macOSPrivateApi").is_none());
    for key in ["targets", "icon", "macOS"] {
        assert!(base["bundle"].get(key).is_none(), "bundle.{key} is per OS");
    }
}

fn merged_config(os_file: &str) -> Value {
    merge_patch(&config("tauri.conf.json"), &config(os_file))
}

/// Base + Windows: WinVPN's identity, the same windows as MacVPN's but titled WinVPN, the default associations of
/// .ovpn, .sstp and .macvpncatalog (no .conf: that one is "Open with" only, through the WiX fragment).
#[test]
fn the_windows_config_is_winvpn() {
    let merged = merged_config("tauri.windows.conf.json");
    assert_eq!(merged["productName"], "WinVPN");
    assert_eq!(merged["mainBinaryName"], "WinVPN");
    assert_eq!(merged["identifier"], "local.winvpn");
    assert_eq!(merged["bundle"]["copyright"], "WinVPN");
    assert_eq!(merged["bundle"]["targets"], serde_json::json!(["msi"]));
    assert_eq!(merged["bundle"]["icon"], serde_json::json!(["icons/32x32.png", "icons/128x128.png", "icons/icon.ico"]));
    // The WebView2 bootstrapper ships inside the MSI (its Binary table; build-msi.sh checks its Microsoft signature):
    // nothing is downloaded into the user's %TEMP% and run from there (security review part 2, P2-L1).
    assert_eq!(merged["bundle"]["windows"]["webviewInstallMode"], serde_json::json!({"type": "embedBootstrapper"}));
    // An older MSI never installs over a newer one; the same version still does (Tauri's template then writes
    // AllowSameVersionUpgrades="yes"; P2-L2).
    assert_eq!(merged["bundle"]["windows"]["allowDowngrades"], serde_json::json!(false));
    // The MSI installs the Windows notices (scripts/third-party-notices.mjs --os windows) next to WinVPN.exe.
    assert_eq!(
        merged["bundle"]["resources"],
        serde_json::json!({"../../THIRD-PARTY-NOTICES.windows.txt": "THIRD-PARTY-NOTICES.txt"})
    );
    assert!(root().join("THIRD-PARTY-NOTICES.windows.txt").is_file());
    assert!(config("tauri.conf.json")["bundle"].get("resources").is_none(), "MacVPN's notices come from build-dmg.sh");
    assert!(merged["bundle"].get("macOS").is_none());
    assert!(merged["app"].get("macOSPrivateApi").is_none());
    // Shared: the version, the CSP (but IPC: WebView2 with `useHttpsScheme` posts to https://ipc.localhost, and an
    // https page may not fetch http) and the capabilities.
    let base = config("tauri.conf.json");
    assert_eq!(merged["version"], base["version"]);
    let mut security = merged["app"]["security"].clone();
    assert_eq!(security["csp"]["connect-src"], "ipc: https://ipc.localhost");
    security["csp"]["connect-src"] = base["app"]["security"]["csp"]["connect-src"].clone();
    assert_eq!(security, base["app"]["security"], "only connect-src differs");
    let (mut ours, mut theirs) = (merged["app"]["windows"].clone(), base["app"]["windows"].clone());
    ours[0]["title"] = "".into();
    theirs[0]["title"] = "".into();
    // Every window loads the UI from https://tauri.localhost (`navigation::WINDOWS_ORIGIN`; the windows built in
    // code set the same through `navigation::uses_https_scheme`).
    assert_eq!(ours[0]["useHttpsScheme"], true);
    assert!(theirs[0].get("useHttpsScheme").is_none(), "macOS keeps tauri://localhost");
    ours[0].as_object_mut().unwrap().remove("useHttpsScheme");
    assert_eq!(ours, theirs, "the same windows apart from the title and the https scheme");
    assert_eq!(merged["app"]["windows"].as_array().unwrap().len(), 1);
    assert_eq!(merged["app"]["windows"][0]["title"], "WinVPN");
    let exts: Vec<String> = merged["bundle"]["fileAssociations"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|a| a["ext"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()))
        .collect();
    assert_eq!(exts, ["ovpn", "sstp", "macvpncatalog"]);
    let wix = &merged["bundle"]["windows"]["wix"];
    assert_eq!(wix["fragmentPaths"][0], "wix/file-associations.wxs");
    assert_eq!(wix["componentRefs"][0], "WinVPNConfOpenWith");
    let upgrade = wix["upgradeCode"].as_str().unwrap();
    assert_eq!(upgrade.len(), 36, "a fixed GUID: MSI upgrades find the installed WinVPN by it");
    let fragment =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("wix/file-associations.wxs")).unwrap();
    assert!(fragment.contains(r"Software\Classes\.conf\OpenWithProgids"));
    assert!(!fragment.contains("<Extension"), ".conf never becomes WinVPN's by default");
}

/// The `.conf` entry of the WiX fragment: one named value under HKLM `.conf\OpenWithProgids` with no data (WiX 3.14
/// takes `Value=""` and writes the MSI row with a null Value: the value's name is all "Open with" reads), the ProgId
/// it names opening WinVPN.exe, and nothing that writes `.conf`'s default value (WinVPN never becomes its default
/// app). `scripts/build-msi.sh` checks the same in the built MSI's Registry table.
#[test]
fn the_conf_fragment_is_open_with_only() {
    let fragment =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("wix/file-associations.wxs")).unwrap();
    let values: Vec<&str> = fragment.lines().map(str::trim).filter(|l| l.starts_with("<RegistryValue")).collect();
    assert_eq!(values.len(), 3, "{values:?}");
    let conf: Vec<&&str> = values.iter().filter(|v| v.contains(r"\.conf")).collect();
    assert_eq!(
        conf,
        [
            &r#"<RegistryValue Root="HKLM" Key="Software\Classes\.conf\OpenWithProgids" Name="WinVPN.conf" Value="" Type="string" />"#
        ]
    );
    assert!(values.iter().any(|v| v.contains(r#"Key="Software\Classes\WinVPN.conf\shell\open\command" Value="&quot;[INSTALLDIR]WinVPN.exe&quot; &quot;%1&quot;""#)));
    assert!(!fragment.contains("<ProgId") && !fragment.contains("<Extension"));
}

/// LinVPN's identity (`tauri.linux.conf.json` merged over the base, as the Tauri CLI and `generate_context!` do on
/// Linux): the menu window is the card panel's transparent overlay (spike L0-2, CP-L0: maximized at show, the card
/// drawn at the top-right, the input region the card); everything else of the base popover stays.
#[test]
fn linux_config_is_linvpn() {
    let base = config("tauri.conf.json");
    let linux = config("tauri.linux.conf.json");
    let merged = merged_config("tauri.linux.conf.json");
    assert_eq!(merged["productName"], "LinVPN");
    assert_eq!(merged["mainBinaryName"], "linvpn");
    assert_eq!(merged["identifier"], "local.linvpn");
    assert_eq!(merged["bundle"]["active"], false, "the .deb is built by scripts/build-deb.sh");
    assert_eq!(merged["bundle"]["copyright"], "LinVPN");
    assert_eq!(merged["version"], base["version"]);
    assert!(linux.get("version").is_none(), "no version of its own");
    assert_eq!(merged["app"]["security"], base["app"]["security"], "the CSP and the capabilities are shared");
    let windows = merged["app"]["windows"].as_array().unwrap();
    assert_eq!(windows.len(), 1);
    let menu = &windows[0];
    assert_eq!(menu["label"], "menu");
    assert_eq!(menu["title"], "LinVPN");
    assert_eq!(menu["transparent"], true, "the overlay: only the card is drawn");
    assert!(menu.get("useHttpsScheme").is_none(), "WebKitGTK serves tauri://localhost, as macOS");
    // Arrays are replaced whole by the merge: the popover keeps every other setting of the base.
    let base_menu = base["app"]["windows"][0].as_object().unwrap();
    for (key, value) in base_menu {
        if key != "title" {
            assert_eq!(&menu[key], value, "menu.{key}");
        }
    }
    let extra: Vec<&String> = menu.as_object().unwrap().keys().filter(|k| !base_menu.contains_key(*k)).collect();
    assert_eq!(extra, ["transparent"]);
    assert!(merged["app"].get("macOSPrivateApi").is_none());
    for key in ["targets", "icon", "macOS", "windows", "fileAssociations", "resources"] {
        assert!(merged["bundle"].get(key).is_none(), "bundle.{key}: the .deb has its own files");
    }
}

/// `scripts/build-dmg.sh` reads the version from `tauri.conf.json` (`plutil -extract version`): it stays there.
#[test]
fn build_script_finds_the_version_in_the_base_config() {
    let script = std::fs::read_to_string(root().join("scripts/build-dmg.sh")).unwrap();
    assert!(script.contains("TAURI_CONF=app/src-tauri/tauri.conf.json\n"));
    assert!(script.contains("VERSION=$(json_version \"$TAURI_CONF\")"));
    let version = config("tauri.conf.json")["version"].as_str().unwrap().to_string();
    let workspace = std::fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(workspace.contains(&format!("\nversion = \"{version}\"\n")), "tauri.conf.json version {version}");
    for name in ["tauri.macos.conf.json", "tauri.windows.conf.json", "tauri.linux.conf.json"] {
        assert!(config(name).get("version").is_none(), "{name} has no version of its own");
    }
}
