//! The per-OS Tauri config (Task 10): `tauri.conf.json` holds what every OS shares, `tauri.macos.conf.json` and
//! `tauri.windows.conf.json` are merged over it by the Tauri CLI (JSON merge patch). Reads the JSON files only.

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
    let mut merged = merge_patch(&config("tauri.conf.json"), &config("tauri.macos.conf.json"));
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

#[test]
fn windows_config_is_winvpn() {
    let merged = merge_patch(&config("tauri.conf.json"), &config("tauri.windows.conf.json"));
    assert_eq!(merged["productName"], "WinVPN");
    assert_eq!(merged["mainBinaryName"], "WinVPN");
    assert_eq!(merged["identifier"], "local.winvpn");
    assert_eq!(merged["bundle"]["targets"], serde_json::json!(["msi"]));
    assert_eq!(merged["bundle"]["icon"], serde_json::json!(["icons/32x32.png", "icons/128x128.png", "icons/icon.ico"]));
    assert_eq!(
        merged["bundle"]["windows"],
        serde_json::json!({"webviewInstallMode": {"type": "downloadBootstrapper"}})
    );
    assert!(merged["bundle"].get("macOS").is_none());
    assert!(merged["app"].get("macOSPrivateApi").is_none());
    // Shared: the version, the windows, the CSP and the capabilities.
    let base = config("tauri.conf.json");
    assert_eq!(merged["version"], base["version"]);
    assert_eq!(merged["app"]["windows"], base["app"]["windows"]);
    assert_eq!(merged["app"]["security"], base["app"]["security"]);
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
    for name in ["tauri.macos.conf.json", "tauri.windows.conf.json"] {
        assert!(config(name).get("version").is_none(), "{name} has no version of its own");
    }
}
