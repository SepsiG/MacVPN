//! Port of the `LocalizationTests.swift` cases that concern the core table and language selection.

use macvpn_core::l10n::{self, AppLanguage, Arg, with_language};
use regex::Regex;

#[test]
fn resolve_picks_first_hungarian_or_english_else_english() {
    assert_eq!(AppLanguage::resolve(&["hu-HU", "en-US"]), AppLanguage::Hu);
    assert_eq!(AppLanguage::resolve(&["en-GB", "hu"]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve(&["de-DE", "hu-HU"]), AppLanguage::Hu);
    assert_eq!(AppLanguage::resolve(&["de-DE", "fr"]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve(&["hr-HR"]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve::<&str>(&[]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve(&["HU_hu"]), AppLanguage::Hu);
}

#[test]
fn lang_argument_unknown_means_english() {
    assert_eq!(AppLanguage::from_argument("hu"), AppLanguage::Hu);
    assert_eq!(AppLanguage::from_argument("en"), AppLanguage::En);
    assert_eq!(AppLanguage::from_argument("de"), AppLanguage::En);
    assert_eq!(AppLanguage::from_argument(""), AppLanguage::En);
}

#[test]
fn explicit_language_parameter() {
    assert_eq!(l10n::tr_in(AppLanguage::En, "Missing remote directive", &[]), "Missing remote directive");
    assert_eq!(l10n::tr_in(AppLanguage::Hu, "Missing remote directive", &[]), "Hiányzik a remote direktíva");
    assert_eq!(l10n::tr_in(AppLanguage::Hu, "Line %ld: %@", &[Arg::Int(3), Arg::Str("x")]), "3. sor: x");
    assert_eq!(l10n::tr_in(AppLanguage::En, "Line %ld: %@", &[Arg::Int(3), Arg::Str("x")]), "Line 3: x");
    // A missing key falls back to the English text.
    assert_eq!(l10n::tr_in(AppLanguage::Hu, "No such key %@", &[Arg::Str("x")]), "No such key x");
}

#[test]
fn thread_override_wins_and_is_restored() {
    with_language(AppLanguage::Hu, || {
        assert_eq!(AppLanguage::current(), AppLanguage::Hu);
        with_language(AppLanguage::En, || assert_eq!(AppLanguage::current(), AppLanguage::En));
        assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    });
}

/// Format specifiers (`%@`, `%ld`, `%d`, also positional), as a sorted multiset.
fn specifiers(s: &str) -> Vec<String> {
    let re = Regex::new(r"%(?:[0-9]+\$)?(l{0,2}[dfu]|@)").unwrap();
    let mut v: Vec<String> = re.captures_iter(s).map(|c| c[1].to_string()).collect();
    v.sort();
    v
}

#[test]
fn core_table_has_both_languages_for_every_key() {
    assert!(!l10n::table().is_empty());
    for e in l10n::table() {
        let (key, hu) = (&e.key, &e.hu);
        assert!(!key.is_empty());
        assert!(!hu.trim_matches(' ').is_empty(), "empty Hungarian text: {key}");
        assert_eq!(specifiers(key), specifiers(hu), "different format specifiers: {key}");
    }
}

/// The core part of `strings.json` equals the Swift `L10n.hungarian` table, verbatim and complete. (The Swift app
/// stays in `legacy/swift` until 1.0.0 ships as the reference; this test goes with it.)
#[test]
fn table_matches_the_swift_core_table() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let swift = std::fs::read_to_string(root.join("legacy/swift/Sources/MacVPNCore/L10n.swift")).unwrap();
    let body = &swift[swift.find("public static let hungarian").unwrap()..];
    let flat = body.replace('\n', " ");
    let unescape = |s: &str| s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
    let pair = Regex::new(r#""((?:[^"\\]|\\.)*)":\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let mut swift_table = std::collections::HashMap::new();
    for c in pair.captures_iter(&flat) {
        swift_table.insert(unescape(&c[1]), unescape(&c[2]));
    }
    let core: Vec<_> = l10n::table().into_iter().filter(|e| e.scope == "core").collect();
    assert_eq!(core.len(), swift_table.len());
    for e in core {
        assert_eq!(swift_table.get(&e.key), Some(&e.hu), "{}", e.key);
    }
}

/// The `app` texts of the Rust UI that the Swift app did not have (from 1.1.0: the control API's pairing window and
/// Paired apps section, the live system VPN list, the credential prompt window; from 1.2.0: shared credentials).
const RUST_ONLY_APP_TEXTS: &[&str] = &[
    "Saved — type to replace",
    "Remove saved password",
    // 1.2: shared credentials.
    "This connection uses the shared credential %@. Change its user name and password in the Credentials section.",
    "Password for %@ — used by %lld connections",
    "Password for %@ — used by 1 connection",
    // 1.2: the Credentials section, the editors' selector, the import's question (Task 19).
    "A credential name must have 1 to 64 characters and no control characters.",
    "A credential named %@ already exists.",
    "A user name and password that several connections share. Change it here once, and every connection that uses it signs in with the new one. Passwords are stored in the vault and never shown.",
    "Add Credential…",
    "Connection",
    "Copy into Each Connection",
    "Create and Link",
    "Create from Connection",
    "Create from Connection…",
    "Credentials",
    "Edit %@",
    "Edit…",
    "Link the Same Sign-in?",
    "New Shared Credential",
    "Next",
    "No other connection has the same user name and password.",
    "No password saved: asked when connecting",
    "No shared credentials yet. Add one, or create one from a connection that already has a user name and password.",
    "No user name",
    "Own username and password",
    "Password from",
    "Password saved",
    "Rename %@",
    "Rename…",
    "The account name is only written into the profile. MacVPN signs in with the shared credential.",
    "The connection's stored user name and password become a shared credential that it then uses. The values are not shown.",
    "The imported file was exported with this shared credential. The user name and password you choose are sent to %@, the server named in the file. Choose a shared credential only if you trust the file; otherwise the connection uses its own user name and password.",
    "The imported file was exported with this shared credential. The user name and password you choose are sent to the server named in the file. Choose a shared credential only if you trust the file; otherwise the connection uses its own user name and password.",
    "The imported file was exported with this shared credential. Its user name and password are sent to the server named in the file. Choose Use Shared Credential only if you trust the file; otherwise the connection uses its own user name and password.",
    "The password comes from the shared credential %@. Change it in the Credentials section.",
    "The password must have at most 1024 bytes and no control characters.",
    "The shared credential '%@' was not checked: %@",
    "The shared credential could not be changed: %@",
    "The user name and password come from the shared credential %@. Change them in the Credentials section.",
    "The user name and password stored for this connection are deleted. It then signs in with the shared credential's.",
    "The user name must have at most 256 bytes and no control characters.",
    "There is no shared credential named '%@'",
    "There is no shared credential named '%@'. The connection uses its own user name and password.",
    "These connections have the same user name and password. The ticked ones will use the new shared credential too.",
    "These connections use this shared credential. Copy its user name and password into each of them, then delete it?",
    "This connection already uses a shared credential.",
    "This connection has no stored user name to share.",
    "This data was saved by a newer MacVPN. Update the app to make changes.",
    "Use Credential",
    "Use Own Fields",
    "Use Shared Credential",
    "Use credential: %@",
    "Use the shared credential %@?",
    "Use the shared credential '%@' for this connection to %@?",
    "Use the shared credential '%@' for this connection?",
    "Used by %lld connections",
    "Used by 1 connection",
    "User name and password",
    "Without a password, MacVPN asks for it when connecting and can save it here.",
    "Connecting…",
    "Disconnecting…",
    "Allow an App to Control VPNs?",
    "An app on this Mac asks to bring the connections you choose up and down. Allow it only if you started this app and you trust it.",
    "Name (self-reported)",
    "Executable",
    "Connections it may use",
    "There are no connections to allow.",
    "Deny",
    "Allow",
    "Paired apps",
    "Allow other apps to control VPNs",
    "Programs on this Mac that you pair can list the connections you allow, and bring them up and down. They never see configurations or passwords.",
    "Revoke",
    "Path changed",
    "This app was started from another location: %@. Revoke it and pair it again to use the new copy.",
    "Last used: %@",
    "Never used",
    "Paired: %@",
    "Allowed connections",
    "Held by %@",
    "No paired apps yet. An app asks for pairing while this is on.",
    "Activity",
    "No activity yet.",
    "Revoke %@?",
    "The app can no longer control VPNs, and its open sessions end now. Connections that only it brought up are disconnected.",
    "Could not change the allowed connections: %@",
    "Could not revoke %@: %@",
    // 1.1: the live system VPN list.
    "This VPN was removed from macOS",
    // 1.1: the credential prompt.
    "Credentials needed",
    "Not ready yet. Wait a moment, then click Connect again.",
    "MacVPN did not accept these values. Check them and try again.",
    // 1.2: the vault (Task 11: the locked state and the legacy read-only mode).
    "The vault is locked. Unlock it and try again.",
    "MacVPN is using the old storage in read-only mode until the migration succeeds",
    // 1.2: the vault windows (Task 14).
    "1 item could not be read and was left where it was.",
    "%lld connections and %lld saved secrets were moved and checked. The old copies are deleted when you continue.",
    "%lld items could not be read and were left where they were.",
    "At least %lld characters. A long phrase is easier to remember and harder to guess.",
    "Back",
    "Check your recovery key",
    "Choose a master password",
    "Confirm",
    "Copied",
    "Create Vault",
    "Creating…",
    "Done",
    "Each connection and saved password is copied, checked, and only then deleted from the old place.",
    "Enter the master password to open the vault.",
    "Enter your recovery key and choose a new master password. Your connections stay as they are.",
    "Fair",
    "Group %lld",
    "I Saved It",
    "If macOS asks for access to the Keychain, choose Always Allow.",
    "If you forget the master password, this key is the only way back into the vault. Write it down or keep it in a password manager. It is shown only now.",
    "Keep your recovery key safe. You can change the master password and make a new recovery key in the menu’s settings.",
    "Kept encrypted in the MacVPN vault, used from the next connect on",
    "MacVPN is locked",
    "MacVPN keeps your connections and their passwords in an encrypted vault. A master password protects it; a recovery key gets you back in if you forget the password.",
    "Master password",
    "Moving your data into the vault…",
    "New master password",
    "Not ready yet. Wait a moment, then try again.",
    "Nothing was deleted. MacVPN keeps using your old data, read-only, until the migration succeeds. The new vault was removed: try again with a new master password.",
    "Recovery key",
    "Repeat the master password",
    "Repeat the new master password",
    "Reset and Unlock",
    "Reset the master password",
    "Restore from backup…",
    "Save in vault",
    "Set Up the Vault",
    "Set up the vault",
    "Strong",
    "The migration did not finish",
    "The migration did not finish: %@",
    "The two passwords are not the same",
    "The vault could not be created: %@",
    "The vault is damaged and cannot be opened",
    "The vault is ready",
    "The vault key is kept in the macOS Keychain, so MacVPN opens without asking. Turn it off to type the master password at every launch.",
    "This is not a valid recovery key",
    "This is not group %lld of your recovery key",
    "This vault was saved by a newer MacVPN. Update MacVPN to open it.",
    "Too short",
    "Try Again",
    "Try again in %lld s",
    "Type group %lld of your recovery key, counting from the left.",
    "Unlock",
    "Unlock MacVPN",
    "Unlock automatically",
    "Unlocking…",
    "Use recovery key",
    "Use the master password",
    "Wait a moment before the next attempt",
    "Weak — easy to guess",
    "Wrong password or recovery key",
    "You can back up the whole vault into one encrypted file at any time from the menu’s settings.",
    "Your data is in the vault",
    "Your existing connections and saved passwords move into the vault, and the old copies are deleted after they were checked.",
    "Your recovery key",
    "macOS may ask once for access to the Keychain — choose Always Allow. This happens only once.",
    "macOS may ask up to %lld times for access to the Keychain — choose Always Allow each time. This happens only once.",
    // 1.2: the vault settings, Lock now, the locked menu (Task 15).
    "%lld connections active",
    "1 connection active",
    "Automatic unlock could not be turned off: %@",
    "Automatic unlock could not be turned on: %@",
    "Change Master Password…",
    "Change Password",
    "Change the master password",
    "Current master password",
    "Enter the current master password, then the new one twice.",
    "Enter the master password. Its key is then kept in the macOS Keychain, and MacVPN opens without asking.",
    "Finish setting up the vault…",
    "Lock Now",
    "MacVPN keeps your connections in an encrypted vault.",
    "MacVPN will ask for the master password at every launch.",
    "Make New Key",
    "Make a new recovery key",
    "Master Password",
    "New Recovery Key",
    "New Recovery Key…",
    "Set Up the Vault…",
    "Show “Lock Now”",
    "The master password was changed",
    "The move into the vault did not finish. Try again…",
    "The new key replaces the old one: the old key stops working at once. Enter the master password to go on.",
    "The new recovery key is ready",
    "The old recovery key no longer works. Keep the new one safe.",
    "Turn Off",
    "Turn On",
    "Turn off automatic unlock?",
    "Turn on automatic unlock",
    "Unlock…",
    "Use the new master password from now on. Your recovery key stays the same.",
    // 1.2: folders and colours.
    "Folders can be made once your data is in the vault.",
    "MacVPN checks your master password before every backup.",
    "Enter your master password in the window that opened to turn on automatic unlock.",
    "A VPN connection failed",
    "A VPN connection dropped",
    "A VPN connection needs authentication",
    "Your MacVPN 1.1 data will not be imported. It will be deleted after the backup is restored.",
    "Your vault and its data were kept. MacVPN tries to finish the move of the old data again at the next launch, or now with Try Again.",
    // 1.2: the saved secrets are in the vault, no longer in the Keychain.
    "%@ refers to these files. If you choose Use, their user name, password or private key password is stored in the vault for this connection. The files are never copied into the config.",
    "Also delete user data (connections, the vault and its key)",
    "Authentication (stored in the vault)",
    "Stored in the MacVPN vault and passed to macOS when connecting. Needed when macOS cannot read the shared secret on its own (\"incorrect user shared secret\").",
    "The export INCLUDES the private keys and credentials from the config (%@). Passwords and the PSK stored in the vault are not included.",
    "The password is stored in the vault. Use user@domain instead of DOMAIN\\user.",
    "The private key password from %@ is stored in the vault.",
    "The username and password from %@ are stored in the vault; the file is not copied into the config.",
    "~/Library/Application Support/MacVPN with the vault, and in the Keychain the vault key and the old MacVPN 1.1 items",
    "%lld active",
    "A folder cannot be moved into itself or one of its subfolders",
    "A folder name needs 1 to 64 characters and no control characters",
    "Amber",
    "Blue",
    "Colour",
    "Colour…",
    "Could not change the folders",
    "Cyan",
    "Delete %lld connections?",
    "Delete Connections",
    "Delete the connections too",
    "Delete…",
    "Disconnect the connections in this folder before deleting them",
    "Folder name",
    "Folders are not available",
    "Folders cannot be changed while the vault is locked",
    "Green",
    "Imported to the top level: the folder could not be created (%@)",
    "Indigo",
    "Lime",
    "Move its contents to the parent folder",
    "Move its contents to the top level",
    "Move to Top Level",
    "New Folder",
    "Orange",
    "Own colour",
    "Pink",
    "Purple",
    "Red",
    "Rename",
    "System VPNs are moved to the top level.",
    "Teal",
    "The connections in %@ and its subfolders are deleted with their saved passwords. This cannot be undone.",
    "The folder change failed: %@",
    "This connection no longer exists",
    "This folder no longer exists",
    "Top level",
    "Unknown colour",
    "Unknown delete option",
    "Use folder colour",
    "What should happen to its contents?",
    "Yellow",
    // 1.2: the full backup and restore.
    "A missing tool or root helper shows in System Status, as usual.",
    "A restore from the first-run window needs a new, empty vault.",
    "Adds what is missing here: %lld new items. Already here: %lld.",
    "Already the same: %@",
    "Another backup or restore is running.",
    "Anyone with this file and its password can read all your VPN credentials.",
    "Apply Selected Preferences",
    "At least %d characters. MacVPN does not store it: without it the backup cannot be opened.",
    "Automatic unlocking could not be changed.",
    "Back Up Everything",
    "Back Up Everything…",
    "Back Up the Current State First…",
    "Back Up…",
    "Backup is available once the vault is set up.",
    "Backup password",
    "Backup: %@ · This Mac: %@",
    "Choose File…",
    "Choose a backup made with Back Up Everything. Nothing changes before you confirm what to restore.",
    "Choose a backup made with Back Up Everything. You set a new master password for this Mac next.",
    "Clears the vault first. Not in the backup, deleted: %lld items. Paired apps stay.",
    "Connections, folders and shared credentials here that are not in the backup are deleted: %lld items. This cannot be undone.",
    "Encrypting and saving the backup…",
    "Folders",
    "Keep both (the backup’s copy is named “(backup)”)",
    "Keep the file and its password apart. To restore it, choose Restore from Backup… in the settings, or in the first-run window on a new Mac.",
    "Keep the item that is here",
    "L2TP and Cisco IPsec connections need their profile on this Mac. macOS asks you to approve each one.",
    "Made on %@ by MacVPN %@",
    "Merge",
    "Native profiles",
    "No file chosen",
    "Off",
    "On",
    "One encrypted file with every connection and its secrets, the folders, the shared credentials, the order and the app preferences. Paired apps are not included: they pair again after a restore.",
    "Open Backup",
    "Opened for approval",
    "Opening the backup…",
    "Overwrite it with the backup’s copy",
    "Preferences",
    "Reinstall %lld Native Profiles",
    "Repeat the backup password",
    "Replace Everything",
    "Replace Everything…",
    "Replace everything",
    "Replace everything keeps these acknowledgements. A merge drops them unless the same connection with the same config is already here; its editor then asks again.",
    "Replace everything?",
    "Restore from Backup",
    "Restore from Backup…",
    "Restoring…",
    "Shared credentials",
    "The backup cannot be opened. The password is wrong, or the file is damaged.",
    "The backup could not be made.",
    "The backup is protected with your master password. MacVPN checks it and does not keep a copy.",
    "The backup password must be at least %d characters long",
    "The backup was restored.",
    "The backup was saved as %@.",
    "The backup's folders would form a loop with the folders here. Nothing was changed.",
    "The backup’s preferences are not applied by themselves. Tick the ones to use on this Mac.",
    "The connection is no longer in the vault.",
    "The file is too large for a MacVPN backup.",
    "The master password is not correct.",
    "The restore failed. Nothing was changed.",
    "The restore keeps these acknowledgements. Restore only a backup you made yourself.",
    "The selected preferences were applied.",
    "The two passwords are not the same.",
    "The vault changed since the summary. Review the restore again.",
    "The vault is locked. Unlock it first.",
    "Then anyone who learns your master password can also open this file, wherever it is kept. A separate backup password keeps the two apart.",
    "These connections have acknowledged risky OpenVPN settings, such as scripts that run as root:",
    "This backup cannot be restored: it holds data MacVPN does not accept.",
    "This backup was made by a newer MacVPN. Update MacVPN to restore it.",
    "Tick it only if you use paired apps on this Mac. They pair again after a restore.",
    "Use Master Password",
    "Use a separate backup password",
    "Use my master password…",
    "Use your master password for this backup?",
    "Wait %d seconds before trying again.",
    "Weak",
    "When an item already exists:",
];

/// Swift texts that 1.2 replaced (the saved secrets moved from the Keychain into the vault): in the String Catalog,
/// no longer in the table.
const RETIRED_SWIFT_TEXTS: &[&str] = &[
    "%@ refers to these files. If you choose Use, their user name, password or private key password is stored in the Keychain for this connection. The files are never copied into the config.",
    "Also delete user data (connections and Keychain passwords)",
    "Authentication (stored in the Keychain)",
    "Stored in the MacVPN keychain and passed to macOS when connecting. Needed when macOS cannot read the shared secret on its own (\"incorrect user shared secret\").",
    "The export INCLUDES the private keys and credentials from the config (%@). Passwords and the PSK stored in the Keychain are not included.",
    "The password is stored in the Keychain. Use user@domain instead of DOMAIN\\user.",
    "The private key password from %@ is stored in the Keychain.",
    "The username and password from %@ are stored in the Keychain; the file is not copied into the config.",
    "~/Library/Application Support/MacVPN and the MacVPN Keychain items",
];

/// The app part of `strings.json` equals the String Catalog (`Localizable.xcstrings`): every key, translated.
/// (`legacy/swift`, removed after 1.0.0 together with this test.)
#[test]
fn table_matches_the_app_catalog() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("legacy/swift/Sources/MacVPN/Resources/Localizable.xcstrings")).unwrap(),
    )
    .unwrap();
    assert_eq!(catalog["sourceLanguage"], "en");
    let strings = catalog["strings"].as_object().unwrap();
    assert!(strings.len() > 100);
    let app: Vec<_> = l10n::table().into_iter().filter(|e| e.scope == "app").collect();
    // UI texts new in the Rust app (no Swift counterpart): listed here, so a Swift text cannot go missing unnoticed.
    let rust_only: Vec<_> = app.iter().filter(|e| RUST_ONLY_APP_TEXTS.contains(&e.key.as_str())).collect();
    assert_eq!(rust_only.len(), RUST_ONLY_APP_TEXTS.len(), "a Rust-only text is missing from the table");
    for retired in RETIRED_SWIFT_TEXTS {
        assert!(strings.contains_key(*retired), "not a Swift text: {retired}");
        assert!(!app.iter().any(|e| e.key == *retired), "still in the table: {retired}");
    }
    assert_eq!(app.len() + RETIRED_SWIFT_TEXTS.len(), strings.len() + RUST_ONLY_APP_TEXTS.len());
    for e in app.into_iter().filter(|e| !RUST_ONLY_APP_TEXTS.contains(&e.key.as_str())) {
        let unit = &strings[&e.key]["localizations"]["hu"]["stringUnit"];
        assert_eq!(unit["state"], "translated", "{}", e.key);
        assert_eq!(unit["value"].as_str(), Some(e.hu.as_str()), "{}", e.key);
    }
}

#[test]
fn positional_and_long_specifiers() {
    assert_eq!(l10n::tr_in(AppLanguage::En, "%2$@ and %1$@", &[Arg::Str("a"), Arg::Str("b")]), "b and a");
    assert_eq!(l10n::tr_in(AppLanguage::En, "%lld items, 100%%", &[Arg::Int(3)]), "3 items, 100%");
}

/// Every `tr("…")` key used in the Rust core sources has a Hungarian translation.
#[test]
fn every_core_call_site_has_a_translation() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let call = Regex::new(r#"\btr\(\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let mut found = 0;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for c in call.captures_iter(&source) {
                let key = c[1].replace("\\\"", "\"").replace("\\\\", "\\");
                found += 1;
                assert!(l10n::hungarian(&key).is_some(), "no Hungarian translation ({}): {key}", path.display());
            }
        }
    }
    assert!(found >= 50, "{found}");
}
