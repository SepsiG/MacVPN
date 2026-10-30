//! Launch at login: `$XDG_CONFIG_HOME/autostart/linvpn.desktop` (the XDG Autostart spec; GNOME reads
//! `X-GNOME-Autostart-enabled`). On: our file exists and neither `Hidden=true` nor `X-GNOME-Autostart-enabled=false`
//! is in its `[Desktop Entry]` group. A file another tool turned off counts as off, with a note.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    On,
    Off,
    TurnedOffElsewhere,
}

pub fn desktop_file() -> String {
    "[Desktop Entry]\nType=Application\nName=LinVPN\nExec=/usr/bin/linvpn\nIcon=linvpn\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n".to_string()
}

pub fn state_of(text: Option<&str>) -> State {
    let Some(text) = text else { return State::Off };
    let mut in_entry = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if in_entry && (line == "Hidden=true" || line == "X-GNOME-Autostart-enabled=false") {
            return State::TurnedOffElsewhere;
        }
    }
    State::On
}
