//! The folder and connection colour palette (spec 3): 12 colours plus "none" (`Option::None`). The UI defines the
//! matching `--folder-<name>` tokens for light and dark mode.
//!
//! Stored as the lower-case name in the `color` columns; these names are stable storage ids and never change. A
//! stored name this build does not know reads as no colour.

/// One of the 12 palette colours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FolderColor {
    Red,
    Orange,
    Amber,
    Yellow,
    Lime,
    Green,
    Teal,
    Cyan,
    Blue,
    Indigo,
    Purple,
    Pink,
}

impl FolderColor {
    /// The palette in display order.
    pub const ALL: [FolderColor; 12] = [
        FolderColor::Red,
        FolderColor::Orange,
        FolderColor::Amber,
        FolderColor::Yellow,
        FolderColor::Lime,
        FolderColor::Green,
        FolderColor::Teal,
        FolderColor::Cyan,
        FolderColor::Blue,
        FolderColor::Indigo,
        FolderColor::Purple,
        FolderColor::Pink,
    ];

    /// The stable storage id (also the UI token suffix).
    pub fn as_str(self) -> &'static str {
        match self {
            FolderColor::Red => "red",
            FolderColor::Orange => "orange",
            FolderColor::Amber => "amber",
            FolderColor::Yellow => "yellow",
            FolderColor::Lime => "lime",
            FolderColor::Green => "green",
            FolderColor::Teal => "teal",
            FolderColor::Cyan => "cyan",
            FolderColor::Blue => "blue",
            FolderColor::Indigo => "indigo",
            FolderColor::Purple => "purple",
            FolderColor::Pink => "pink",
        }
    }

    /// The colour of a storage id (exact, lower case); `None` for anything else.
    pub fn parse(s: &str) -> Option<FolderColor> {
        FolderColor::ALL.into_iter().find(|c| c.as_str() == s)
    }
}
