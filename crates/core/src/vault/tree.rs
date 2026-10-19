//! The folder tree (spec 3): nesting to any depth, cycle rejection, colour inheritance, export paths and the
//! display order. Pure: built from the stored [`FolderNode`]s, no database access.
//!
//! - **Colour:** an item's effective colour is its own, else the nearest ancestor folder's, else none; a folder
//!   without its own colour inherits from its parent the same way. [`ColorSource`] says where it came from, so the
//!   UI can mark an explicit override and offer "Use folder colour".
//! - **Order** ([`order_tree`]): per folder (and the root) the subfolders first, by `position` (then name), then
//!   the items in [`ConnectionRanking::order`] (pinned in pin order, then by usage score, then by name). Items
//!   have no manual position: dragging an item only changes its folder (plan B, "Resolved").

use super::color::FolderColor;
use crate::collation;
use crate::date::Date;
use crate::mfa;
use crate::ranking::ConnectionRanking;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use uuid::Uuid;

/// The longest folder name, in characters (grapheme clusters).
pub const MAX_FOLDER_NAME_CHARACTERS: usize = crate::importer::MAX_META_NAME_CHARACTERS;

/// One stored folder (`folders` row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderNode {
    pub id: Uuid,
    /// `None`: at the root.
    pub parent: Option<Uuid>,
    pub name: String,
    /// The folder's own colour; `None` inherits.
    pub color: Option<FolderColor>,
    /// The manual order among its siblings.
    pub position: i64,
    /// Collapsed in the menu (persisted).
    pub collapsed: bool,
}

/// Where an effective colour comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSource {
    /// The item's or folder's own colour.
    Own,
    /// Inherited from this ancestor folder (the nearest one with a colour).
    Inherited(Uuid),
    /// No colour anywhere up the chain.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    /// A folder would become its own ancestor.
    Cycle,
    UnknownFolder(Uuid),
    /// A folder name that is empty, too long or has a control character.
    InvalidName,
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::Cycle => f.write_str("a folder cannot be moved into itself or one of its subfolders"),
            TreeError::UnknownFolder(id) => write!(f, "unknown folder {id}"),
            TreeError::InvalidName => write!(
                f,
                "a folder name must have 1 to {MAX_FOLDER_NAME_CHARACTERS} characters and no control characters"
            ),
        }
    }
}

impl std::error::Error for TreeError {}

/// The folders, indexed by id and by parent. Always acyclic, and every parent exists.
#[derive(Debug, Clone, Default)]
pub struct FolderTree {
    nodes: HashMap<Uuid, FolderNode>,
    /// Children per parent (`None`: the root), in display order.
    children: HashMap<Option<Uuid>, Vec<Uuid>>,
}

impl FolderTree {
    /// Rejects a cycle ([`TreeError::Cycle`], a folder that is its own parent included) and a parent that is not
    /// in the list ([`TreeError::UnknownFolder`]). A repeated id keeps the last node.
    pub fn new(folders: Vec<FolderNode>) -> Result<FolderTree, TreeError> {
        let nodes: HashMap<Uuid, FolderNode> = folders.into_iter().map(|f| (f.id, f)).collect();
        for node in nodes.values() {
            if let Some(parent) = node.parent
                && !nodes.contains_key(&parent)
            {
                return Err(TreeError::UnknownFolder(parent));
            }
        }
        // Every chain must reach the root within `nodes.len()` steps.
        for node in nodes.values() {
            let mut current = node.parent;
            let mut steps = 0;
            while let Some(id) = current {
                if id == node.id || steps > nodes.len() {
                    return Err(TreeError::Cycle);
                }
                steps += 1;
                current = nodes[&id].parent;
            }
        }
        let mut children: HashMap<Option<Uuid>, Vec<Uuid>> = HashMap::new();
        for node in nodes.values() {
            children.entry(node.parent).or_default().push(node.id);
        }
        for list in children.values_mut() {
            list.sort_by(|a, b| sibling_order(&nodes[a], &nodes[b]));
        }
        Ok(FolderTree { nodes, children })
    }

    pub fn get(&self, folder: Uuid) -> Option<&FolderNode> {
        self.nodes.get(&folder)
    }

    pub fn contains(&self, folder: Uuid) -> bool {
        self.nodes.contains_key(&folder)
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Every folder, in no particular order.
    pub fn nodes(&self) -> impl Iterator<Item = &FolderNode> {
        self.nodes.values()
    }

    /// The direct subfolders of `parent` (`None`: the root) in display order: by `position`, then name, then id.
    pub fn children(&self, parent: Option<Uuid>) -> &[Uuid] {
        self.children.get(&parent).map_or(&[], Vec::as_slice)
    }

    /// Whether `folder` may move under `new_parent` (`None`: the root): both must exist, and the new parent must
    /// not be the folder itself or one of its descendants.
    pub fn check_move(&self, folder: Uuid, new_parent: Option<Uuid>) -> Result<(), TreeError> {
        if !self.contains(folder) {
            return Err(TreeError::UnknownFolder(folder));
        }
        let Some(target) = new_parent else { return Ok(()) };
        if !self.contains(target) {
            return Err(TreeError::UnknownFolder(target));
        }
        if self.ancestors_and_self(target).any(|a| a == folder) {
            return Err(TreeError::Cycle);
        }
        Ok(())
    }

    /// A folder's effective colour: its own, else the nearest ancestor's. An unknown folder has none.
    pub fn folder_color(&self, folder: Uuid) -> (Option<FolderColor>, ColorSource) {
        match self.get(folder).and_then(|n| n.color) {
            Some(color) => (Some(color), ColorSource::Own),
            None => self.inherited(self.get(folder).and_then(|n| n.parent)),
        }
    }

    /// An item's effective colour: `own`, else the nearest coloured folder from `folder` up.
    pub fn item_color(&self, own: Option<FolderColor>, folder: Option<Uuid>) -> (Option<FolderColor>, ColorSource) {
        match own {
            Some(color) => (Some(color), ColorSource::Own),
            None => self.inherited(folder),
        }
    }

    /// The folder names from the root down to `folder` (the export path); empty for an unknown folder.
    pub fn path(&self, folder: Uuid) -> Vec<String> {
        let mut names: Vec<String> = self.ancestors_and_self(folder).map(|id| self.nodes[&id].name.clone()).collect();
        names.reverse();
        names
    }

    /// Every folder below `folder` (not itself), depth first in display order.
    pub fn descendants(&self, folder: Uuid) -> Vec<Uuid> {
        let mut out = Vec::new();
        let mut stack: Vec<Uuid> = self.children(Some(folder)).iter().rev().copied().collect();
        while let Some(id) = stack.pop() {
            out.push(id);
            stack.extend(self.children(Some(id)).iter().rev());
        }
        out
    }

    /// The number of ancestors: 0 for a folder at the root (and for an unknown folder).
    pub fn depth(&self, folder: Uuid) -> usize {
        self.ancestors_and_self(folder).count().saturating_sub(1)
    }

    /// `folder`, its parent, … up to the root folder. Empty for an unknown folder. Finite: the tree is acyclic.
    fn ancestors_and_self(&self, folder: Uuid) -> impl Iterator<Item = Uuid> + '_ {
        let start = self.contains(folder).then_some(folder);
        std::iter::successors(start, |id| self.nodes[id].parent)
    }

    /// The nearest coloured folder from `folder` up.
    fn inherited(&self, folder: Option<Uuid>) -> (Option<FolderColor>, ColorSource) {
        let Some(folder) = folder else { return (None, ColorSource::None) };
        self.ancestors_and_self(folder)
            .find_map(|id| self.nodes[&id].color.map(|c| (Some(c), ColorSource::Inherited(id))))
            .unwrap_or((None, ColorSource::None))
    }
}

/// Siblings: by `position`, then by name (case-insensitive, by the language's rules), then by id (stable).
fn sibling_order(a: &FolderNode, b: &FolderNode) -> Ordering {
    a.position
        .cmp(&b.position)
        .then_with(|| collation::localized_case_insensitive_compare(&a.name, &b.name))
        .then_with(|| a.id.cmp(&b.id))
}

/// One row of the ordered tree. `depth` is the real nesting depth (a folder at the root and an item at the root are
/// 0, an item in a root folder is 1); the UI caps the indentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeEntry {
    Folder { id: Uuid, depth: usize },
    Item { key: String, depth: usize },
}

/// Per folder (and the root): subfolders by `position` (then name), then the items in
/// `ConnectionRanking::order` (pinned in pin order, then score, then name).
///
/// `items` are `(key, folder)` pairs, the key being the ranking key (a managed connection's UUID string or a system
/// VPN's service ID). An item whose folder is not in the tree shows at the root. Every folder and item is listed,
/// collapsed folders included: hiding the contents of a collapsed folder is up to the view.
pub fn order_tree(
    tree: &FolderTree,
    items: &[(String, Option<Uuid>)],
    ranking: &ConnectionRanking,
    now: Date,
    name: impl Fn(&str) -> String,
) -> Vec<TreeEntry> {
    let mut by_folder: HashMap<Option<Uuid>, Vec<String>> = HashMap::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for (key, folder) in items {
        if seen.insert(key.as_str()) {
            let folder = folder.filter(|f| tree.contains(*f));
            by_folder.entry(folder).or_default().push(key.clone());
        }
    }
    let mut out = Vec::with_capacity(tree.nodes.len() + seen.len());
    // Depth-first with an explicit stack: (folder, depth of its contents). A folder's subfolders are expanded
    // before its items are emitted, so each level is emitted when it is popped the second time.
    enum Step {
        Enter(Option<Uuid>, usize),
        Items(Option<Uuid>, usize),
    }
    let mut stack = vec![Step::Enter(None, 0)];
    while let Some(step) = stack.pop() {
        match step {
            Step::Enter(folder, depth) => {
                if let Some(id) = folder {
                    out.push(TreeEntry::Folder { id, depth: depth - 1 });
                }
                stack.push(Step::Items(folder, depth));
                for child in tree.children(folder).iter().rev() {
                    stack.push(Step::Enter(Some(*child), depth + 1));
                }
            }
            Step::Items(folder, depth) => {
                if let Some(keys) = by_folder.get(&folder) {
                    for key in ranking.order(keys, now, &name) {
                        out.push(TreeEntry::Item { key, depth });
                    }
                }
            }
        }
    }
    out
}

/// A folder name as stored: format characters (bidi controls, zero width) dropped, trimmed, 1 to
/// [`MAX_FOLDER_NAME_CHARACTERS`] characters, no control character (C0, DEL, C1, U+2028/U+2029; the same set as
/// the MFA code check).
pub fn validate_folder_name(name: &str) -> Result<String, TreeError> {
    mfa::clean_name(name, MAX_FOLDER_NAME_CHARACTERS).ok_or(TreeError::InvalidName)
}
