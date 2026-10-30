//! Which notification id shows which identifier, and its user info (in memory: a click after a restart opens
//! nothing, as on Windows).

use std::collections::{BTreeMap, HashMap};

#[derive(Default)]
pub struct Book {
    by_identifier: HashMap<String, u32>,
    info: HashMap<u32, (String, BTreeMap<String, String>)>,
}

impl Book {
    /// The id a new post of `identifier` replaces (0: none).
    pub fn replaces(&self, identifier: &str) -> u32 {
        self.by_identifier.get(identifier).copied().unwrap_or(0)
    }

    pub fn posted(&mut self, identifier: &str, id: u32, user_info: (&str, &str)) {
        if let Some(old) = self.by_identifier.insert(identifier.to_string(), id) {
            self.info.remove(&old);
        }
        self.info
            .insert(id, (identifier.to_string(), BTreeMap::from([(user_info.0.to_string(), user_info.1.to_string())])));
    }

    /// The user info of the notification `id`, if it is still shown.
    pub fn clicked(&self, id: u32) -> Option<BTreeMap<String, String>> {
        self.info.get(&id).map(|(_, i)| i.clone())
    }

    pub fn id_of(&self, identifier: &str) -> Option<u32> {
        self.by_identifier.get(identifier).copied()
    }

    pub fn closed(&mut self, id: u32) {
        if let Some((identifier, _)) = self.info.remove(&id)
            && self.by_identifier.get(&identifier) == Some(&id)
        {
            self.by_identifier.remove(&identifier);
        }
    }
}
