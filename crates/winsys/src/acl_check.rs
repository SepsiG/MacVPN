//! "Only administrators can change this file": what the WinVPN Service requires of `openvpn.exe` before it runs it
//! as SYSTEM.
//!
//! The file and every ancestor directory up to the volume root must be owned by SYSTEM, Administrators or
//! TrustedInstaller, and no ACE of their DACLs may grant anyone else a right that changes them:
//! - on the file and on the directory that contains it, any of write / add file, append / add subdirectory,
//!   delete child, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, `GENERIC_ALL` (the directory holds the
//!   DLLs the program loads first, so nobody else may add a file there);
//! - on the directories above it, the same except append / add subdirectory: a new folder next to an existing one
//!   replaces nothing, and every volume root grants it to Authenticated Users (`C:\` has `(AD)`).
//!
//! Inherit-only ACEs are skipped: they grant nothing on the object that carries them, only on objects created in
//! it later, and every object on the path is checked with its own DACL (where what it inherited is stored). Deny
//! ACEs are skipped (they only take rights away). An ACE of any other type (an object or callback ACE, whose
//! grantee is not parsed) that grants one of the rights is a refusal, as is a null DACL. The rule is the plan's
//! (Task 4) with two changes the real `C:\` needs: all inherit-only ACEs are skipped (not only CREATOR OWNER's: `C:\`
//! carries `Authenticated Users:(OI)(CI)(IO)(M)`), and add subdirectory is allowed above the containing directory.
//!
//! Reparse points are not followed: a symbolic link, junction or mount point (a name surrogate) or an app execution
//! alias anywhere on the path is a refusal; other reparse points (WOF-compressed and deduplicated files) are the
//! file itself and are checked as such. Only a plain absolute path on a drive letter is accepted (no UNC: another
//! machine decides what a share contains). Any read failure is an error, which the caller treats as "not
//! admin-only" (fail closed).

use crate::file::{self, AceEntry};
use crate::sid::Sid;
use crate::util::plain_absolute;
use std::io;
use std::path::Path;

const FILE_WRITE_DATA: u32 = 0x0002; // FILE_ADD_FILE on a directory
const FILE_APPEND_DATA: u32 = 0x0004; // FILE_ADD_SUBDIRECTORY on a directory
const FILE_DELETE_CHILD: u32 = 0x0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// The rights nobody but the trusted owners may have on the file and its directory.
const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
/// The same for the directories above them.
const ANCESTOR_WRITE_RIGHTS: u32 = WRITE_RIGHTS & !FILE_APPEND_DATA;

/// `INHERIT_ONLY_ACE` (winnt.h).
const INHERIT_ONLY_ACE: u8 = 0x08;
/// `IO_REPARSE_TAG_APPEXECLINK` (winnt.h): an app execution alias, which starts another program.
const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001B;

const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const ADMINISTRATORS: &str = "S-1-5-32-544";

/// SYSTEM, Administrators and TrustedInstaller.
fn trusted() -> io::Result<[Sid; 3]> {
    Ok([Sid::local_system(), Sid::parse(ADMINISTRATORS)?, Sid::parse(TRUSTED_INSTALLER)?])
}

/// Whether only SYSTEM, Administrators and TrustedInstaller can change the file at `path` (see the module
/// documentation). `Err` when the path is not a plain absolute path or anything on it cannot be read.
pub fn is_admin_only(path: &Path) -> io::Result<bool> {
    plain_absolute(path)?;
    let trusted = trusted()?;
    for (depth, p) in path.ancestors().enumerate() {
        let f = file::open_metadata(p, false)?;
        if let Some(tag) = file::info(&f)?.reparse_tag
            && (file::is_name_surrogate(tag) || tag == IO_REPARSE_TAG_APPEXECLINK)
        {
            return Ok(false);
        }
        let (owner, aces) = file::owner_and_aces(&f)?;
        let rights = if depth <= 1 { WRITE_RIGHTS } else { ANCESTOR_WRITE_RIGHTS };
        if !only_trusted_can_write(&owner, aces.as_deref(), rights, &trusted) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The rule for one object: a trusted owner, a DACL, and no ACE that applies to the object and grants any of
/// `rights` to anyone but the trusted SIDs.
fn only_trusted_can_write(owner: &Sid, aces: Option<&[AceEntry]>, rights: u32, trusted: &[Sid]) -> bool {
    if !trusted.contains(owner) {
        return false;
    }
    let Some(aces) = aces else { return false };
    aces.iter().all(|a| {
        if a.flags & INHERIT_ONLY_ACE != 0 || a.mask & rights == 0 {
            return true;
        }
        match (&a.sid, a.allow) {
            (Some(sid), true) => trusted.contains(sid),
            // A deny ACE (allow and deny ACEs are the only ones whose SID is parsed).
            (Some(_), false) => true,
            // Any other type: its grantee is unknown.
            (None, _) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(allow: bool, sid: Option<&Sid>, mask: u32, flags: u8) -> AceEntry {
        AceEntry { allow, sid: sid.cloned(), mask, flags }
    }

    #[test]
    fn the_rule_allows_writes_only_to_trusted_sids() {
        let trusted = trusted().unwrap();
        let [system, admins, ti] = trusted.clone();
        let (users, auth) = (Sid::builtin_users(), Sid::parse("S-1-5-11").unwrap());
        let creator_owner = Sid::parse("S-1-3-0").unwrap();
        const RX: u32 = 0x0012_00A9;
        const MODIFY: u32 = 0x0013_01BF;
        // System32 as it is on Windows 11.
        let system32 = [
            ace(true, Some(&ti), 0x001F_01FF, 0),
            ace(true, Some(&ti), GENERIC_ALL, 0x02 | INHERIT_ONLY_ACE),
            ace(true, Some(&system), MODIFY, 0),
            ace(true, Some(&admins), MODIFY, 0),
            ace(true, Some(&users), RX, 0),
            ace(true, Some(&creator_owner), GENERIC_ALL, 0x03 | INHERIT_ONLY_ACE),
        ];
        let check =
            |owner: &Sid, aces: &[AceEntry], rights| only_trusted_can_write(owner, Some(aces), rights, &trusted);
        assert!(check(&ti, &system32, WRITE_RIGHTS));
        assert!(check(&admins, &system32, WRITE_RIGHTS));
        // An untrusted owner (implicit WRITE_DAC) or a null DACL.
        assert!(!check(&users, &system32, WRITE_RIGHTS));
        assert!(!only_trusted_can_write(&system, None, WRITE_RIGHTS, &trusted));
        // `C:\`: add subdirectory for Authenticated Users is fine above the containing directory only; an
        // inherit-only modify ACE grants nothing on the root itself.
        let root = [
            ace(true, Some(&admins), 0x001F_01FF, 0x03),
            ace(true, Some(&auth), MODIFY, 0x03 | INHERIT_ONLY_ACE),
            ace(true, Some(&auth), FILE_APPEND_DATA, 0),
        ];
        assert!(check(&ti, &root, ANCESTOR_WRITE_RIGHTS));
        assert!(!check(&ti, &root, WRITE_RIGHTS));
        // The same modify ACE once inherited (no longer inherit-only) by a folder created in `C:\`.
        let inherited = [ace(true, Some(&admins), 0x001F_01FF, 0x10), ace(true, Some(&auth), MODIFY, 0x13)];
        assert!(!check(&admins, &inherited, ANCESTOR_WRITE_RIGHTS));
        // Each write right on its own, for an untrusted SID.
        for right in [FILE_WRITE_DATA, FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL] {
            assert!(!check(&system, &[ace(true, Some(&users), right, 0)], ANCESTOR_WRITE_RIGHTS), "{right:#x}");
        }
        // A deny ACE is skipped; an ACE of an unparsed type that grants a write right is not.
        assert!(check(&system, &[ace(false, Some(&users), GENERIC_ALL, 0)], WRITE_RIGHTS));
        assert!(!check(&system, &[ace(false, None, WRITE_DAC, 0)], WRITE_RIGHTS));
        assert!(check(&system, &[ace(false, None, RX, 0)], WRITE_RIGHTS));
        // Write attributes and extended attributes do not change the content.
        assert!(check(&system, &[ace(true, Some(&users), RX | 0x0110, 0)], WRITE_RIGHTS));
    }
}
