//! Absolute security descriptors with an explicit owner and a protected DACL.

use crate::sid::Sid;
use crate::util::check;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_FLAGS, ACL, ACL_REVISION, AddAccessAllowedAceEx, AddAccessDeniedAceEx, InitializeAcl,
    InitializeSecurityDescriptor, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
};

/// `SECURITY_DESCRIPTOR_REVISION` (winnt.h); defined here so the crate needs no `Win32_System_SystemServices`.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

pub(crate) enum Ace<'a> {
    Allow(&'a Sid, u32),
    Deny(&'a Sid, u32),
}

/// An ACL in a u32-aligned buffer.
pub(crate) struct Acl(Vec<u32>);

impl Acl {
    /// The ACEs in this order, each with `flags`.
    pub(crate) fn new(aces: &[Ace<'_>], flags: ACE_FLAGS) -> io::Result<Acl> {
        // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE have the same layout: the SID starts at `SidStart`.
        let ace_size = |sid: &Sid| size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid.byte_len();
        let size = size_of::<ACL>()
            + aces
                .iter()
                .map(|a| match a {
                    Ace::Allow(s, _) | Ace::Deny(s, _) => ace_size(s),
                })
                .sum::<usize>();
        let mut buf = vec![0u32; size.div_ceil(4)];
        let len = u32::try_from(buf.len() * 4)
            .ok()
            .filter(|&l| l <= u32::from(u16::MAX))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "an ACL larger than 64 KiB"))?;
        let acl = buf.as_mut_ptr() as *mut ACL;
        // SAFETY: `buf` is u32-aligned and `len` bytes long, enough for the header and every ACE added below
        // (AddAccess*AceEx fail rather than write past the size InitializeAcl recorded); the SIDs are valid.
        unsafe {
            check(InitializeAcl(acl, len, ACL_REVISION))?;
            for ace in aces {
                match ace {
                    Ace::Allow(sid, mask) => {
                        check(AddAccessAllowedAceEx(acl, ACL_REVISION, flags, *mask, sid.as_psid()))?
                    }
                    Ace::Deny(sid, mask) => {
                        check(AddAccessDeniedAceEx(acl, ACL_REVISION, flags, *mask, sid.as_psid()))?
                    }
                }
            }
        }
        Ok(Acl(buf))
    }

    pub(crate) fn as_ptr(&self) -> *const ACL {
        self.0.as_ptr().cast()
    }
}

/// An absolute security descriptor: owner + protected DACL, and `SECURITY_ATTRIBUTES` pointing to it. Owns
/// everything it points to; every pointer targets heap memory owned by the descriptor, so the pointers stay valid
/// as long as it lives (moving the `Box` does not move the heap data).
pub(crate) struct Descriptor {
    sd: Box<SECURITY_DESCRIPTOR>,
    owner: Sid,
    acl: Acl,
    attributes: SECURITY_ATTRIBUTES,
}

impl Descriptor {
    pub(crate) fn new(owner: Sid, acl: Acl) -> io::Result<Box<Descriptor>> {
        // SAFETY: SECURITY_DESCRIPTOR is plain data (integers and raw pointers); all zero is a valid value, and
        // InitializeSecurityDescriptor sets it up below.
        let sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let mut d = Box::new(Descriptor {
            sd,
            owner,
            acl,
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 0,
            },
        });
        let psd = (&mut *d.sd as *mut SECURITY_DESCRIPTOR).cast::<c_void>();
        // SAFETY: `psd` points to the boxed descriptor; the owner SID and the ACL it records are heap buffers owned
        // by the same Descriptor, so the recorded pointers stay valid as long as it does.
        unsafe {
            check(InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION))?;
            check(SetSecurityDescriptorOwner(psd, d.owner.as_psid(), 0))?;
            check(SetSecurityDescriptorDacl(psd, 1, d.acl.as_ptr(), 0))?;
            check(SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED))?;
        }
        d.attributes.lpSecurityDescriptor = psd;
        Ok(d)
    }

    /// For `CreateFileW`, `CreateDirectoryW`, `CreateNamedPipeW`; valid while `self` lives.
    pub(crate) fn attributes(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attributes
    }

    /// The owner it records (tests).
    #[cfg(test)]
    pub(crate) fn owner(&self) -> &Sid {
        &self.owner
    }

    /// The DACL, for `SetSecurityInfo`; valid while `self` lives.
    pub(crate) fn acl(&self) -> *const ACL {
        self.acl.as_ptr()
    }
}
