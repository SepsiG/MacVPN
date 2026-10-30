//! The download mark on Linux: the `user.xdg.origin.url` extended attribute browsers set on downloads. Fail closed:
//! only "absent", "the file system has no user xattrs" and "no such file" are unmarked.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrRead {
    Present,
    /// `ENODATA`.
    Absent,
    /// `ENOTSUP`: no mark can exist there.
    NotSupported,
    /// `ENOENT`.
    NoFile,
    /// Any other errno.
    Error(i32),
}

pub fn is_marked(read: XattrRead) -> bool {
    matches!(read, XattrRead::Present | XattrRead::Error(_))
}
