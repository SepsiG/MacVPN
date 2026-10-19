//! Secrets from stdin (`username=`, `password=`, `psk=`, `keypass=`, `otp=`, `challenge=packed`).
//!
//! They stay in this process's memory (zeroed on drop): never in an argument list (except the documented sstpc
//! `--password`), never in an environment, never in the log (every non-empty one is masked).

use crate::mask::Masker;
use std::io::Read;
use zeroize::Zeroizing;

/// The longest stdin accepted; the app sends a few hundred bytes.
const STDIN_MAX: u64 = 64 * 1024;

#[derive(Default)]
pub struct Secrets {
    pub user: Zeroizing<Vec<u8>>,
    pub pass: Zeroizing<Vec<u8>>,
    pub psk: Zeroizing<Vec<u8>>,
    pub keypass: Zeroizing<Vec<u8>>,
    /// The MFA code: only for masking (it is already part of the password).
    pub otp: Zeroizing<Vec<u8>>,
    /// OpenVPN static challenge: the password is already in SCRV1 / concat form.
    pub packed: bool,
}

impl Secrets {
    /// `read_secrets`: nothing from a terminal; otherwise every complete line (`read -r` drops an unterminated
    /// last line).
    pub fn read_stdin() -> Secrets {
        if crate::sys::stdin_is_tty() {
            return Secrets::default();
        }
        let mut data = Zeroizing::new(Vec::new());
        let _ = std::io::stdin().lock().take(STDIN_MAX).read_to_end(&mut data);
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Secrets {
        let mut s = Secrets::default();
        let complete = match data.iter().rposition(|&b| b == b'\n') {
            Some(p) => &data[..p],
            None => return s,
        };
        for raw in complete.split(|&b| b == b'\n') {
            // bash `read` drops NUL bytes.
            let line: Zeroizing<Vec<u8>> = Zeroizing::new(raw.iter().copied().filter(|&b| b != 0).collect());
            let value = |prefix: &[u8]| Zeroizing::new(line[prefix.len()..].to_vec());
            if line.starts_with(b"username=") {
                s.user = value(b"username=");
            } else if line.starts_with(b"password=") {
                s.pass = value(b"password=");
            } else if line.starts_with(b"psk=") {
                s.psk = value(b"psk=");
            } else if line.starts_with(b"keypass=") {
                s.keypass = value(b"keypass=");
            } else if line.starts_with(b"otp=") {
                s.otp = value(b"otp=");
            } else if line.as_slice() == b"challenge=packed" {
                s.packed = true;
            }
        }
        s
    }

    /// The bash `mask`: password, PSK, key password and code.
    pub fn masker(&self) -> Masker {
        Masker::new([self.pass.as_slice(), self.psk.as_slice(), self.keypass.as_slice(), self.otp.as_slice()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_lines_only() {
        let s =
            Secrets::parse(b"username=bob\npassword=a=b\npsk=k\nkeypass=kp\notp=123\nchallenge=packed\nx=y\npassword");
        assert_eq!(s.user.as_slice(), b"bob");
        assert_eq!(s.pass.as_slice(), b"a=b");
        assert_eq!(s.psk.as_slice(), b"k");
        assert_eq!(s.keypass.as_slice(), b"kp");
        assert_eq!(s.otp.as_slice(), b"123");
        assert!(s.packed);
        let t = Secrets::parse(b"password=unterminated");
        assert!(t.pass.is_empty());
        let u = Secrets::parse(b"password=1\npassword=2\n");
        assert_eq!(u.pass.as_slice(), b"2");
    }

    #[test]
    fn masks_all_but_the_user_name() {
        let s = Secrets::parse(b"username=bobby\npassword=pw1pw\npsk=psk99\nkeypass=kp77k\notp=135790\n");
        assert_eq!(s.masker().line(b"bobby pw1pw psk99 kp77k 135790"), b"bobby *** *** *** ***".to_vec());
    }
}
