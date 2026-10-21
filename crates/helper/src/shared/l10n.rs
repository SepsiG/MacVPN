//! The helper's messages: the keys are the English texts of the `strings.json` table (scope `mvpn`).

use macvpn_core::l10n::{self, Arg};

/// The localized text of `key` (an English message of the `strings.json` table), `%@` filled in order.
pub fn tr(key: &str, args: &[&str]) -> String {
    let args: Vec<Arg<'_>> = args.iter().map(|a| Arg::Str(a)).collect();
    l10n::tr(key, &args)
}
