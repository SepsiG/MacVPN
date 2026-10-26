// The Windows parts of the native VPN editors and the failure banner (WinVPN 2c): which text and button each
// platform flag selects. Without the flags (macOS) every function answers the macOS text, so the macOS UI is
// unchanged.
import type { AdminAction, CaConfirmView, EditorPlatformView } from '../api';

/// The UI's text lookup (`tr` of `l10n.svelte`): the keys below are its literal keys.
export type Tr = (key: string, ...args: (string | number)[]) => string;

/// The L2TP / Cisco form's button: "Save" where saving writes the Windows VPN entry at once, else macOS' "Save and
/// Install Profile".
export function nativeSaveLabel(platform: EditorPlatformView | undefined, tr: Tr): string {
  return platform?.noInstallStep ? tr('Save') : tr('Save and Install Profile');
}

/// The L2TP / Cisco form's footer after a save: no "approve the profile" where there is nothing to approve.
export function nativeSavedText(platform: EditorPlatformView | undefined, tr: Tr): string {
  return platform?.noInstallStep ? tr('Saved') : tr('Profile opened, approve it in System Settings.');
}

/// The L2TP / Cisco form's note on what saving does.
export function nativeSaveNote(platform: EditorPlatformView | undefined, tr: Tr): string {
  return platform?.noInstallStep
    ? tr('Saving writes the Windows VPN entry of this connection at once; there is nothing to approve. The password is not in it: MacVPN passes it when connecting.')
    : tr(
        'Saving creates and opens a configuration profile. Approve it in System Settings → General → Device Management (Profiles). After each change it has to be approved again. The password is not in the profile: MacVPN passes it when connecting (from System Settings, macOS asks for it).',
      );
}

/// The failure banner's button for the administrator step the error names.
export function adminActionLabel(action: AdminAction, tr: Tr): string {
  return action === 'allow-l2tp-behind-nat' ? tr('Allow L2TP Behind NAT…') : tr('Trust This CA in Windows…');
}

/// A Unix time as a date of the UI language.
export function caDate(seconds: number, language: string): string {
  return new Date(seconds * 1000).toLocaleDateString(language === 'hu' ? 'hu-HU' : 'en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

/// The confirmation's text: the CA's subject, validity and SHA-256 fingerprint, then the warning.
export function caConfirmMessage(view: CaConfirmView, language: string, tr: Tr): string {
  return [
    tr('Subject: %@', view.subject),
    tr('Valid from %@ to %@', caDate(view.notBefore, language), caDate(view.notAfter, language)),
    tr('SHA-256 fingerprint: %@', view.sha256),
    view.warning,
  ].join('\n');
}
