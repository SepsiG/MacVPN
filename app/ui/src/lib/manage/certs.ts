// The editor's "Certificates" section (pure, tested by node --test). The backend reads the certificates and their
// validity (`EditorView.certificates`); this only labels and formats them. Everything here is public (no key).
import type { CertificateView } from '../api';
import { tr } from '../l10n.svelte';

/// The certificate's title by what it is for.
export function roleTitle(role: CertificateView['role']): string {
  switch (role) {
    case 'client':
      return tr('Client certificate');
    case 'ca':
      return tr('CA certificate');
    case 'chain':
      return tr('Intermediate certificate');
  }
}

/// A validity date (Unix seconds) in the app's language, local time.
export function certificateDate(seconds: number, language: string): string {
  return new Date(seconds * 1000).toLocaleDateString(language === 'hu' ? 'hu-HU' : 'en-US', { dateStyle: 'medium' });
}

/// The note's colour: red when expired or not valid yet, yellow within 30 days of expiry, none otherwise.
export function noteTone(status: CertificateView['status']): 'error' | 'warn' | null {
  if (status === 'expired' || status === 'notYetValid') return 'error';
  return status === 'expiresSoon' ? 'warn' : null;
}
