// The IKEv2 client certificate panel's rules (pure, tested by node --test). The backend reads and checks the files
// and keeps the key in the vault (`EditorView.clientCert`); the web view only sees the public summary.
import type { ClientCertSummary, ClientCertView } from '../api';
import { tr } from '../l10n.svelte';

/// "Private key password" in the text editor: OpenVPN always; IKEv2 when the config signs with a key
/// (`auth = pubkey`) on a platform where MacVPN loads the key itself (not Windows' certificate store).
export function showsKeyPassword(kind: string, cert: ClientCertView | undefined): boolean {
  if (kind === 'openvpn') return true;
  return kind === 'strongswan' && !!cert && cert.import && cert.pubkey;
}

/// The client certificate panel is shown: IKEv2 where the app imports certificates, when the config signs with a
/// key or a certificate is already imported (to remove it).
export function showsPanel(kind: string, cert: ClientCertView | undefined): cert is ClientCertView {
  return kind === 'strongswan' && !!cert && cert.import && (cert.pubkey || cert.imported !== null);
}

/// "PEM certificate and key" / "PKCS#12 file".
export function formLabel(summary: ClientCertSummary): string {
  return summary.form === 'pkcs12' ? tr('PKCS#12 file') : tr('PEM certificate and key');
}

/// The notes under the imported certificate, in display order.
export function notes(cert: ClientCertView): string[] {
  const out: string[] = [];
  if (cert.imported && !cert.pubkey) {
    out.push(tr('This config does not sign in with a certificate (auth = pubkey): the imported certificate is not used.'));
  }
  if (cert.imported?.needsPassword) {
    out.push(tr('The key is protected by a password: save it below, or MacVPN asks for it when connecting.'));
  }
  if (cert.ignored > 0) {
    out.push(tr('%ld other certificates in the files (the CA, the chain) were not imported.', cert.ignored));
  }
  return out;
}
