// The texts of the publish review's codes (app/src-tauri/src/catalog.rs `PublishPreviewView`): personal fields,
// inline keys, stored team secrets and refusals. An unknown code (a newer backend) shows a generic text.
import { i18n, tr } from '../l10n.svelte';

/// A personal field of a selected connection, with what happens to it.
export function personalText(code: string): string {
  switch (code) {
    case 'sstpUser':
      return tr('SSTP user name (user=): with a ticked credential slot the config is published with user=slot-user and each member’s own user name goes in at connect; without a slot the user name is published only with its tick below.');
    case 'nativeAccount':
      return tr('Account name: never published; each member enters their own');
    case 'wireguardPrivateKey':
      return tr('WireGuard private key: everyone appears to the server as the same peer');
    case 'openvpnInlineKey':
      return tr('OpenVPN inline <key> or <pkcs12>: everyone uses the same client key');
    default:
      return tr('A personal setting');
  }
}

/// An inline key of a config that needs its own tick. The WireGuard private key's tick is the acknowledgement.
export function inlineText(code: string): string {
  switch (code) {
    case 'wireguardPrivateKey':
      return tr('Everyone with this catalog uses the same WireGuard key');
    case 'sstpUser':
      return tr('Publish this SSTP user name: no credential slot is ticked, so everyone signs in with it');
    case 'wireguardPresharedKey':
      return tr('Publish the WireGuard PresharedKey');
    case 'openvpnKey':
      return tr('Publish the inline <key> / <pkcs12>: everyone uses the same client key');
    case 'tlsAuth':
      return tr('Publish the <tls-auth> key');
    case 'tlsCrypt':
      return tr('Publish the <tls-crypt> key');
    case 'tlsCryptV2':
      return tr('Publish the <tls-crypt-v2> key');
    case 'staticKey':
      return tr('Publish the static <secret> key');
    default:
      return tr('Publish this key');
  }
}

/// A stored team secret (opt-in).
export function secretText(code: string): string {
  return code === 'psk' ? tr('Shared secret (PSK)') : code === 'keypass' ? tr('Private key password') : tr('Secret');
}

/// Why a connection cannot be published.
export function refusalText(code: string): string {
  switch (code) {
    case 'inlineCredentials':
      return tr('The config holds a user name or password (an inline <auth-user-pass> / <http-proxy-user-pass> block or a strongSwan secrets section). Remove it and use a credential slot.');
    case 'config':
      return tr('The config has errors. Open the connection and fix them.');
    case 'nativeSettings':
      return tr('The connection’s settings are not valid.');
    case 'configTooLarge':
      return tr('The config is too large to publish.');
    case 'connectionName':
      return tr('The connection’s name cannot be published. Rename it.');
    default:
      return tr('This connection cannot be published.');
  }
}

/// A connection's name for the review (an id the rows no longer have: the id itself).
export function itemName(names: ReadonlyMap<string, string>, id: string): string {
  return names.get(id) ?? id;
}

/// A date for the publications list.
export function dateText(seconds: number | null): string {
  if (seconds === null) return tr('Never');
  return new Date(seconds * 1000).toLocaleString(i18n.language === 'hu' ? 'hu-HU' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' });
}
