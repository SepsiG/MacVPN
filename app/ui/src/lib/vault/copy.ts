// Copying a shown recovery key: the backend puts it on the pasteboard concealed (clipboard managers skip it,
// Universal Clipboard does not send it) and empties it a minute later, at a lock or at quit if it is still there.
// The web view never writes a secret to the clipboard itself.
import { api } from '../api';

export async function copyRecoveryKey(key: string | null): Promise<boolean> {
  if (!key) return false;
  try {
    await api.vaultCopyRecoveryKey(key);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
}
