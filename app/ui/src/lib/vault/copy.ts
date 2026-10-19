// Copying a shown recovery key: the async clipboard, else the shown text selected and copied. The key never goes
// back to the backend for this; the backend only empties the pasteboard a minute later if it still holds a key.
import { api } from '../api';

export async function copyRecoveryKey(key: string | null): Promise<boolean> {
  const copied = await copyText(key);
  if (copied) api.vaultKeyCopied().catch(console.error);
  return copied;
}

async function copyText(key: string | null): Promise<boolean> {
  if (!key) return false;
  try {
    await navigator.clipboard.writeText(key);
    return true;
  } catch {
    const code = document.querySelector('[data-recovery-key]');
    const selection = window.getSelection();
    if (!code || !selection) return false;
    const range = document.createRange();
    range.selectNodeContents(code);
    selection.removeAllRanges();
    selection.addRange(range);
    const copied = document.execCommand('copy');
    selection.removeAllRanges();
    return copied;
  }
}
