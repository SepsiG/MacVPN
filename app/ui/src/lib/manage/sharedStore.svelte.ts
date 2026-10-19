// The Credentials section's list as the last view model had it, for the editors' selector (they are not handed
// the view model). Never a password.
import type { CredentialsView } from '../api';

export const sharedCredentials = $state<{ view: CredentialsView }>({ view: { available: false, message: null, items: [] } });

export function setSharedCredentials(view: CredentialsView | undefined): void {
  if (view) sharedCredentials.view = view;
}
