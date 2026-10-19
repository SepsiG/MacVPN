// The secret fields' input rule (pure, tested by node --test). The backend never sends a stored secret: the field
// is `null` ("keep the stored value") until the user types a new one, or removes the stored one with the explicit
// action (`''`). Emptying the field again goes back to "keep", so a stored secret is only ever deleted on purpose.
import type { SecretInput } from '../api';

export function secretFromInput(text: string, removed: boolean): SecretInput {
  if (text !== '') return text;
  return removed ? '' : null;
}
