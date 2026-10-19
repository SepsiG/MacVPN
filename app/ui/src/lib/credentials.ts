// The credential window's rules (the backend checks the answer again: `CredentialBroker::answer_checked`).
import type { CredentialField } from './api';

/// The display order of the fields.
export const FIELD_ORDER: readonly CredentialField[] = ['username', 'password', 'psk', 'keyPassword'];

/// The credential ID of a credential window's label (`cred-<id>`).
export function credentialIdOfLabel(label: string): number | null {
  const m = /^cred-(\d{1,15})$/.exec(label);
  return m ? Number(m[1]) : null;
}

/// The asked fields in display order, each once, unknown names dropped.
export function orderedFields(fields: readonly string[]): CredentialField[] {
  return FIELD_ORDER.filter((f) => fields.includes(f));
}

/// A secret field (a password input); the user name is plain text.
export function isSecretField(field: CredentialField): boolean {
  return field !== 'username';
}

/// "Connect" works once the input lock passed and every asked field has a value.
export function canConnect(
  fields: readonly CredentialField[],
  values: Partial<Record<CredentialField, string>>,
  armed: boolean,
): boolean {
  return armed && fields.length > 0 && fields.every((f) => (values[f] ?? '') !== '');
}

/// Exactly the asked fields' values (the answer the backend expects).
export function answerValues(
  fields: readonly CredentialField[],
  values: Partial<Record<CredentialField, string>>,
): Partial<Record<CredentialField, string>> {
  const out: Partial<Record<CredentialField, string>> = {};
  for (const f of fields) out[f] = values[f] ?? '';
  return out;
}
