<script lang="ts">
  // The certificates of a connection's config (the client certificate first, then the chain and the CAs): the
  // subject, the issuer, the validity, the key type, the serial number and the SHA-256 fingerprint, with a yellow
  // note within 30 days of expiry and a red one once expired. The fingerprint and the PEM are public: "Copy" uses
  // the web view's clipboard. A certificate with a note is shown open.
  import type { CertificatesView } from '../api';
  import Icon from '../Icon.svelte';
  import { i18n, tr } from '../l10n.svelte';
  import { certificateDate, noteTone, roleTitle } from './certs';

  let { certificates }: { certificates: CertificatesView } = $props();

  let copied = $state<{ index: number; what: 'fingerprint' | 'pem' } | null>(null);
  let error = $state<string | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy(index: number, what: 'fingerprint' | 'pem', text: string) {
    error = null;
    try {
      await navigator.clipboard.writeText(text);
      copied = { index, what };
      clearTimeout(timer);
      timer = setTimeout(() => (copied = null), 3000);
    } catch (e) {
      error = String(e);
    }
  }
</script>

<fieldset class="certificates">
  <legend>{tr('Certificates')}</legend>
  {#each certificates.certificates as c, i (i)}
    {@const tone = noteTone(c.status)}
    <details class="certificate" open={tone !== null}>
      <summary>
        <span class="role">{roleTitle(c.role)}</span>
        <span class="subject">{c.subject}</span>
        {#if c.note}<span class="cert-note {tone}" role={tone === 'error' ? 'alert' : 'note'}><Icon name="warning" />{c.note}</span>{/if}
      </summary>
      <dl>
        <dt>{tr('Subject')}</dt>
        <dd>{c.subject}</dd>
        <dt>{tr('Issuer')}</dt>
        <dd>{c.issuer}</dd>
        <dt>{tr('Valid from')}</dt>
        <dd>{certificateDate(c.notBefore, i18n.language)}</dd>
        <dt>{tr('Valid until')}</dt>
        <dd class:expiring={tone !== null}>{certificateDate(c.notAfter, i18n.language)}</dd>
        <dt>{tr('Key type')}</dt>
        <dd>{c.keyType}</dd>
        <dt>{tr('Serial number')}</dt>
        <dd><code>{c.serial}</code></dd>
        <dt>{tr('SHA-256 fingerprint')}</dt>
        <dd class="fingerprint">
          <code>{c.sha256}</code>
          <button class="copy-fingerprint" type="button" onclick={() => copy(i, 'fingerprint', c.sha256).catch(console.error)}
            ><Icon name="copy" />{copied?.index === i && copied.what === 'fingerprint' ? tr('Copied') : tr('Copy')}</button
          >
        </dd>
        <dt>{tr('Source')}</dt>
        <dd><code>{c.source}</code></dd>
      </dl>
      <div class="actions">
        <button class="copy-pem" type="button" onclick={() => copy(i, 'pem', c.pem).catch(console.error)}
          ><Icon name="copy" />{copied?.index === i && copied.what === 'pem' ? tr('Copied') : tr('Copy PEM')}</button
        >
      </div>
    </details>
  {/each}
  {#if certificates.pkcs12Encrypted}
    <p class="note pkcs12-encrypted">{tr('The certificates in the PKCS#12 file are encrypted with its password, so they cannot be shown here.')}</p>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</fieldset>

<style>
  .certificates {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .certificate summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    cursor: default;
  }
  .role {
    font-weight: 600;
  }
  .subject {
    flex: 1;
    min-width: 0;
    color: var(--secondary);
    overflow-wrap: anywhere;
  }
  .cert-note {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 1px 8px;
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
  }
  .cert-note :global(.icon) {
    width: 12px;
    height: 12px;
  }
  .cert-note.warn {
    background: var(--state-busy-soft);
    color: var(--state-busy-text);
  }
  .cert-note.error {
    background: var(--state-fail-soft);
    color: var(--state-fail-text);
  }
  dl {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: 4px var(--space-3);
    margin: var(--space-2) 0 0;
  }
  dt {
    color: var(--secondary);
  }
  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  dd.expiring {
    font-weight: 600;
  }
  code {
    font-family: var(--mono);
    font-size: var(--text-sm);
    user-select: all;
  }
  .fingerprint {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .fingerprint code {
    flex: 1;
    min-width: 0;
  }
  .actions {
    margin-top: var(--space-2);
  }
</style>
