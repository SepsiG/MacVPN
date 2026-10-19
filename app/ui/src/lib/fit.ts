// The prompt windows (MFA code / web sign-in, credentials, pairing) follow their content's height, the way the
// menu does: the rendered content is measured whenever it changes (the view model's texts, a retry message, an
// error, the language) and the window asks the backend for that height (`fit_window`: its own window only,
// bounded, centred on the first fit). Beyond the backend's maximum the page scrolls instead of clipping.
/// The height to ask for: the content's, in whole points; nothing for an empty page (not rendered yet).
export function fitHeight(contentHeight: number): number | null {
  if (!Number.isFinite(contentHeight) || contentHeight <= 0) return null;
  return Math.ceil(contentHeight);
}

/// Keeps the window as tall as `content` (the page's mount point, whose height is the content's), through `send`
/// (`api.fitWindow`). Returns the clean-up.
export function fitToContent(content: HTMLElement | null, send: (height: number) => Promise<void>): () => void {
  if (!content) return () => {};
  // The base style hides overflow; past the backend's maximum the page scrolls rather than clipping the buttons.
  document.documentElement.style.overflowY = 'auto';
  let last: number | null = null;
  const measure = () => {
    const height = fitHeight(content.getBoundingClientRect().height);
    if (height === null || height === last) return;
    last = height;
    send(height).catch(console.error);
  };
  const observer = new ResizeObserver(measure);
  observer.observe(content);
  document.fonts?.ready.then(measure, () => {});
  return () => observer.disconnect();
}
