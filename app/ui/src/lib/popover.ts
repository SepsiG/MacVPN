// Popovers and context menus stay inside the window (every language, every window size): the popover is measured
// after it rendered, placed next to its anchor (a button's rectangle, or the pointer for a context menu), flipped
// to the other side when there is no room, and clamped `POPOVER_MARGIN` points inside the viewport. A popover
// larger than the viewport gets the viewport's size (less the margins) as its maximum and scrolls. It is placed
// again whenever the window or its content changes size.

/// The distance kept from the window's edges.
export const POPOVER_MARGIN = 8;

export interface Rect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export interface Size {
  width: number;
  height: number;
}

export interface Placement {
  left: number;
  top: number;
  /// Shown above the anchor (no room below).
  flipped: boolean;
}

export interface PlaceOptions {
  /// `start`: the popover's left edge at the anchor's left (a context menu: at the pointer); `end`: its right edge
  /// at the anchor's right (a menu under a right-aligned button).
  align?: 'start' | 'end';
  /// The space between the anchor and the popover.
  gap?: number;
  margin?: number;
}

/// A point (a context menu's pointer position) as an anchor.
export function pointAnchor(x: number, y: number): Rect {
  return { left: x, top: y, right: x, bottom: y };
}

/// Where a popover of `size` goes for `anchor` in a `viewport`: below the anchor, or above it when only there it
/// fits (else on the roomier side); aligned as asked, or the other way when only that fits; then clamped inside
/// the margins (a popover wider or taller than the viewport starts at the margin).
export function placePopover(anchor: Rect, size: Size, viewport: Size, options: PlaceOptions = {}): Placement {
  const { align = 'start', gap = 0, margin = POPOVER_MARGIN } = options;
  const clamp = (value: number, length: number, extent: number) =>
    Math.max(margin, Math.min(value, extent - margin - length));
  const fitsX = (x: number) => x >= margin && x + size.width <= viewport.width - margin;

  const preferred = align === 'start' ? anchor.left : anchor.right - size.width;
  const other = align === 'start' ? anchor.right - size.width : anchor.left;
  const left = clamp(fitsX(preferred) || !fitsX(other) ? preferred : other, size.width, viewport.width);

  const below = anchor.bottom + gap;
  const above = anchor.top - gap - size.height;
  const roomBelow = viewport.height - margin - below;
  const roomAbove = anchor.top - gap - margin;
  const flipped = size.height > roomBelow && (size.height <= roomAbove || roomAbove > roomBelow);
  const top = clamp(flipped ? above : below, size.height, viewport.height);
  return { left, top, flipped };
}

export interface PopoverParams extends PlaceOptions {
  /// What the popover is placed by, read on every placement (a button's rectangle follows a resized window).
  anchor: Rect | (() => Rect);
  /// The widest it may be (narrower when the window is): long items wrap instead.
  maxWidth?: number;
}

/// The action that keeps a popover inside the window (`use:popover={{ anchor, align, gap }}`): fixed positioning,
/// the viewport as the maximum size, placed after rendering, again on a window resize, a content size change
/// (language, fonts) or new parameters.
export function popover(node: HTMLElement, params: PopoverParams) {
  let current = params;
  let frame = 0;
  node.style.position = 'fixed';
  node.style.boxSizing = 'border-box';
  node.style.overflowY = 'auto';

  const place = () => {
    const margin = current.margin ?? POPOVER_MARGIN;
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    node.style.maxWidth = `${Math.max(0, Math.min(current.maxWidth ?? Infinity, viewport.width - 2 * margin))}px`;
    node.style.maxHeight = `${Math.max(0, viewport.height - 2 * margin)}px`;
    // offsetWidth/offsetHeight: the layout size (the opening animation's scale does not count).
    const size = { width: node.offsetWidth, height: node.offsetHeight };
    const anchor = typeof current.anchor === 'function' ? current.anchor() : current.anchor;
    const { left, top, flipped } = placePopover(anchor, size, viewport, current);
    node.style.left = `${Math.round(left)}px`;
    node.style.top = `${Math.round(top)}px`;
    node.style.right = 'auto';
    node.style.bottom = 'auto';
    node.dataset.placement = flipped ? 'above' : 'below';
  };
  const schedule = () => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(place);
  };

  place();
  const observer = new ResizeObserver(schedule);
  observer.observe(node);
  window.addEventListener('resize', place);
  return {
    update(next: PopoverParams) {
      current = next;
      place();
    },
    destroy() {
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener('resize', place);
    },
  };
}
