// The pinned list's drag: which gap the pointer is over, and whether dropping there moves the row
// (SwiftUI `onMove` semantics: the destination is the gap index in the list before the move).

/// The gap (0 … mids.length) for the pointer's y, given the rows' vertical midpoints in order.
export function dropIndex(mids: readonly number[], y: number): number {
  let gap = 0;
  while (gap < mids.length && y > mids[gap]) gap += 1;
  return gap;
}

/// Dropping row `from` into gap `to` changes the order (not its own gap above or below it).
export function isMove(from: number, to: number): boolean {
  return to !== from && to !== from + 1;
}
