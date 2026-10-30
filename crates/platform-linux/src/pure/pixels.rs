//! Tray icon pixels: the StatusNotifierItem's `IconPixmap` is ARGB32 in network byte order (big-endian).

/// RGBA (row-major, 8 bits per channel) → the SNI's ARGB32 big-endian. A trailing partial pixel is dropped.
pub fn argb(rgba: &[u8]) -> Vec<u8> {
    let (pixels, _) = rgba.as_chunks::<4>();
    pixels.iter().flat_map(|&[r, g, b, a]| [a, r, g, b]).collect()
}
