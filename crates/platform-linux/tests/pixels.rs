use macvpn_platform_linux::pure::pixels::argb;

#[test]
fn rgba_becomes_big_endian_argb() {
    assert_eq!(argb(&[1, 2, 3, 4]), [4, 1, 2, 3]);
    assert_eq!(argb(&[255, 255, 255, 0, 10, 20, 30, 255]), [0, 255, 255, 255, 255, 10, 20, 30]);
}

#[test]
fn a_partial_pixel_is_dropped() {
    assert_eq!(argb(&[1, 2, 3, 4, 5, 6]), [4, 1, 2, 3]);
    assert!(argb(&[]).is_empty());
}
