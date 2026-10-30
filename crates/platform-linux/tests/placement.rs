use macvpn_platform_linux::pure::placement::{DEFAULT_CARD, card_input_rect, panel_position};

#[test]
fn top_right_of_the_work_area_with_an_8_px_margin() {
    // A 1920×1080 monitor whose work area starts below a 32 px top bar.
    assert_eq!(panel_position((0, 32, 1920, 1048), (330, 360)), (1582, 40));
    // A second monitor to the right.
    assert_eq!(panel_position((1920, 0, 2560, 1440), (660, 720)), (3812, 8));
}

#[test]
fn never_left_of_the_work_area() {
    assert_eq!(panel_position((100, 0, 300, 600), (330, 360)), (100, 8));
}

#[test]
fn the_spikes_overlay_on_a_1280_by_800_monitor() {
    // Spike L0-2: Mutter maximized the overlay to 1213×768 at (67, 32); inside it the card is at (8 px from the
    // right, 8 px from the top) of the overlay's own coordinates.
    assert_eq!(panel_position((0, 0, 1213, 768), (360, 420)), (845, 8));
}

#[test]
fn the_input_region_is_the_reported_card_rounded_outward() {
    // The page's card in a 1213×768 overlay: CSS pixels with fractions (the region never cuts off a card pixel).
    assert_eq!(card_input_rect((1213, 768), Some((874.5, 8.0, 330.0, 412.25))), (874, 8, 331, 413));
    assert_eq!(card_input_rect((1213, 768), Some((875.0, 8.0, 330.0, 412.0))), (875, 8, 330, 412));
}

#[test]
fn the_input_region_stays_inside_the_window() {
    // A card taller than the overlay (a short work area) and one reaching past its left edge.
    assert_eq!(card_input_rect((1213, 400), Some((875.0, 8.0, 330.0, 900.0))), (875, 8, 330, 392));
    assert_eq!(card_input_rect((300, 768), Some((-30.0, 8.0, 330.0, 100.0))), (0, 8, 300, 100));
    // Nothing left of it: an empty region (the overlay takes no click at all).
    assert_eq!(card_input_rect((300, 768), Some((400.0, 8.0, 330.0, 100.0))), (300, 8, 0, 100));
}

#[test]
fn before_the_page_reports_the_card_the_default_card_is_at_the_corner() {
    assert_eq!(DEFAULT_CARD, (330, 360));
    assert_eq!(card_input_rect((1213, 768), None), (875, 8, 330, 360));
    // A report the page cannot mean (not a number, a negative size) is the default card too.
    assert_eq!(card_input_rect((1213, 768), Some((f64::NAN, 8.0, 330.0, 100.0))), (875, 8, 330, 360));
    assert_eq!(card_input_rect((1213, 768), Some((875.0, 8.0, -1.0, 100.0))), (875, 8, 330, 360));
}
