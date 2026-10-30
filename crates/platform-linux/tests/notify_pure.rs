use macvpn_platform_linux::pure::notify::Book;
use std::collections::BTreeMap;

#[test]
fn ids_per_identifier_clicks_and_closes() {
    let mut book = Book::default();
    assert_eq!(book.replaces("connected"), 0);
    book.posted("connected", 41, ("connection", "6F1C"));
    assert_eq!(book.replaces("connected"), 41, "a repost replaces the shown one");
    assert_eq!(book.clicked(41), Some(BTreeMap::from([("connection".to_string(), "6F1C".to_string())])));
    assert_eq!(book.id_of("connected"), Some(41));
    book.closed(41);
    assert_eq!(book.id_of("connected"), None);
    assert_eq!(book.clicked(41), None);
}
