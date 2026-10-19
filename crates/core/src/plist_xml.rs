//! A small XML property-list writer producing exactly what Foundation's `PropertyListSerialization` (`.xml`)
//! writes: tab indentation, dictionary keys sorted, `&`, `<`, `>` escaped, data as base64 wrapped by indentation.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Data(Vec<u8>),
    Array(Vec<PlistValue>),
    Dictionary(BTreeMap<String, PlistValue>),
}

/// `PropertyListSerialization.data(fromPropertyList:format: .xml, options: 0)`.
pub fn to_xml(root: &PlistValue) -> Vec<u8> {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n",
    );
    write(&mut out, root, 0);
    out.push_str("</plist>\n");
    out.into_bytes()
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push('\t');
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn write(out: &mut String, value: &PlistValue, level: usize) {
    indent(out, level);
    match value {
        PlistValue::String(s) => out.push_str(&format!("<string>{}</string>\n", escape(s))),
        PlistValue::Integer(n) => out.push_str(&format!("<integer>{n}</integer>\n")),
        PlistValue::Boolean(b) => out.push_str(if *b { "<true/>\n" } else { "<false/>\n" }),
        PlistValue::Data(d) => {
            out.push_str("<data>\n");
            let encoded = crate::swift_base64::encode(d);
            let width = (76 - level.min(8) * 8) / 4 * 4;
            for chunk in encoded.as_bytes().chunks(width.max(4)) {
                indent(out, level);
                out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
                out.push('\n');
            }
            indent(out, level);
            out.push_str("</data>\n");
        }
        PlistValue::Array(items) => {
            if items.is_empty() {
                out.push_str("<array/>\n");
                return;
            }
            out.push_str("<array>\n");
            for item in items {
                write(out, item, level + 1);
            }
            indent(out, level);
            out.push_str("</array>\n");
        }
        PlistValue::Dictionary(map) => {
            if map.is_empty() {
                out.push_str("<dict/>\n");
                return;
            }
            out.push_str("<dict>\n");
            for (key, item) in map {
                indent(out, level + 1);
                out.push_str(&format!("<key>{}</key>\n", escape(key)));
                write(out, item, level + 1);
            }
            indent(out, level);
            out.push_str("</dict>\n");
        }
    }
}
