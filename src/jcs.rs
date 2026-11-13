//! RFC 8785 (JCS) canonical JSON, over which the console signs its orders (protocol §7.1).

use serde_json::Value;

pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                // ECMAScript number serialization; the orders of v1 carry integers only.
                let f = n.as_f64().unwrap_or(0.0);
                if f.fract() == 0.0 && f.abs() < 1e21 {
                    out.push_str(&format!("{}", f as i64));
                } else {
                    out.push_str(&f.to_string());
                }
            }
        }
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // Sorted by UTF-16 code units, as the RFC says.
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(key, out);
                out.push(':');
                write(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// JSON.stringify of a string: `"`, `\` and the control characters escaped, everything else as is.
fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_keys_and_escapes_like_the_rfc() {
        let value: Value =
            serde_json::from_str(r#"{"b":[1,{"z":null,"a":true}],"a":"x\u0001\"é/","€":1,"\r":2}"#)
                .unwrap();
        assert_eq!(
            canonical(&value),
            "{\"\\r\":2,\"a\":\"x\\u0001\\\"é/\",\"b\":[1,{\"a\":true,\"z\":null}],\"€\":1}"
        );
        assert_eq!(
            canonical(&serde_json::json!({"payload": {}})),
            r#"{"payload":{}}"#
        );
    }
}
