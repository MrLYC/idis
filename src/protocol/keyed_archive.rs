use anyhow::{anyhow, bail, Context, Result};
use plist::{Dictionary, Uid, Value};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

/// Apple Cocoa `NSDate` epoch is 2001-01-01 00:00:00 UTC.
pub const APPLE_EPOCH_OFFSET_SECS: f64 = 978_307_200.0;

pub fn now_apple_secs() -> f64 {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(APPLE_EPOCH_OFFSET_SECS);
    unix - APPLE_EPOCH_OFFSET_SECS
}

/// Decoded/encodable representation of an `NSKeyedArchiver` object graph.
#[derive(Debug, Clone, PartialEq)]
pub enum ArchivedValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Real(f64),
    String(String),
    Data(Vec<u8>),
    Date(f64), // NS.time (seconds since 2001-01-01 UTC)
    Array(Vec<ArchivedValue>),
    Set(Vec<ArchivedValue>),
    Dict(BTreeMap<String, ArchivedValue>),
    Object {
        class_name: String,
        classes: Vec<String>,
        fields: BTreeMap<String, ArchivedValue>,
    },
}

impl ArchivedValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ArchivedValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ArchivedValue::Int(v) => Some(*v),
            ArchivedValue::Uint(v) => i64::try_from(*v).ok(),
            ArchivedValue::Bool(b) => Some(if *b { 1 } else { 0 }),
            ArchivedValue::Real(f) => Some(*f as i64),
            ArchivedValue::String(s) => s.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            ArchivedValue::Uint(v) => Some(*v),
            ArchivedValue::Int(v) if *v >= 0 => Some(*v as u64),
            ArchivedValue::Real(f) if *f >= 0.0 => Some(*f as u64),
            ArchivedValue::String(s) => s.trim().parse::<u64>().ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            ArchivedValue::Real(f) => Some(*f),
            ArchivedValue::Int(v) => Some(*v as f64),
            ArchivedValue::Uint(v) => Some(*v as f64),
            ArchivedValue::String(s) => s.trim().parse::<f64>().ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ArchivedValue::Bool(b) => Some(*b),
            ArchivedValue::Int(v) => Some(*v != 0),
            ArchivedValue::Uint(v) => Some(*v != 0),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<String, ArchivedValue>> {
        match self {
            ArchivedValue::Dict(d) => Some(d),
            _ => None,
        }
    }
}

/// Pre-validate raw `bplist00` or XML plist bytes BEFORE handing them to the `plist` crate
/// so hostile pre-auth payloads cannot trigger unbudgeted object-table diamond DAG expansion,
/// 2-level leaf amplification, legacy ASCII plist stack overflow (`P0-A1`), or XML attribute/comment
/// depth-counter bypass (`P0-A2`).
///
/// Returns `Ok(true)` for validated `bplist00` binary plists and `Ok(false)` for validated XML plists.
fn prevalidate_plist_bytes(bytes: &[u8]) -> Result<bool> {
    const MAX_NODES: usize = 16_384;
    const MAX_BYTES: usize = 2 * 1024 * 1024;
    const MAX_DEPTH: usize = 64;

    if bytes.len() > MAX_BYTES {
        bail!("plist payload exceeds maximum allowed size ({} bytes)", bytes.len());
    }
    if bytes.starts_with(b"bplist00") {
        if bytes.len() < 40 {
            bail!("truncated bplist00 payload ({} bytes)", bytes.len());
        }
        let trailer = &bytes[bytes.len() - 32..];
        let offset_int_size = trailer[6] as usize;
        let object_ref_size = trailer[7] as usize;
        if !(1..=8).contains(&offset_int_size) || !(1..=8).contains(&object_ref_size) {
            bail!(
                "invalid bplist00 trailer sizes: offset_int_size={offset_int_size}, object_ref_size={object_ref_size}"
            );
        }
        let num_objects = u64::from_be_bytes(trailer[8..16].try_into().unwrap()) as usize;
        let top_object = u64::from_be_bytes(trailer[16..24].try_into().unwrap()) as usize;
        let offset_table_offset = u64::from_be_bytes(trailer[24..32].try_into().unwrap()) as usize;

        if num_objects == 0 || top_object >= num_objects {
            bail!("invalid bplist00 root object index {top_object}/{num_objects}");
        }
        let table_bytes = num_objects
            .checked_mul(offset_int_size)
            .ok_or_else(|| anyhow!("bplist00 offset table size overflow"))?;
        let table_end = offset_table_offset
            .checked_add(table_bytes)
            .ok_or_else(|| anyhow!("bplist00 offset table end overflow"))?;
        if offset_table_offset < 8 || table_end > bytes.len() - 32 {
            bail!("bplist00 offset table out of bounds");
        }

        fn read_be_uint(slice: &[u8]) -> usize {
            let mut v: usize = 0;
            for &b in slice {
                v = (v << 8) | (b as usize);
            }
            v
        }

        fn read_bplist_len(bytes: &[u8], pos: usize, low_nibble: u8) -> Result<(usize, usize)> {
            if low_nibble != 0x0f {
                return Ok((low_nibble as usize, pos));
            }
            let marker = *bytes
                .get(pos)
                .ok_or_else(|| anyhow!("truncated bplist00 extended length marker"))?;
            if (marker & 0xf0) != 0x10 {
                bail!("invalid bplist00 extended length marker 0x{marker:02x}");
            }
            let exp = (marker & 0x0f) as u32;
            if exp > 3 {
                bail!("bplist00 extended length exponent too large ({exp})");
            }
            let int_len = 1usize << exp;
            let end = pos
                .checked_add(1 + int_len)
                .ok_or_else(|| anyhow!("bplist00 length offset overflow"))?;
            let slice = bytes
                .get(pos + 1..end)
                .ok_or_else(|| anyhow!("truncated bplist00 extended length value"))?;
            Ok((read_be_uint(slice), end))
        }

        #[allow(clippy::too_many_arguments)]
        fn walk_bplist(
            bytes: &[u8],
            offset_table_offset: usize,
            offset_int_size: usize,
            object_ref_size: usize,
            num_objects: usize,
            obj_idx: usize,
            depth: usize,
            budget: &mut DecodeBudget,
            visiting: &mut std::collections::HashSet<usize>,
        ) -> Result<()> {
            budget.consume_node(depth)?;
            if obj_idx >= num_objects {
                bail!("bplist00 object ref {obj_idx} out of bounds ({num_objects})");
            }
            if !visiting.insert(obj_idx) {
                bail!("bplist00 raw object cycle detected at ref {obj_idx}");
            }
            let off_pos = offset_table_offset + obj_idx * offset_int_size;
            let obj_offset = read_be_uint(&bytes[off_pos..off_pos + offset_int_size]);
            if obj_offset < 8 || obj_offset >= offset_table_offset {
                visiting.remove(&obj_idx);
                bail!("bplist00 object offset {obj_offset} out of bounds");
            }
            let marker = bytes[obj_offset];
            let hi = marker & 0xf0;
            let lo = marker & 0x0f;
            let res = match hi {
                0x00 | 0x10 | 0x20 | 0x30 | 0x80 => Ok(()), // null/bool/int/real/date/uid
                0x40 | 0x50 => {
                    // Data or ASCII string
                    let (len, _) = read_bplist_len(bytes, obj_offset + 1, lo)?;
                    budget.consume_bytes(len)
                }
                0x60 => {
                    // UTF-16BE string (2 bytes per code unit)
                    let (chars, _) = read_bplist_len(bytes, obj_offset + 1, lo)?;
                    let byte_len = chars
                        .checked_mul(2)
                        .ok_or_else(|| anyhow!("bplist00 UTF-16 length overflow"))?;
                    budget.consume_bytes(byte_len)
                }
                0xA0 | 0xC0 => {
                    // Array or Set
                    let (count, items_pos) = read_bplist_len(bytes, obj_offset + 1, lo)?;
                    let refs_bytes = count
                        .checked_mul(object_ref_size)
                        .ok_or_else(|| anyhow!("bplist00 array ref size overflow"))?;
                    let items_end = items_pos
                        .checked_add(refs_bytes)
                        .ok_or_else(|| anyhow!("bplist00 array end overflow"))?;
                    if items_end > offset_table_offset {
                        bail!("bplist00 array refs out of bounds");
                    }
                    for i in 0..count {
                        let p = items_pos + i * object_ref_size;
                        let child_ref = read_be_uint(&bytes[p..p + object_ref_size]);
                        walk_bplist(
                            bytes,
                            offset_table_offset,
                            offset_int_size,
                            object_ref_size,
                            num_objects,
                            child_ref,
                            depth + 1,
                            budget,
                            visiting,
                        )?;
                    }
                    Ok(())
                }
                0xD0 => {
                    // Dict: `count` key refs followed by `count` val refs
                    let (count, items_pos) = read_bplist_len(bytes, obj_offset + 1, lo)?;
                    let total_refs = count
                        .checked_mul(2)
                        .ok_or_else(|| anyhow!("bplist00 dict ref count overflow"))?;
                    let refs_bytes = total_refs
                        .checked_mul(object_ref_size)
                        .ok_or_else(|| anyhow!("bplist00 dict ref size overflow"))?;
                    let items_end = items_pos
                        .checked_add(refs_bytes)
                        .ok_or_else(|| anyhow!("bplist00 dict end overflow"))?;
                    if items_end > offset_table_offset {
                        bail!("bplist00 dict refs out of bounds");
                    }
                    for i in 0..total_refs {
                        let p = items_pos + i * object_ref_size;
                        let child_ref = read_be_uint(&bytes[p..p + object_ref_size]);
                        walk_bplist(
                            bytes,
                            offset_table_offset,
                            offset_int_size,
                            object_ref_size,
                            num_objects,
                            child_ref,
                            depth + 1,
                            budget,
                            visiting,
                        )?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            };
            visiting.remove(&obj_idx);
            res
        }

        let mut budget = DecodeBudget {
            nodes: MAX_NODES,
            bytes: MAX_BYTES,
        };
        let mut visiting = std::collections::HashSet::new();
        walk_bplist(
            bytes,
            offset_table_offset,
            offset_int_size,
            object_ref_size,
            num_objects,
            top_object,
            0,
            &mut budget,
            &mut visiting,
        )?;
        Ok(true)
    } else {
        // Strictly reject legacy OpenStep ASCII plists (`(`, `{`, etc.) so `plist::stream::AsciiReader`
        // can NEVER be reached by untrusted pre-auth frames (Iter-6 P0-A1).
        let trimmed = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        let start = trimmed
            .iter()
            .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .ok_or_else(|| anyhow!("empty plist payload"))?;
        let xml = &trimmed[start..];
        if !(xml.starts_with(b"<?xml") || xml.starts_with(b"<!DOCTYPE") || xml.starts_with(b"<plist")) {
            bail!("unsupported plist format (expected bplist00 or XML plist)");
        }

        // Stateful XML tokenizer: properly skips comments (`<!-- ... -->`), CDATA (`<![CDATA[...]]>`),
        // processing instructions (`<?...?>`), DOCTYPE declarations (rejecting internal `<!ENTITY`),
        // and quoted attribute values (`"..."` / `'...'`) so neither `<array a="/>">` nor
        // `<!-- > </></>... -->` can spoof nesting depth (Iter-6 P0-A2).
        let mut depth: usize = 0;
        let mut elements: usize = 0;
        let mut i = 0usize;
        while i < xml.len() {
            if xml[i] != b'<' {
                i += 1;
                continue;
            }
            let rest = &xml[i..];
            if rest.starts_with(b"<!--") {
                let end = rest[4..]
                    .windows(3)
                    .position(|w| w == b"-->")
                    .ok_or_else(|| anyhow!("unterminated XML comment"))?;
                i += 4 + end + 3;
            } else if rest.starts_with(b"<![CDATA[") {
                let end = rest[9..]
                    .windows(3)
                    .position(|w| w == b"]]>")
                    .ok_or_else(|| anyhow!("unterminated XML CDATA"))?;
                i += 9 + end + 3;
            } else if rest.starts_with(b"<?") {
                let end = rest[2..]
                    .windows(2)
                    .position(|w| w == b"?>")
                    .ok_or_else(|| anyhow!("unterminated XML processing instruction"))?;
                i += 2 + end + 2;
            } else if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case(b"<!doctype") {
                // Standard Apple XML plists never use internal DTD subsets (`[...]`). Rejecting `[`
                // outright eliminates quote-desync bypasses via `<!DOCTYPE plist [<!-- " -->]>`
                // (`quick-xml` DtdParser::InComment/InPi/InElementDecl) so our prevalidator is a
                // 1:1 bijection with `quick-xml`'s `DtdParser::BeforeInternalSubset` (Iter-7 P0-A1).
                let mut j = i + 9;
                let mut quote: Option<u8> = None;
                let mut closed = false;
                while j < xml.len() {
                    let b = xml[j];
                    if let Some(q) = quote {
                        if b == q {
                            quote = None;
                        }
                    } else {
                        match b {
                            b'"' | b'\'' => quote = Some(b),
                            b'[' => bail!("XML DOCTYPE internal subset is disallowed"),
                            b'<' => bail!("unexpected '<' inside XML DOCTYPE"),
                            b'>' => {
                                closed = true;
                                j += 1;
                                break;
                            }
                            _ => {}
                        }
                    }
                    j += 1;
                }
                if !closed {
                    bail!("unterminated XML DOCTYPE");
                }
                i = j;
            } else if rest.starts_with(b"<!") {
                bail!("unsupported XML declaration");
            } else if rest.starts_with(b"</") {
                // Reject quotes and `<` inside closing tags (illegal in XML 1.0 `ETag ::= '</' Name S? '>'`),
                // eliminating `quick-xml 0.41.0` ElementParser quote-desync bypasses like `</a="><!--":array>`
                // (Iter-8 P0-A1).
                let mut end_rel = None;
                for (off, &b) in rest[2..].iter().enumerate() {
                    match b {
                        b'"' | b'\'' | b'<' => {
                            bail!("invalid character inside XML closing tag");
                        }
                        b'>' => {
                            end_rel = Some(off);
                            break;
                        }
                        _ => {}
                    }
                }
                let end = end_rel.ok_or_else(|| anyhow!("unterminated XML closing tag"))?;
                if depth == 0 {
                    bail!("unbalanced XML closing tag");
                }
                depth -= 1;
                i += 2 + end + 1;
            } else {
                let mut j = i + 1;
                let mut quote: Option<u8> = None;
                // Strictly track whether the immediately preceding byte before `>` was an unquoted `/`
                // (1:1 bijection with `quick-xml`'s `strip_suffix(b"/>")`, blocking `<array / >`
                // whitespace-separated self-closing spoofing; Iter-7 P1-A2).
                let mut prev_was_unquoted_slash = false;
                let mut closed = false;
                while j < xml.len() {
                    let b = xml[j];
                    if let Some(q) = quote {
                        if b == b'<' {
                            bail!("unexpected '<' inside XML attribute value");
                        }
                        if b == q {
                            quote = None;
                        }
                        prev_was_unquoted_slash = false;
                    } else {
                        match b {
                            b'"' | b'\'' => {
                                quote = Some(b);
                                prev_was_unquoted_slash = false;
                            }
                            b'<' => bail!("unexpected '<' inside XML start tag"),
                            b'>' => {
                                closed = true;
                                j += 1;
                                break;
                            }
                            b'/' => prev_was_unquoted_slash = true,
                            _ => prev_was_unquoted_slash = false,
                        }
                    }
                    j += 1;
                }
                if !closed {
                    bail!("unterminated XML start tag");
                }
                elements += 1;
                if elements > MAX_NODES {
                    bail!("XML plist element budget exceeded");
                }
                if !prev_was_unquoted_slash {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        bail!("XML plist nesting depth exceeded");
                    }
                }
                i = j;
            }
        }
        if depth != 0 {
            bail!("unclosed XML element");
        }
        Ok(false)
    }
}

/// Decode an Apple `NSKeyedArchiver` binary (or XML) plist into an `ArchivedValue`.
/// Enforces depth (`<= 64`), total decoded node budget (`<= 16_384`), total materialized byte
/// budget (`<= 2 MiB`), and active-path cycle detection at BOTH the raw `bplist00`/XML layer
/// and the `$objects` UID graph layer.
pub fn unarchive(bytes: &[u8]) -> Result<ArchivedValue> {
    const MAX_DECODED_NODES: usize = 16_384;
    const MAX_DECODED_BYTES: usize = 2 * 1024 * 1024;
    let is_binary = prevalidate_plist_bytes(bytes)?;
    let root_val = if is_binary {
        Value::from_reader(Cursor::new(bytes))
    } else {
        Value::from_reader_xml(Cursor::new(bytes))
    }
    .context("failed to parse NSKeyedArchiver plist")?;
    let top_dict = root_val
        .as_dictionary()
        .ok_or_else(|| anyhow!("NSKeyedArchiver root is not a dictionary"))?;

    let objects = top_dict
        .get("$objects")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("missing $objects in NSKeyedArchiver"))?;

    let top = top_dict
        .get("$top")
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| anyhow!("missing $top in NSKeyedArchiver"))?;

    let root_uid = top
        .get("root")
        .and_then(|v| v.as_uid())
        .or_else(|| top.values().find_map(|v| v.as_uid()))
        .ok_or_else(|| anyhow!("missing root UID in $top"))?;

    let mut budget = DecodeBudget {
        nodes: MAX_DECODED_NODES,
        bytes: MAX_DECODED_BYTES,
    };
    let mut visiting = std::collections::HashSet::new();
    resolve_uid(objects, root_uid.get() as usize, 0, &mut budget, &mut visiting)
}

struct DecodeBudget {
    nodes: usize,
    bytes: usize,
}

impl DecodeBudget {
    fn consume_node(&mut self, depth: usize) -> Result<()> {
        if depth > 64 {
            bail!("NSKeyedArchiver recursion depth exceeded");
        }
        if self.nodes == 0 {
            bail!("NSKeyedArchiver decoded node budget exceeded");
        }
        self.nodes -= 1;
        Ok(())
    }

    fn consume_bytes(&mut self, len: usize) -> Result<()> {
        if len > self.bytes {
            bail!("NSKeyedArchiver decoded byte budget exceeded");
        }
        self.bytes -= len;
        Ok(())
    }
}

fn resolve_uid(
    objects: &[Value],
    idx: usize,
    depth: usize,
    budget: &mut DecodeBudget,
    visiting: &mut std::collections::HashSet<usize>,
) -> Result<ArchivedValue> {
    budget.consume_node(depth)?;
    if !visiting.insert(idx) {
        bail!("NSKeyedArchiver cycle detected at UID {idx}");
    }
    let res = match objects.get(idx) {
        Some(val) => decode_value(objects, val, depth + 1, budget, visiting),
        None => Err(anyhow!("UID {idx} out of bounds (len {})", objects.len())),
    };
    visiting.remove(&idx);
    res
}

fn decode_value(
    objects: &[Value],
    val: &Value,
    depth: usize,
    budget: &mut DecodeBudget,
    visiting: &mut std::collections::HashSet<usize>,
) -> Result<ArchivedValue> {
    budget.consume_node(depth)?;
    match val {
        Value::Uid(u) => resolve_uid(objects, u.get() as usize, depth, budget, visiting),
        Value::Boolean(b) => Ok(ArchivedValue::Bool(*b)),
        Value::Integer(i) => {
            if let Some(s) = i.as_signed() {
                Ok(ArchivedValue::Int(s))
            } else if let Some(u) = i.as_unsigned() {
                Ok(ArchivedValue::Uint(u))
            } else {
                Ok(ArchivedValue::Int(0))
            }
        }
        Value::Real(f) => Ok(ArchivedValue::Real(*f)),
        Value::String(s) => {
            if s == "$null" {
                Ok(ArchivedValue::Null)
            } else {
                budget.consume_bytes(s.len())?;
                Ok(ArchivedValue::String(s.clone()))
            }
        }
        Value::Data(d) => {
            budget.consume_bytes(d.len())?;
            Ok(ArchivedValue::Data(d.clone()))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len().min(budget.nodes));
            for item in arr {
                out.push(decode_value(objects, item, depth + 1, budget, visiting)?);
            }
            Ok(ArchivedValue::Array(out))
        }
        Value::Dictionary(dict) => decode_object_dict(objects, dict, depth, budget, visiting),
        Value::Date(_) => Ok(ArchivedValue::Date(now_apple_secs())),
        _ => Ok(ArchivedValue::Null),
    }
}

fn read_class_info(
    objects: &[Value],
    class_uid: usize,
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<(String, Vec<String>)> {
    const MAX_CLASSES_LEN: usize = 64;
    let Some(Value::Dictionary(cls_dict)) = objects.get(class_uid) else {
        return Ok((String::new(), Vec::new()));
    };
    budget.consume_node(depth)?;
    let name = cls_dict
        .get("$classname")
        .and_then(|v| v.as_string())
        .unwrap_or("");
    budget.consume_bytes(name.len())?;
    let mut classes = Vec::new();
    if let Some(arr) = cls_dict.get("$classes").and_then(|v| v.as_array()) {
        if arr.len() > MAX_CLASSES_LEN {
            bail!("NSKeyedArchiver $classes array too large ({})", arr.len());
        }
        classes.reserve(arr.len());
        for v in arr {
            budget.consume_node(depth)?;
            if let Some(s) = v.as_string() {
                budget.consume_bytes(s.len())?;
                classes.push(s.to_string());
            }
        }
    }
    Ok((name.to_string(), classes))
}

fn decode_object_dict(
    objects: &[Value],
    dict: &Dictionary,
    depth: usize,
    budget: &mut DecodeBudget,
    visiting: &mut std::collections::HashSet<usize>,
) -> Result<ArchivedValue> {
    let (class_name, classes) = match dict.get("$class").and_then(|v| v.as_uid()) {
        Some(u) => read_class_info(objects, u.get() as usize, depth, budget)?,
        None => (String::new(), Vec::new()),
    };

    let has_class = |name: &str| class_name == name || classes.iter().any(|c| c == name);

    if has_class("NSDate") {
        let t = dict
            .get("NS.time")
            .and_then(|v| v.as_real())
            .unwrap_or(0.0);
        return Ok(ArchivedValue::Date(t));
    }

    if has_class("NSString") || has_class("NSMutableString") {
        if let Some(s) = dict.get("NS.string").and_then(|v| v.as_string()) {
            budget.consume_bytes(s.len())?;
            return Ok(ArchivedValue::String(s.to_string()));
        }
    }

    if has_class("NSData") || has_class("NSMutableData") {
        if let Some(d) = dict.get("NS.data").and_then(|v| v.as_data()) {
            budget.consume_bytes(d.len())?;
            return Ok(ArchivedValue::Data(d.to_vec()));
        }
    }

    if has_class("NSDictionary") || has_class("NSMutableDictionary") {
        let mut map = BTreeMap::new();
        if let (Some(keys), Some(vals)) = (
            dict.get("NS.keys").and_then(|v| v.as_array()),
            dict.get("NS.objects").and_then(|v| v.as_array()),
        ) {
            for (k_raw, v_raw) in keys.iter().zip(vals.iter()) {
                let k_dec = decode_value(objects, k_raw, depth + 1, budget, visiting)?;
                let v_dec = decode_value(objects, v_raw, depth + 1, budget, visiting)?;
                let key_str = match k_dec {
                    ArchivedValue::String(s) => s,
                    ArchivedValue::Int(i) => i.to_string(),
                    ArchivedValue::Uint(u) => u.to_string(),
                    ArchivedValue::Bool(b) => b.to_string(),
                    ArchivedValue::Real(f) => format!("{f}"),
                    ArchivedValue::Data(d) => {
                        let s = format!("<data:{}>", d.len());
                        budget.consume_bytes(s.len())?;
                        s
                    }
                    _ => {
                        let s = "<non-string-key>".to_string();
                        budget.consume_bytes(s.len())?;
                        s
                    }
                };
                map.insert(key_str, v_dec);
            }
        }
        return Ok(ArchivedValue::Dict(map));
    }

    if has_class("NSSet") || has_class("NSMutableSet") {
        let mut out = Vec::new();
        if let Some(objs) = dict.get("NS.objects").and_then(|v| v.as_array()) {
            for item in objs {
                out.push(decode_value(objects, item, depth + 1, budget, visiting)?);
            }
        }
        return Ok(ArchivedValue::Set(out));
    }

    if has_class("NSArray") || has_class("NSMutableArray") {
        let mut out = Vec::new();
        if let Some(objs) = dict.get("NS.objects").and_then(|v| v.as_array()) {
            for item in objs {
                out.push(decode_value(objects, item, depth + 1, budget, visiting)?);
            }
        }
        return Ok(ArchivedValue::Array(out));
    }

    if has_class("NSNull") {
        return Ok(ArchivedValue::Null);
    }

    // Generic ObjC keyed-archived object (e.g. MSMMessagePacket, MSMTouchEvent, MSMTouch, ...)
    let mut fields = BTreeMap::new();
    for (k, v) in dict {
        if k == "$class" {
            continue;
        }
        budget.consume_bytes(k.len())?;
        fields.insert(k.clone(), decode_value(objects, v, depth + 1, budget, visiting)?);
    }
    Ok(ArchivedValue::Object {
        class_name,
        classes,
        fields,
    })
}

/// Encoder that constructs a valid Apple `NSKeyedArchiver` binary plist (`bplist00`).
pub struct KeyedArchiver {
    objects: Vec<Value>,
    class_cache: BTreeMap<String, u64>,
}

impl KeyedArchiver {
    pub fn new() -> Self {
        Self {
            objects: vec![Value::String("$null".to_string())],
            class_cache: BTreeMap::new(),
        }
    }

    fn push_obj(&mut self, val: Value) -> u64 {
        let idx = self.objects.len() as u64;
        self.objects.push(val);
        idx
    }

    fn intern_class(&mut self, class_name: &str, classes: &[String]) -> u64 {
        if let Some(&idx) = self.class_cache.get(class_name) {
            return idx;
        }
        let mut d = Dictionary::new();
        d.insert("$classname".to_string(), Value::String(class_name.to_string()));
        let cls_arr: Vec<Value> = if classes.is_empty() {
            vec![
                Value::String(class_name.to_string()),
                Value::String("NSObject".to_string()),
            ]
        } else {
            classes.iter().map(|s| Value::String(s.clone())).collect()
        };
        d.insert("$classes".to_string(), Value::Array(cls_arr));
        let idx = self.push_obj(Value::Dictionary(d));
        self.class_cache.insert(class_name.to_string(), idx);
        idx
    }

    /// Encode an `ArchivedValue` as an entry in `$objects` and return its UID.
    pub fn encode_value(&mut self, val: &ArchivedValue) -> u64 {
        match val {
            ArchivedValue::Null => 0,
            ArchivedValue::Bool(b) => self.push_obj(Value::Boolean(*b)),
            ArchivedValue::Int(i) => self.push_obj(Value::Integer((*i).into())),
            ArchivedValue::Uint(u) => self.push_obj(Value::Integer((*u).into())),
            ArchivedValue::Real(f) => self.push_obj(Value::Real(*f)),
            ArchivedValue::String(s) => self.push_obj(Value::String(s.clone())),
            ArchivedValue::Data(bytes) => self.push_obj(Value::Data(bytes.clone())),
            ArchivedValue::Date(ns_time) => {
                let slot = self.push_obj(Value::Boolean(false)); // placeholder to keep root at UID 1
                let cls_uid = self.intern_class(
                    "NSDate",
                    &["NSDate".to_string(), "NSObject".to_string()],
                );
                let mut d = Dictionary::new();
                d.insert("$class".to_string(), Value::Uid(Uid::new(cls_uid)));
                d.insert("NS.time".to_string(), Value::Real(*ns_time));
                self.objects[slot as usize] = Value::Dictionary(d);
                slot
            }
            ArchivedValue::Dict(map) => {
                let slot = self.push_obj(Value::Boolean(false));
                let mut key_uids = Vec::with_capacity(map.len());
                let mut val_uids = Vec::with_capacity(map.len());
                for (k, v) in map {
                    let ku = self.push_obj(Value::String(k.clone()));
                    let vu = self.encode_value(v);
                    key_uids.push(Value::Uid(Uid::new(ku)));
                    val_uids.push(Value::Uid(Uid::new(vu)));
                }
                let cls_uid = self.intern_class(
                    "NSDictionary",
                    &["NSDictionary".to_string(), "NSObject".to_string()],
                );
                let mut d = Dictionary::new();
                d.insert("$class".to_string(), Value::Uid(Uid::new(cls_uid)));
                d.insert("NS.keys".to_string(), Value::Array(key_uids));
                d.insert("NS.objects".to_string(), Value::Array(val_uids));
                self.objects[slot as usize] = Value::Dictionary(d);
                slot
            }
            ArchivedValue::Array(items) => {
                let slot = self.push_obj(Value::Boolean(false));
                let uids: Vec<Value> = items
                    .iter()
                    .map(|it| Value::Uid(Uid::new(self.encode_value(it))))
                    .collect();
                let cls_uid = self.intern_class(
                    "NSArray",
                    &["NSArray".to_string(), "NSObject".to_string()],
                );
                let mut d = Dictionary::new();
                d.insert("$class".to_string(), Value::Uid(Uid::new(cls_uid)));
                d.insert("NS.objects".to_string(), Value::Array(uids));
                self.objects[slot as usize] = Value::Dictionary(d);
                slot
            }
            ArchivedValue::Set(items) => {
                let slot = self.push_obj(Value::Boolean(false));
                let uids: Vec<Value> = items
                    .iter()
                    .map(|it| Value::Uid(Uid::new(self.encode_value(it))))
                    .collect();
                let cls_uid = self.intern_class(
                    "NSSet",
                    &["NSSet".to_string(), "NSObject".to_string()],
                );
                let mut d = Dictionary::new();
                d.insert("$class".to_string(), Value::Uid(Uid::new(cls_uid)));
                d.insert("NS.objects".to_string(), Value::Array(uids));
                self.objects[slot as usize] = Value::Dictionary(d);
                slot
            }
            ArchivedValue::Object {
                class_name,
                classes,
                fields,
            } => {
                let slot = self.push_obj(Value::Boolean(false));
                let mut d = Dictionary::new();
                for (k, v) in fields {
                    // Primitive numeric fields on custom NSCoding objects (encodeInt64/encodeDouble)
                    // are stored inline in the object dict, whereas encodeObject stores a UID.
                    // Caller marks inline primitives via `encode_custom_object` when needed;
                    // for generic ArchivedValue::Object, store object refs except known primitive keys.
                    if is_inline_primitive_field(class_name, k) {
                        match v {
                            ArchivedValue::Int(i) => {
                                d.insert(k.clone(), Value::Integer((*i).into()));
                            }
                            ArchivedValue::Uint(u) => {
                                d.insert(k.clone(), Value::Integer((*u).into()));
                            }
                            ArchivedValue::Real(f) => {
                                d.insert(k.clone(), Value::Real(*f));
                            }
                            ArchivedValue::Bool(b) => {
                                d.insert(k.clone(), Value::Boolean(*b));
                            }
                            _ => {
                                let uid = self.encode_value(v);
                                d.insert(k.clone(), Value::Uid(Uid::new(uid)));
                            }
                        }
                    } else {
                        let uid = self.encode_value(v);
                        d.insert(k.clone(), Value::Uid(Uid::new(uid)));
                    }
                }
                let cls_uid = self.intern_class(class_name, classes);
                d.insert("$class".to_string(), Value::Uid(Uid::new(cls_uid)));
                self.objects[slot as usize] = Value::Dictionary(d);
                slot
            }
        }
    }

    pub fn finish_binary(mut self, root: &ArchivedValue) -> Result<Vec<u8>> {
        let root_uid = self.encode_value(root);
        let mut top = Dictionary::new();
        top.insert("root".to_string(), Value::Uid(Uid::new(root_uid)));

        let mut archive = Dictionary::new();
        archive.insert("$version".to_string(), Value::Integer(100_000i64.into()));
        archive.insert(
            "$archiver".to_string(),
            Value::String("NSKeyedArchiver".to_string()),
        );
        archive.insert("$top".to_string(), Value::Dictionary(top));
        archive.insert("$objects".to_string(), Value::Array(self.objects));

        let mut out = Vec::new();
        Value::Dictionary(archive)
            .to_writer_binary(&mut out)
            .context("failed to write NSKeyedArchiver bplist00")?;
        Ok(out)
    }
}

fn is_inline_primitive_field(class_name: &str, key: &str) -> bool {
    match class_name {
        "MSMMessagePacket" => matches!(key, "type" | "subtype"),
        "MSMTouchEvent" => matches!(key, "_type" | "_subtype" | "_touchPhase" | "_timestamp"),
        "MSMTouch" => matches!(
            key,
            "_timestamp"
                | "_phase"
                | "_tapCount"
                | "_location.x"
                | "_location.y"
                | "_previousLocation.x"
                | "_previousLocation.y"
        ),
        "MSMKeyboardEvent" => matches!(key, "value" | "specialValue" | "_timestamp"),
        "MSMWheelEvent" => matches!(key, "value" | "_timestamp"),
        "MSMWheelXYEvent" => matches!(key, "value" | "valueX" | "valueY" | "_timestamp"),
        _ => false,
    }
}

pub fn archive(root: &ArchivedValue) -> Result<Vec<u8>> {
    KeyedArchiver::new().finish_binary(root)
}

impl Default for KeyedArchiver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_archive_roundtrip_packet_and_dict() {
        let mut info = BTreeMap::new();
        info.insert("isAccess".to_string(), ArchivedValue::Bool(true));
        info.insert("reason".to_string(), ArchivedValue::Int(0));
        info.insert(
            "serverVersion".to_string(),
            ArchivedValue::String("3.3.0.18".to_string()),
        );

        let mut fields = BTreeMap::new();
        fields.insert("dateCreatePacket".to_string(), ArchivedValue::Date(123.5));
        fields.insert("dateEndWaitRequest".to_string(), ArchivedValue::Date(123.5));
        fields.insert("type".to_string(), ArchivedValue::Int(0));
        fields.insert("subtype".to_string(), ArchivedValue::Int(0));
        fields.insert(
            "nameMethod".to_string(),
            ArchivedValue::String("AccessConfirmed".to_string()),
        );
        fields.insert("paramObject".to_string(), ArchivedValue::Dict(info.clone()));
        fields.insert("resultObject".to_string(), ArchivedValue::Null);

        let pkt = ArchivedValue::Object {
            class_name: "MSMMessagePacket".to_string(),
            classes: vec!["MSMMessagePacket".to_string(), "NSObject".to_string()],
            fields,
        };

        let bytes = archive(&pkt).unwrap();
        assert_eq!(&bytes[0..8], b"bplist00");
        let decoded = unarchive(&bytes).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hostile_nskeyedarchiver_cycles_diamond_dag_and_deep_chains_fail_fast() {
        use std::time::Instant;

        fn encode_raw_archive(objects: Vec<Value>, root_uid: u64) -> Vec<u8> {
            let mut top = Dictionary::new();
            top.insert("root".to_string(), Value::Uid(Uid::new(root_uid)));
            let mut root = Dictionary::new();
            root.insert("$version".to_string(), Value::Integer(100000i64.into()));
            root.insert("$archiver".to_string(), Value::String("NSKeyedArchiver".to_string()));
            root.insert("$top".to_string(), Value::Dictionary(top));
            root.insert("$objects".to_string(), Value::Array(objects));
            let mut out = Vec::new();
            Value::Dictionary(root).to_writer_binary(&mut out).unwrap();
            out
        }

        // 1) Self-cycle: obj[1] = [Uid(1)]
        let self_cycle = encode_raw_archive(
            vec![Value::String("$null".into()), Value::Array(vec![Value::Uid(Uid::new(1))])],
            1,
        );
        let t0 = Instant::now();
        assert!(unarchive(&self_cycle).is_err(), "self-cycle must error");
        assert!(t0.elapsed().as_millis() < 200);

        // 2) Branching 2-node cycle: obj[1] = [Uid(1), Uid(1)] (previously 2^32 blowup!)
        let branch_cycle = encode_raw_archive(
            vec![
                Value::String("$null".into()),
                Value::Array(vec![Value::Uid(Uid::new(1)), Value::Uid(Uid::new(1))]),
            ],
            1,
        );
        let t1 = Instant::now();
        assert!(unarchive(&branch_cycle).is_err(), "branching cycle must error");
        assert!(t1.elapsed().as_millis() < 200);

        // 3) 25-level diamond DAG (2^25 = 33M nodes if unbudgeted, <500B on wire!)
        let mut dag = vec![Value::String("$null".into())];
        for i in 1..=25u64 {
            dag.push(Value::Array(vec![
                Value::Uid(Uid::new(i + 1)),
                Value::Uid(Uid::new(i + 1)),
            ]));
        }
        dag.push(Value::String("leaf".into()));
        let diamond_dag = encode_raw_archive(dag, 1);
        let t2 = Instant::now();
        assert!(unarchive(&diamond_dag).is_err(), "diamond DAG must trip node budget");
        assert!(t2.elapsed().as_millis() < 200);

        // 4) Out-of-bounds UID
        let oob = encode_raw_archive(vec![Value::String("$null".into())], 99);
        assert!(unarchive(&oob).is_err(), "out-of-bounds UID must error");

        // 5) P1-A3: Large-leaf byte amplification (50 KiB string referenced 100 times -> 5 MiB > 2 MiB budget)
        let big_str = "A".repeat(50 * 1024);
        let refs: Vec<Value> = (0..100).map(|_| Value::Uid(Uid::new(2))).collect();
        let leaf_amp = encode_raw_archive(
            vec![
                Value::String("$null".into()),
                Value::Array(refs),
                Value::String(big_str),
            ],
            1,
        );
        let t3 = Instant::now();
        assert!(
            unarchive(&leaf_amp).is_err(),
            "large-leaf UID amplification must trip decoded byte budget"
        );
        assert!(t3.elapsed().as_millis() < 200);

        // 6) P1-A3: Oversized $classes array (>64 entries) must fail fast
        let mut cls_dict = Dictionary::new();
        cls_dict.insert("$classname".to_string(), Value::String("EvilClass".into()));
        cls_dict.insert(
            "$classes".to_string(),
            Value::Array((0..128).map(|_| Value::String("NSObject".into())).collect()),
        );
        let mut obj_dict = Dictionary::new();
        obj_dict.insert("$class".to_string(), Value::Uid(Uid::new(2)));
        let evil_cls = encode_raw_archive(
            vec![
                Value::String("$null".into()),
                Value::Dictionary(obj_dict),
                Value::Dictionary(cls_dict),
            ],
            1,
        );
        assert!(
            unarchive(&evil_cls).is_err(),
            "oversized $classes array must be rejected"
        );

        // 7) P0-A1: Raw bplist00 28-level diamond DAG (158 bytes -> 2^28 nodes inside plist::Value::from_reader!)
        fn build_raw_bplist(raw_objs: &[Vec<u8>], top_obj: u64) -> Vec<u8> {
            let mut out = Vec::from(&b"bplist00"[..]);
            let mut offsets: Vec<u32> = Vec::with_capacity(raw_objs.len());
            for obj in raw_objs {
                offsets.push(out.len() as u32);
                out.extend_from_slice(obj);
            }
            let offset_table_offset = out.len() as u64;
            for off in &offsets {
                out.extend_from_slice(&off.to_be_bytes());
            }
            // 32-byte trailer: 6 unused, offset_int_size=4, object_ref_size=2, num_objects, top_object, offset_table_offset
            out.extend_from_slice(&[0u8; 6]);
            out.push(4);
            out.push(2);
            out.extend_from_slice(&(raw_objs.len() as u64).to_be_bytes());
            out.extend_from_slice(&top_obj.to_be_bytes());
            out.extend_from_slice(&offset_table_offset.to_be_bytes());
            out
        }
        let mut dag_objs = Vec::new();
        for i in 0..28u16 {
            let next = (i + 1).to_be_bytes();
            dag_objs.push(vec![0xA2, next[0], next[1], next[0], next[1]]); // Array[ref(i+1), ref(i+1)]
        }
        dag_objs.push(vec![0x54, b'b', b'o', b'o', b'm']); // ASCII "boom"
        let raw_dag = build_raw_bplist(&dag_objs, 0);
        let t4 = Instant::now();
        assert!(
            unarchive(&raw_dag).is_err(),
            "P0-A1: raw bplist00 28-level diamond DAG must fail fast before plist::Value::from_reader"
        );
        assert!(t4.elapsed().as_millis() < 100);

        // 8) P0-A1: Raw bplist00 2-level leaf amplification (1000 x 1000 x 40 KiB = 40 GiB!)
        let mut arr1000 = vec![0xAF, 0x11, 0x03, 0xE8]; // Array of 1000 items (2-byte length 0x03E8)
        for _ in 0..1000 {
            arr1000.extend_from_slice(&1u16.to_be_bytes());
        }
        let mut arr1000_leaf = vec![0xAF, 0x11, 0x03, 0xE8];
        for _ in 0..1000 {
            arr1000_leaf.extend_from_slice(&2u16.to_be_bytes());
        }
        let mut data40k = vec![0x4F, 0x11, 0x9C, 0x40]; // Data of 40000 bytes
        data40k.resize(4 + 40_000, 0x41);
        let raw_amp = build_raw_bplist(&[arr1000, arr1000_leaf, data40k], 0);
        let t5 = Instant::now();
        assert!(
            unarchive(&raw_amp).is_err(),
            "P0-A1: raw bplist00 2-level leaf amplification bomb must fail fast"
        );
        assert!(t5.elapsed().as_millis() < 100);

        // 9) P0-A1: Deep XML plist nesting (200 nested <array> tags) must fail fast
        let mut deep_xml = String::from("<?xml version=\"1.0\"?><plist version=\"1.0\">");
        for _ in 0..200 {
            deep_xml.push_str("<array>");
        }
        for _ in 0..200 {
            deep_xml.push_str("</array>");
        }
        deep_xml.push_str("</plist>");
        assert!(
            unarchive(deep_xml.as_bytes()).is_err(),
            "P0-A1: deep XML plist nesting must be rejected before plist::Value::from_reader"
        );

        // 10) Iter-6 P0-A1: Legacy OpenStep ASCII plist (`((((...))))` and `{a = ...;}`) MUST be
        //     rejected before reaching `plist::stream::AsciiReader` (prevents SIGABRT stack overflow).
        let mut ascii_deep = Vec::with_capacity(24_000);
        ascii_deep.resize(12_000, b'(');
        ascii_deep.resize(24_000, b')');
        let t6 = Instant::now();
        let err_ascii = unarchive(&ascii_deep).unwrap_err().to_string();
        assert!(
            err_ascii.contains("unsupported plist format"),
            "Iter-6 P0-A1: legacy ASCII array plist must fail in prevalidator, got: {err_ascii}"
        );
        assert!(t6.elapsed().as_millis() < 100);
        assert!(unarchive(b"{ a = (1, 2, 3); }").is_err());

        // 11) Iter-6 P0-A2: XML quoted-attribute `/>` depth bypass (`<array a="/>">`) MUST fail in prevalidator!
        let mut attr_bypass = String::from("<plist version=\"1.0\">");
        for _ in 0..200 {
            attr_bypass.push_str("<array a=\"/>\">");
        }
        for _ in 0..200 {
            attr_bypass.push_str("</array>");
        }
        attr_bypass.push_str("</plist>");
        let err_attr = unarchive(attr_bypass.as_bytes()).unwrap_err().to_string();
        assert!(
            err_attr.contains("nesting depth exceeded"),
            "Iter-6 P0-A2: quoted attribute `/>` must NOT spoof self-closing tag, got: {err_attr}"
        );

        // 12) Iter-6 P0-A2: XML comment `<!-- > </></>... -->` depth-reset bypass MUST fail in prevalidator!
        let mut comment_bypass = String::from("<plist version=\"1.0\">");
        for _ in 0..4 {
            for _ in 0..60 {
                comment_bypass.push_str("<array>");
            }
            comment_bypass.push_str("<!-- >");
            for _ in 0..60 {
                comment_bypass.push_str("</>");
            }
            comment_bypass.push_str("-->");
        }
        for _ in 0..240 {
            comment_bypass.push_str("</array>");
        }
        comment_bypass.push_str("</plist>");
        let err_cmt = unarchive(comment_bypass.as_bytes()).unwrap_err().to_string();
        assert!(
            err_cmt.contains("nesting depth exceeded"),
            "Iter-6 P0-A2: XML comment with fake closing tags must NOT reset depth, got: {err_cmt}"
        );

        // 13) Iter-7 P0-A1: XML DOCTYPE internal subset quote-desync (`<!DOCTYPE plist [<!-- " -->]>`)
        //     MUST be rejected outright before reaching `plist::Value::from_reader_xml`!
        let mut dtd_bypass = String::from("<?xml version=\"1.0\"?><!DOCTYPE plist [<!-- \" -->]><plist>");
        for _ in 0..200 {
            dtd_bypass.push_str("<array>");
        }
        for _ in 0..200 {
            dtd_bypass.push_str("</array>");
        }
        dtd_bypass.push_str("</plist><!-- \" ]> -->");
        let err_dtd = unarchive(dtd_bypass.as_bytes()).unwrap_err().to_string();
        assert!(
            err_dtd.contains("internal subset is disallowed"),
            "Iter-7 P0-A1: DOCTYPE internal subset must be rejected, got: {err_dtd}"
        );

        // 14) Iter-7 P1-A2: XML start-tag `<array / >` (space between `/` and `>`) MUST NOT spoof
        //     self-closing (`quick-xml` treats it as Event::Start)!
        let mut ws_slash_bypass = String::from("<plist version=\"1.0\">");
        for _ in 0..200 {
            ws_slash_bypass.push_str("<array / >");
        }
        for _ in 0..200 {
            ws_slash_bypass.push_str("</array>");
        }
        ws_slash_bypass.push_str("</plist>");
        let err_ws = unarchive(ws_slash_bypass.as_bytes()).unwrap_err().to_string();
        assert!(
            err_ws.contains("nesting depth exceeded"),
            "Iter-7 P1-A2: `<array / >` must count toward depth, got: {err_ws}"
        );

        // 15) Iter-8 P0-A1: XML closing-tag quote-desync (`</a="><!--":array>`, CDATA, PI) MUST be
        //     rejected before reaching `plist::Value::from_reader_xml`!
        for (open_seq, close_seq) in [
            ("<!--", "-->"),
            ("<![CDATA[", "]]>"),
            ("<?", "?>"),
        ] {
            let mut etag_bypass = format!(
                "<plist><array><a=\">{open_seq}\":array></a=\">{open_seq}\":array>"
            );
            for _ in 0..200 {
                etag_bypass.push_str("<array>");
            }
            for _ in 0..200 {
                etag_bypass.push_str("</array>");
            }
            etag_bypass.push_str(&format!("{open_seq} {close_seq}</array></plist>"));
            let err_etag = unarchive(etag_bypass.as_bytes()).unwrap_err().to_string();
            assert!(
                err_etag.contains("unexpected '<'") || err_etag.contains("invalid character"),
                "Iter-8 P0-A1: closing-tag quote-desync ({open_seq}) must fail in prevalidator, got: {err_etag}"
            );
        }
        // Also test direct closing-tag quote without `<` inside start-tag quotes
        assert!(
            unarchive(b"<plist><array></array\" ></plist>").is_err(),
            "Iter-8 P0-A1: quote inside closing tag must be rejected"
        );
    }
}
