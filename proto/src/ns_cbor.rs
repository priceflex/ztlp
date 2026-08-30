//! Minimal CBOR parsing for ZTLP-NS records.
//!
//! Lightweight CBOR map parser that can extract string and integer values.
//! No dependencies, no tokio — usable from both tokio-gated and ios-sync builds.
//!
//! This module exists because `agent/proxy.rs` (which contains the original
//! CBOR helpers) is gated behind the `tokio-runtime` feature and unavailable
//! in ios-sync builds. Rather than duplicate the code, both proxy.rs and
//! the sync NS resolver use this shared module.

/// Extract a string value from a CBOR map by key name.
///
/// Supports CBOR maps (major type 5) with text string keys and values (major type 3).
/// Returns `None` if the map doesn't contain the key or if the value isn't a text string.
pub fn cbor_extract_string(data: &[u8], target_key: &str) -> Option<String> {
    if data.is_empty() {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }

    let mut pos = 0;
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    pos += 1;

    // Must be a map (major type 5)
    if major != 5 {
        eprintln!(
            "DEBUG: parse_ns_record MAP RET None at line {}, major={}",
            line!(),
            major
        );
        return None;
    }

    let (arity, new_pos) = cbor_read_uint(additional, data, pos)?;
    pos = new_pos;

    for _ in 0..arity {
        let (key_str, new_pos) = cbor_read_text(data, pos)?;
        pos = new_pos;
        let (val_str, new_pos) = cbor_read_text(data, pos)?;
        pos = new_pos;

        if key_str == target_key {
            return Some(val_str);
        }
    }

    None
}

/// Extract a u64 value from a CBOR map by key name.
///
/// Supports CBOR maps where values may be unsigned integers (major type 0).
/// Returns `None` if the key isn't found or the value isn't a uint.
pub fn cbor_extract_uint(data: &[u8], target_key: &str) -> Option<u64> {
    if data.is_empty() {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }

    let mut pos = 0;
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    pos += 1;

    if major != 5 {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }

    let (arity, new_pos) = cbor_read_uint(additional, data, pos)?;
    pos = new_pos;

    for _ in 0..arity {
        let (key_str, new_pos) = cbor_read_text(data, pos)?;
        pos = new_pos;
        // Try to read value as text first; if that fails, try as uint
        if let Some((val_str, new_pos2)) = cbor_read_text_raw(data, pos) {
            if key_str == target_key {
                // Text value, but caller wanted uint — try parsing
                if let Ok(n) = val_str.parse::<u64>() {
                    return Some(n);
                }
                eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
                return None;
            }
            pos = new_pos2;
        } else {
            // Try reading as uint (major type 0)
            let val_initial = data.get(pos)?;
            let val_major = val_initial >> 5;
            let val_additional = val_initial & 0x1F;
            if val_major == 0 {
                // Unsigned integer
                let (n, new_pos2) = cbor_read_uint(val_additional, data, pos + 1)?;
                if key_str == target_key {
                    return Some(n as u64);
                }
                pos = new_pos2;
            } else {
                // Skip unknown value type — not text, not uint
                // We can't easily skip arbitrary CBOR, so bail
                eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
                return None;
            }
        }
    }

    None
}

/// Read a CBOR unsigned integer (additional info encoding).
///
/// Returns (value, new_position) or None if the data is too short.
pub fn cbor_read_uint(additional: u8, data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if additional < 24 {
        Some((additional as usize, pos))
    } else if additional == 24 {
        if pos >= data.len() {
            eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
            return None;
        }
        Some((data[pos] as usize, pos + 1))
    } else if additional == 25 {
        if pos + 2 > data.len() {
            eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
            return None;
        }
        let n = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        Some((n, pos + 2))
    } else if additional == 26 {
        if pos + 4 > data.len() {
            eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
            return None;
        }
        let n =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        Some((n, pos + 4))
    } else {
        None
    }
}

/// Read a CBOR text string (major type 3).
///
/// Returns (string, new_position) or None if parsing fails.
pub fn cbor_read_text(data: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos >= data.len() {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    if major != 3 {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }
    let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
    if new_pos + len > data.len() {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }
    let s = std::str::from_utf8(&data[new_pos..new_pos + len]).ok()?;
    Some((s.to_string(), new_pos + len))
}

/// Try to read a CBOR text string at the given position.
/// Returns None if the value at this position is NOT a text string (e.g., it's an integer).
/// Unlike `cbor_read_text`, this doesn't fail for non-text — it just returns None.
fn cbor_read_text_raw(data: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos >= data.len() {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }
    let initial = data[pos];
    let major = initial >> 5;
    if major != 3 {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None; // Not a text string
    }
    let additional = initial & 0x1F;
    let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
    if new_pos + len > data.len() {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }
    let s = std::str::from_utf8(&data[new_pos..new_pos + len]).ok()?;
    Some((s.to_string(), new_pos + len))
}

/// Parse the NS response header and extract the record payload.
///
/// NS response wire format:
///   [0x02 = FOUND] [optional 0x01 truncation flag] [type: u8] [name_len: u16 BE] [name] [data_len: u32 BE] [data: CBOR]
///
/// Returns (record_type, record_name, cbor_data) or None if parsing fails.
/// Also handles NOT_FOUND (0x03) and REVOKED (0x04) responses.
pub fn parse_ns_record(data: &[u8]) -> Option<NsRecordPayload> {
    if data.is_empty() {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }

    let status = data[0];
    match status {
        0x02 => { /* FOUND — continue parsing */ }
        0x03 => {
            // NOT_FOUND
            return Some(NsRecordPayload {
                status: NsResponseStatus::NotFound,
                record_type: 0,
                name: String::new(),
                data: Vec::new(),
            });
        }
        0x04 => {
            // REVOKED
            return Some(NsRecordPayload {
                status: NsResponseStatus::Revoked,
                record_type: 0,
                name: String::new(),
                data: Vec::new(),
            });
        }
        _ => return None,
    }

    // Determine whether byte[1] is a genuine amplification-prevention
    // truncation flag or the record's own type byte (which happens to
    // collide with the flag's value for KEY records, type=1 — see
    // `test_parse_ns_record_key_type_not_confused_with_truncation_flag`
    // for the real bug this caused: every complete, correctly-sized KEY
    // record response was silently shifted by one byte and corrupted).
    //
    // Disambiguate structurally instead of by byte value: try the
    // "no flag, byte[1] is the real type" interpretation FIRST (this is
    // the common case — most responses aren't truncated), and only fall
    // back to the "flag present, skip a byte" interpretation if the
    // first one fails to parse as a structurally valid record (lengths
    // that don't fit the buffer). A genuinely truncated response's name
    // and data lengths won't validate under the no-flag interpretation
    // (they'll overrun the buffer or land on garbage), so this ordering
    // is safe both ways.
    fn try_parse_record_body(record: &[u8]) -> Option<(u8, usize, usize)> {
        if record.len() < 4 {
            return None;
        }
        let record_type = record[0];
        let rname_len = u16::from_be_bytes([record[1], record[2]]) as usize;
        if record.len() < 3 + rname_len + 4 {
            return None;
        }
        let offset = 3 + rname_len;
        let data_len = u32::from_be_bytes([
            record[offset],
            record[offset + 1],
            record[offset + 2],
            record[offset + 3],
        ]) as usize;
        if record.len() < offset + 4 + data_len {
            return None;
        }
        Some((record_type, rname_len, data_len))
    }

    let no_flag_candidate = &data[1..];
    let (record, has_flag) = if try_parse_record_body(no_flag_candidate).is_some() {
        (no_flag_candidate, false)
    } else if data.len() > 1 && data[1] == 0x01 {
        (&data[2..], true)
    } else {
        (no_flag_candidate, false)
    };
    let _ = has_flag; // only used to pick the byte slice above
    if record.len() < 4 {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }

    let record_type = record[0];
    let rname_len = u16::from_be_bytes([record[1], record[2]]) as usize;
    if record.len() < 3 + rname_len + 4 {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }

    let offset = 3 + rname_len;
    let name = std::str::from_utf8(&record[3..3 + rname_len])
        .ok()?
        .to_string();
    let data_len = u32::from_be_bytes([
        record[offset],
        record[offset + 1],
        record[offset + 2],
        record[offset + 3],
    ]) as usize;

    if record.len() < offset + 4 + data_len {
        eprintln!("DEBUG: parse_ns_record RET None at line {}", line!());
        return None;
    }

    let data_start = offset + 4;
    let cbor_data = record[data_start..data_start + data_len].to_vec();

    Some(NsRecordPayload {
        status: NsResponseStatus::Found,
        record_type,
        name,
        data: cbor_data,
    })
}

/// Status of an NS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsResponseStatus {
    Found,
    NotFound,
    Revoked,
}

/// Parsed NS record payload.
#[derive(Debug, Clone)]
pub struct NsRecordPayload {
    pub status: NsResponseStatus,
    pub record_type: u8,
    pub name: String,
    pub data: Vec<u8>, // Raw CBOR data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_extract_string_simple() {
        // CBOR: { "address" => "1.2.3.4:443" }
        let mut cbor = vec![0xA1]; // map(1)
        cbor.push(0x67); // text(7) "address"
        cbor.extend_from_slice(b"address");
        cbor.push(0x6B); // text(11) "1.2.3.4:443"
        cbor.extend_from_slice(b"1.2.3.4:443");

        let result = cbor_extract_string(&cbor, "address");
        assert_eq!(result, Some("1.2.3.4:443".to_string()));
    }

    #[test]
    fn test_cbor_extract_string_missing_key() {
        let mut cbor = vec![0xA1]; // map(1)
        cbor.push(0x64); // text(4) "name"
        cbor.extend_from_slice(b"name");
        cbor.push(0x65); // text(5) "value"
        cbor.extend_from_slice(b"value");

        let result = cbor_extract_string(&cbor, "address");
        assert_eq!(result, None);
    }

    #[test]
    fn test_cbor_extract_string_two_keys() {
        // { "name" => "beta1", "address" => "10.0.0.1:443" }
        let mut cbor = vec![0xA2]; // map(2)
        cbor.push(0x64); // text(4) "name"
        cbor.extend_from_slice(b"name");
        cbor.push(0x65); // text(5) "beta1"
        cbor.extend_from_slice(b"beta1");
        cbor.push(0x67); // text(7) "address"
        cbor.extend_from_slice(b"address");
        cbor.push(0x6C); // text(12) "10.0.0.1:443"
        cbor.extend_from_slice(b"10.0.0.1:443");

        assert_eq!(
            cbor_extract_string(&cbor, "address"),
            Some("10.0.0.1:443".to_string())
        );
        assert_eq!(
            cbor_extract_string(&cbor, "name"),
            Some("beta1".to_string())
        );
    }

    #[test]
    fn test_cbor_read_uint_direct() {
        assert_eq!(cbor_read_uint(5, &[], 0), Some((5, 0)));
        assert_eq!(cbor_read_uint(23, &[], 0), Some((23, 0)));
        assert_eq!(cbor_read_uint(24, &[42], 0), Some((42, 1)));
        assert_eq!(cbor_read_uint(25, &[0, 100], 0), Some((100, 2)));
        assert_eq!(cbor_read_uint(26, &[0, 0, 1, 0], 0), Some((256, 4)));
    }

    #[test]
    fn test_cbor_extract_uint_from_text() {
        // CBOR: { "load" => "75" } — some NS responses encode numbers as strings
        let mut cbor = vec![0xA1]; // map(1)
        cbor.push(0x64); // text(4) "load"
        cbor.extend_from_slice(b"load");
        cbor.push(0x62); // text(2) "75"
        cbor.extend_from_slice(b"75");

        assert_eq!(cbor_extract_uint(&cbor, "load"), Some(75));
    }

    #[test]
    fn test_parse_ns_record_found() {
        // Build a synthetic NS FOUND response for SVC record
        let name = b"beta.techrockstars";
        let cbor_data = {
            let mut c = vec![0xA1]; // map(1)
            c.push(0x67); // text(7) "address"
            c.extend_from_slice(b"address");
            c.push(0x6C); // text(12)
            c.extend_from_slice(b"10.0.0.1:443");
            c
        };

        let mut resp = vec![0x02]; // FOUND
        resp.push(0x02); // record_type = SVC
        resp.extend_from_slice(&(name.len() as u16).to_be_bytes());
        resp.extend_from_slice(name);
        resp.extend_from_slice(&(cbor_data.len() as u32).to_be_bytes());
        resp.extend_from_slice(&cbor_data);

        let record = parse_ns_record(&resp).unwrap();
        assert_eq!(record.status, NsResponseStatus::Found);
        assert_eq!(record.record_type, 0x02);
        assert_eq!(record.name, "beta.techrockstars");
        assert_eq!(
            cbor_extract_string(&record.data, "address"),
            Some("10.0.0.1:443".to_string())
        );
    }

    // ── KEY-record (type=1) / truncation-flag ambiguity bug (2026-08-30) ──
    //
    // Real bug found live against the demo NS server (34.221.165.244:24096):
    // `parse_ns_record`'s truncation-flag detection (`data[1] == 0x01` =>
    // "skip one extra byte, amplification prevention inserted a flag")
    // is genuinely ambiguous with a KEY record, whose record_type byte is
    // ALSO literally 0x01. Every non-truncated KEY record response
    // (`[0x02 FOUND, 0x01 KEY-type, name_len_hi, name_len_lo, name...]`)
    // was being misparsed as `[0x02 FOUND, 0x01 TRUNCATION-FLAG, <real
    // type byte mistaken for name_len_hi>, ...]`, permanently shifting
    // every subsequent field by one byte and corrupting the parsed name,
    // data length, and CBOR payload — even for perfectly complete,
    // correctly-sized responses.
    //
    // This is exactly why `ztlp ns lookup` printed "Type: UNKNOWN / Raw:
    // (truncated record)" for a live, fully-registered KEY record, and
    // why `ns_query_addr`'s KEY fallback couldn't find the "address"
    // field even after the amplification-padding fix: the padding fix
    // (see agent/proxy.rs) got a complete, untruncated response, but this
    // separate parsing bug then corrupted it anyway.
    //
    // The existing `test_parse_ns_record_found` test above never caught
    // this because it exercises a SVC record (type=2), which never
    // collides with the 0x01 truncation-flag value.
    //
    // Fixture: the exact bytes captured from a live, padded (256-byte)
    // query to the demo NS for `web.demo.spongebob.ztlp`'s KEY record —
    // confirmed complete/untruncated (matches ztlp-cli.rs's own
    // NS_QUERY_PAD_BYTES-padded capture, 339 bytes, no continuation
    // needed).
    #[test]
    fn test_parse_ns_record_key_type_not_confused_with_truncation_flag() {
        let real_untruncated_key_response = hex_decode(REAL_UNTRUNCATED_KEY_RESPONSE_HEX);
        let record = parse_ns_record(&real_untruncated_key_response)
            .expect("must parse a real, complete KEY record response");
        assert_eq!(record.status, NsResponseStatus::Found);
        assert_eq!(
            record.record_type, 0x01,
            "record_type must be KEY (1), not misread as a truncation flag"
        );
        assert_eq!(
            record.name, "web.demo.spongebob.ztlp",
            "name must parse correctly once the type byte isn't misidentified \
             as a truncation flag (this is what silently shifted every \
             subsequent field by one byte in the original bug)"
        );
        assert_eq!(
            cbor_extract_string(&record.data, "address"),
            Some("34.221.165.244:24095".to_string()),
            "the address field must be extractable once record.data lines \
             up on the correct byte boundary"
        );
    }

    /// Real capture: a live, PADDED (256-byte query, matching
    /// `NS_QUERY_PAD_BYTES`) response from the demo NS server
    /// (34.221.165.244:24096) for `web.demo.spongebob.ztlp`'s KEY record —
    /// confirmed complete (339 bytes, no amplification truncation).
    const REAL_UNTRUNCATED_KEY_RESPONSE_HEX: &str = "020100177765622e64656d6f2e73706f6e6765626f622e7a746c70000000bca567616464726573737433342e3232312e3136352e3234343a3234303935676e6f64655f69647820316236663535636661383563636630383032393236336433343865366361373769616c676f726974686d67456432353531396a7075626c69635f6b657978403464666533613937353466623466326166326135616134626239636132663139623730376431303262326362366264666435633366636165393739653663646473726567697374657265645f756e7369676e6564f5000000006a93b76900015180000000006a93b76900408339e10261b7135a9b92ed5f3b342b26fb7195a7950392e344eb6e11b8275a2a798cb2ae06391da17aedef3d311fdc01ed4805b42236294decd84eec0ebf8209002073193631c65c8252184a64b419dc1b5007021ba70eb531697f9b816596d986c9";

    fn hex_decode(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_parse_ns_record_not_found() {
        let resp = [0x03]; // NOT_FOUND
        let record = parse_ns_record(&resp).unwrap();
        assert_eq!(record.status, NsResponseStatus::NotFound);
    }

    #[test]
    fn test_parse_ns_record_revoked() {
        let resp = [0x04]; // REVOKED
        let record = parse_ns_record(&resp).unwrap();
        assert_eq!(record.status, NsResponseStatus::Revoked);
    }

    #[test]
    fn test_parse_ns_record_with_truncation_flag() {
        let name = b"test";
        let cbor_data = vec![0xA0]; // empty map

        let mut resp = vec![0x02, 0x01]; // FOUND + truncation flag
        resp.push(0x01); // record_type = KEY
        resp.extend_from_slice(&(name.len() as u16).to_be_bytes());
        resp.extend_from_slice(name);
        resp.extend_from_slice(&(cbor_data.len() as u32).to_be_bytes());
        resp.extend_from_slice(&cbor_data);

        let record = parse_ns_record(&resp).unwrap();
        assert_eq!(record.status, NsResponseStatus::Found);
        assert_eq!(record.record_type, 0x01);
        assert_eq!(record.name, "test");
    }
}
