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
        return None;
    }

    let mut pos = 0;
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    pos += 1;

    // Must be a map (major type 5)
    if major != 5 {
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
        return None;
    }

    let mut pos = 0;
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    pos += 1;

    if major != 5 {
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
            return None;
        }
        Some((data[pos] as usize, pos + 1))
    } else if additional == 25 {
        if pos + 2 > data.len() {
            return None;
        }
        let n = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        Some((n, pos + 2))
    } else if additional == 26 {
        if pos + 4 > data.len() {
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
        return None;
    }
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    if major != 3 {
        return None;
    }
    let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
    if new_pos + len > data.len() {
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
        return None;
    }
    let initial = data[pos];
    let major = initial >> 5;
    if major != 3 {
        return None; // Not a text string
    }
    let additional = initial & 0x1F;
    let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
    if new_pos + len > data.len() {
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

    // Skip optional truncation flag (0x01) inserted by NS amplification prevention.
    let record = if data.len() > 1 && data[1] == 0x01 {
        &data[2..]
    } else {
        &data[1..]
    };
    if record.len() < 4 {
        return None;
    }

    let record_type = record[0];
    let rname_len = u16::from_be_bytes([record[1], record[2]]) as usize;
    if record.len() < 3 + rname_len + 4 {
        return None;
    }

    let offset = 3 + rname_len;
    let name = std::str::from_utf8(&record[3..3 + rname_len]).ok()?.to_string();
    let data_len = u32::from_be_bytes([
        record[offset],
        record[offset + 1],
        record[offset + 2],
        record[offset + 3],
    ]) as usize;

    if record.len() < offset + 4 + data_len {
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
        assert_eq!(
            cbor_read_uint(26, &[0, 0, 1, 0], 0),
            Some((256, 4))
        );
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
