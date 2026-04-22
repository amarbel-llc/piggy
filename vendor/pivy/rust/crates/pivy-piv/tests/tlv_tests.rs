use pivy_piv::tlv::{TlvReader, TlvWriter};

#[test]
fn decode_single_tag() {
    // Tag 0x53 (PIV data object), length 3, value [0x01, 0x02, 0x03]
    let data = [0x53, 0x03, 0x01, 0x02, 0x03];
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x53);
    let value = reader.read_value().unwrap();
    assert_eq!(value, &[0x01, 0x02, 0x03]);
}

#[test]
fn decode_two_byte_length() {
    // Tag 0x53, length 0x81 0x80 (128 bytes), value = 128 zeros
    let mut data = vec![0x53, 0x81, 0x80];
    data.extend(vec![0x00; 128]);
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x53);
    let value = reader.read_value().unwrap();
    assert_eq!(value.len(), 128);
}

#[test]
fn decode_three_byte_length() {
    // Tag 0x53, length 0x82 0x01 0x00 (256 bytes)
    let mut data = vec![0x53, 0x82, 0x01, 0x00];
    data.extend(vec![0xAA; 256]);
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x53);
    let value = reader.read_value().unwrap();
    assert_eq!(value.len(), 256);
    assert!(value.iter().all(|&b| b == 0xAA));
}

#[test]
fn decode_multi_byte_tag() {
    // Multi-byte tag: first byte has lower 5 bits all set (0x1F mask),
    // then continuation bytes with bit 7 set, final byte without bit 7.
    // Tag 0x5F2F = two-byte tag: 0x5F (class+constructed+0x1F), 0x2F
    let data = [0x5F, 0x2F, 0x02, 0xAB, 0xCD];
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x5F2F);
    let value = reader.read_value().unwrap();
    assert_eq!(value, &[0xAB, 0xCD]);
}

#[test]
fn decode_zero_length() {
    let data = [0x01, 0x00];
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x01);
    let value = reader.read_value().unwrap();
    assert_eq!(value.len(), 0);
}

#[test]
fn decode_nested_tags() {
    // Outer tag 0x01 containing two inner tags: 0xA1 (len 1, val 0x00) and 0xA2 (len 2, val AB CD)
    let data = [0x01, 0x07, 0xA1, 0x01, 0x00, 0xA2, 0x02, 0xAB, 0xCD];
    let mut reader = TlvReader::new(&data);

    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x01);
    let inner = reader.read_value().unwrap();

    // Parse inner TLV
    let mut inner_reader = TlvReader::new(inner);
    let tag1 = inner_reader.read_tag().unwrap();
    assert_eq!(tag1, 0xA1);
    let val1 = inner_reader.read_value().unwrap();
    assert_eq!(val1, &[0x00]);

    let tag2 = inner_reader.read_tag().unwrap();
    assert_eq!(tag2, 0xA2);
    let val2 = inner_reader.read_value().unwrap();
    assert_eq!(val2, &[0xAB, 0xCD]);

    assert!(!inner_reader.has_remaining());
}

#[test]
fn decode_truncated_value_fails() {
    // Tag 0x53, claims length 10 but only 3 bytes of data
    let data = [0x53, 0x0A, 0x01, 0x02, 0x03];
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x53);
    assert!(reader.read_value().is_err());
}

#[test]
fn decode_truncated_length_fails() {
    // Tag 0x53, 0x82 says 2 more length bytes but only 1 follows
    let data = [0x53, 0x82, 0x01];
    let mut reader = TlvReader::new(&data);
    let _tag = reader.read_tag().unwrap();
    assert!(reader.read_value().is_err());
}

#[test]
fn decode_empty_fails() {
    let data = [];
    let mut reader = TlvReader::new(&data);
    assert!(reader.read_tag().is_err());
}

#[test]
fn encode_single_tag() {
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0x53, &[0x01, 0x02, 0x03]);
    assert_eq!(writer.as_bytes(), &[0x53, 0x03, 0x01, 0x02, 0x03]);
}

#[test]
fn encode_two_byte_length() {
    let value = vec![0x00; 128];
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0x53, &value);
    let bytes = writer.as_bytes();
    assert_eq!(bytes[0], 0x53);
    assert_eq!(bytes[1], 0x81);
    assert_eq!(bytes[2], 0x80);
    assert_eq!(bytes.len(), 3 + 128);
}

#[test]
fn encode_three_byte_length() {
    let value = vec![0x00; 256];
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0x53, &value);
    let bytes = writer.as_bytes();
    assert_eq!(bytes[0], 0x53);
    assert_eq!(bytes[1], 0x82);
    assert_eq!(bytes[2], 0x01);
    assert_eq!(bytes[3], 0x00);
    assert_eq!(bytes.len(), 4 + 256);
}

#[test]
fn encode_multi_byte_tag() {
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0x5F2F, &[0xAB, 0xCD]);
    assert_eq!(writer.as_bytes(), &[0x5F, 0x2F, 0x02, 0xAB, 0xCD]);
}

#[test]
fn encode_zero_length() {
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0x01, &[]);
    assert_eq!(writer.as_bytes(), &[0x01, 0x00]);
}

#[test]
fn roundtrip_single() {
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0xA2, &[0x01, 0x02, 0x03, 0x04]);
    let encoded = writer.as_bytes();

    let mut reader = TlvReader::new(encoded);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0xA2);
    let value = reader.read_value().unwrap();
    assert_eq!(value, &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn roundtrip_multi_byte_tag() {
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0x5F2F, &[0xDE, 0xAD]);
    let encoded = writer.as_bytes();

    let mut reader = TlvReader::new(encoded);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x5F2F);
    let value = reader.read_value().unwrap();
    assert_eq!(value, &[0xDE, 0xAD]);
}
