use pivy_piv::guid::Guid;

#[test]
fn parse_guid_from_hex() {
    let guid = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();
    assert_eq!(guid.as_bytes().len(), 16);
    assert_eq!(guid.to_hex(), "995E171383029CDA0D9CDBDBAD580813");
}

#[test]
fn parse_guid_lowercase() {
    let guid = Guid::from_hex("995e171383029cda0d9cdbdbad580813").unwrap();
    assert_eq!(guid.to_hex(), "995E171383029CDA0D9CDBDBAD580813");
}

#[test]
fn guid_short_display() {
    let guid = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();
    assert_eq!(guid.short_id(), "995E1713");
}

#[test]
fn guid_from_bytes() {
    let bytes = [
        0x99, 0x5E, 0x17, 0x13, 0x83, 0x02, 0x9C, 0xDA, 0x0D, 0x9C, 0xDB, 0xDB, 0xAD, 0x58,
        0x08, 0x13,
    ];
    let guid = Guid::from_bytes(&bytes).unwrap();
    assert_eq!(guid.to_hex(), "995E171383029CDA0D9CDBDBAD580813");
}

#[test]
fn guid_reject_invalid_hex() {
    assert!(Guid::from_hex("ZZZZ").is_err());
}

#[test]
fn guid_reject_too_long() {
    assert!(Guid::from_hex("00112233445566778899AABBCCDDEEFF00").is_err());
}

#[test]
fn guid_reject_too_short() {
    assert!(Guid::from_hex("001122").is_err());
}

#[test]
fn guid_reject_wrong_byte_length() {
    assert!(Guid::from_bytes(&[0x00; 15]).is_err());
    assert!(Guid::from_bytes(&[0x00; 17]).is_err());
}

#[test]
fn guid_equality() {
    let a = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();
    let b = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();
    let c = Guid::from_hex("AABBCCDD11223344AABBCCDD11223344").unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn guid_debug_display() {
    let guid = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();
    let debug = format!("{:?}", guid);
    assert!(debug.contains("995E171383029CDA0D9CDBDBAD580813"));
    let display = format!("{}", guid);
    assert_eq!(display, "995E1713");
}
