use pivy_piv::apdu::{Apdu, StatusWord, PIV_AID};

#[test]
fn build_select_piv() {
    let apdu = Apdu::select(PIV_AID);
    let bytes = apdu.to_bytes();
    assert_eq!(bytes[0], 0x00); // CLA
    assert_eq!(bytes[1], 0xA4); // INS = SELECT
    assert_eq!(bytes[2], 0x04); // P1 = select by AID
    assert_eq!(bytes[3], 0x00); // P2
    assert_eq!(bytes[4], PIV_AID.len() as u8); // Lc
    assert_eq!(&bytes[5..5 + PIV_AID.len()], PIV_AID);
}

#[test]
fn build_get_data() {
    let apdu = Apdu::get_data(0x5FC102); // CHUID tag
    let bytes = apdu.to_bytes();
    assert_eq!(bytes[0], 0x00); // CLA
    assert_eq!(bytes[1], 0xCB); // INS = GET DATA
    assert_eq!(bytes[2], 0x3F); // P1
    assert_eq!(bytes[3], 0xFF); // P2
    // Data should contain a TLV-wrapped tag
    assert!(bytes.len() > 5);
}

#[test]
fn build_verify_pin() {
    let pin = b"123456";
    let apdu = Apdu::verify_pin(pin);
    let bytes = apdu.to_bytes();
    assert_eq!(bytes[0], 0x00); // CLA
    assert_eq!(bytes[1], 0x20); // INS = VERIFY
    assert_eq!(bytes[2], 0x00); // P1
    assert_eq!(bytes[3], 0x80); // P2 = PIV PIN
    assert_eq!(bytes[4], 0x08); // Lc = 8 (PIN padded to 8 bytes)
    // PIN data: "123456" + 0xFF padding
    assert_eq!(&bytes[5..11], pin.as_slice());
    assert_eq!(bytes[11], 0xFF);
    assert_eq!(bytes[12], 0xFF);
}

#[test]
fn build_general_authenticate() {
    let data = [0x7C, 0x02, 0x81, 0x00];
    let apdu = Apdu::general_authenticate(0x07, 0x9A, &data);
    let bytes = apdu.to_bytes();
    assert_eq!(bytes[0], 0x00); // CLA
    assert_eq!(bytes[1], 0x87); // INS = GENERAL AUTHENTICATE
    assert_eq!(bytes[2], 0x07); // P1 = algorithm
    assert_eq!(bytes[3], 0x9A); // P2 = slot
}

#[test]
fn parse_status_word_success() {
    let sw = StatusWord::from_bytes(0x90, 0x00);
    assert!(sw.is_success());
    assert_eq!(sw.as_u16(), 0x9000);
}

#[test]
fn parse_status_word_auth_required() {
    let sw = StatusWord::from_bytes(0x69, 0x82);
    assert!(!sw.is_success());
    assert_eq!(sw.as_u16(), 0x6982);
}

#[test]
fn parse_status_word_bytes_remaining() {
    let sw = StatusWord::from_bytes(0x61, 0x10);
    assert!(!sw.is_success());
    assert!(sw.has_more_data());
    assert_eq!(sw.remaining_bytes(), 0x10);
}

#[test]
fn parse_status_word_incorrect_pin() {
    let sw = StatusWord::from_bytes(0x63, 0xC2);
    assert!(!sw.is_success());
    assert!(sw.is_pin_incorrect());
    assert_eq!(sw.pin_retries_remaining(), Some(2));
}

#[test]
fn apdu_no_data_no_le() {
    let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00);
    let bytes = apdu.to_bytes();
    assert_eq!(bytes, &[0x00, 0xA4, 0x04, 0x00]);
}

#[test]
fn apdu_with_le() {
    let mut apdu = Apdu::new(0x00, 0xC0, 0x00, 0x00);
    apdu.le = Some(256);
    let bytes = apdu.to_bytes();
    // Le=256 encoded as 0x00 in short form
    assert_eq!(bytes, &[0x00, 0xC0, 0x00, 0x00, 0x00]);
}
