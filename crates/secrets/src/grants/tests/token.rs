use super::*;

#[test]
fn rejects_malformed_token_hex() {
    assert_eq!(SessionToken::parse_hex("nothex"), Err(ErrCode::BadRequest));
    assert_eq!(SessionToken::parse_hex("aabb"), Err(ErrCode::BadRequest));
}

#[test]
fn token_debug_never_reveals_raw_or_hex_bytes() {
    let rendered = format!("{:?}", token(0xaa));
    assert!(!rendered.contains("aa"), "leaked token hex: {rendered}");
    assert!(!rendered.contains('ª'), "leaked token bytes: {rendered}");
    assert!(rendered.contains("redacted"));
}
