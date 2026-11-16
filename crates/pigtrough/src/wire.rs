//! Conversions between hyper's header map and the proxy's own [`Headers`].

use hyper::header::{HeaderMap, HeaderName, HeaderValue};

use crate::Headers;

pub(crate) fn from_header_map(map: &HeaderMap) -> Headers {
    map.iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect()
}

/// Append `headers` to `map`, skipping any that are not valid HTTP (which a
/// filtered set should never hold).
pub(crate) fn extend_header_map(map: &mut HeaderMap, headers: &Headers) {
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value),
        ) {
            map.append(name, value);
        }
    }
}
