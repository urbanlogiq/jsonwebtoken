use base64;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::map::Map;
use serde_json::{from_str, to_string, Value};

use errors::Result;
use header::Header;

/// The return type of a successful call to decode
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: Header,
    /// The decoded JWT claims
    pub claims: T,
}

/// Serializes to JSON and encodes to base64
pub fn to_jwt_part<T: Serialize>(input: &T) -> Result<String> {
    let encoded = to_string(input)?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(engine.encode(encoded.as_bytes()))
}

/// Decodes from base64 and deserializes from JSON to a struct
pub fn from_jwt_part<B: AsRef<str>, T: DeserializeOwned>(encoded: B) -> Result<T> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded = engine.decode(encoded.as_ref())?;
    let s = String::from_utf8(decoded)?;

    Ok(from_str(&s)?)
}

/// Decodes from base64 and deserializes from JSON to a struct AND a hashmap
pub fn from_jwt_part_claims<B: AsRef<str>, T: DeserializeOwned>(
    encoded: B,
) -> Result<(T, Map<String, Value>)> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded = engine.decode(encoded.as_ref())?;
    let s = String::from_utf8(decoded)?;

    let claims: T = from_str(&s)?;
    let map: Map<_, _> = from_str(&s)?;
    Ok((claims, map))
}
