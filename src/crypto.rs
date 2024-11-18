use base64;
use base64::Engine;
use ring::constant_time::verify_slices_are_equal;
use ring::signature;
use std::str::FromStr;
use untrusted;

use errors::{new_error, Error, ErrorKind, Result};

/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,

    /// ECDSA using SHA-256
    ES256,

    /// ECDSA using SHA-384
    ES384,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::HS256
    }
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            _ => Err(new_error(ErrorKind::InvalidAlgorithmName)),
        }
    }
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
pub fn sign(_signing_input: &str, _key: &[u8], _algorithm: Algorithm) -> Result<String> {
    unimplemented!()
}

/// See Ring docs for more details
fn verify_ring(
    alg: &dyn signature::VerificationAlgorithm,
    signature: &str,
    signing_input: &str,
    key: &[u8],
) -> Result<bool> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signature_bytes = engine.decode(signature)?;
    let public_key_der = untrusted::Input::from(key);
    let message = untrusted::Input::from(signing_input.as_bytes());
    let expected_signature = untrusted::Input::from(signature_bytes.as_slice());

    let res = alg.verify(public_key_der, message, expected_signature);

    Ok(res.is_ok())
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA.
///
/// Only use this function if you want to do something other than JWT.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `signing_input` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    signing_input: &str,
    key: &[u8],
    algorithm: Algorithm,
) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the data with the key and compare if they are equal
            let signed = sign(signing_input, key, algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        }
        Algorithm::ES256 => {
            verify_ring(&signature::ECDSA_P256_SHA256_FIXED, signature, signing_input, key)
        }
        Algorithm::ES384 => {
            verify_ring(&signature::ECDSA_P384_SHA384_FIXED, signature, signing_input, key)
        }
        Algorithm::RS256 => {
            verify_ring(&signature::RSA_PKCS1_2048_8192_SHA256, signature, signing_input, key)
        }
        Algorithm::RS384 => {
            verify_ring(&signature::RSA_PKCS1_2048_8192_SHA384, signature, signing_input, key)
        }
        Algorithm::RS512 => {
            verify_ring(&signature::RSA_PKCS1_2048_8192_SHA512, signature, signing_input, key)
        }
    }
}
