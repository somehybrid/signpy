// adapted from the rust-crypto ed25519 implementation

use crate::ge::{ge_scalarmult_base, sc_muladd, sc_reduce, GeP2, GeP3};
use crate::utils::const_time_eq;
use getrandom::getrandom;
use pyo3::exceptions::{PyAssertionError, PyException};
use pyo3::prelude::*;
use sha2::{Digest, Sha512};
use std::borrow::Cow;

fn check_s_lt_l(s: &[u8]) -> bool {
    static L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    for i in (0..32).rev() {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= ((((s[i] ^ L[i]) as i32) - 1) >> 8) as u8;
    }

    c != 0
}

#[pyfunction]
/// Generates a random secret key
pub fn generate() -> PyResult<Cow<'static, [u8]>> {
    let mut seed = [0u8; 32];
    let result = getrandom(&mut seed);

    if result.is_err() {
        return Err(PyException::new_err("An unexpected error occurred!"));
    }

    let mut secret: [u8; 64] = {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let mut hash_output: [u8; 64] = hasher.finalize().into();
        hash_output[0] &= 248;
        hash_output[31] &= 63;
        hash_output[31] |= 64;
        hash_output
    };

    let a = ge_scalarmult_base(&secret[0..32]);
    let public_key = a.to_bytes();
    for (dest, src) in (&mut secret[32..64]).iter_mut().zip(public_key.iter()) {
        *dest = *src;
    }
    for (dest, src) in (&mut secret[0..32]).iter_mut().zip(seed.iter()) {
        *dest = *src;
    }
    let mut secret: [u8; 64] = {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let mut hash_output: [u8; 64] = hasher.finalize().into();
        hash_output[0] &= 248;
        hash_output[31] &= 63;
        hash_output[31] |= 64;
        hash_output
    };

    let a = ge_scalarmult_base(&secret[0..32]);
    let public_key = a.to_bytes();
    for (dest, src) in (&mut secret[32..64]).iter_mut().zip(public_key.iter()) {
        *dest = *src;
    }
    for (dest, src) in (&mut secret[0..32]).iter_mut().zip(seed.iter()) {
        *dest = *src;
    }

    Ok(Cow::Owned(secret.to_vec()))
}

/// A class to sign keys
#[pyclass]
pub struct SigningKey {
    az: [u8; 64],
    public: [u8; 32],
}

#[pymethods]
impl SigningKey {
    /// Constructs a secret key from a 64-byte secret key
    #[new]
    pub fn new(secret: &[u8]) -> PyResult<SigningKey> {
        if secret.len() != 64 {
            return Err(PyAssertionError::new_err(
                "The secret key must be 64 bytes!",
            ));
        }

        let az: [u8; 64] = {
            let mut hash_output: [u8; 64] = [0; 64];
            let mut hasher = Sha512::new();
            hasher.update(&secret[0..32]);
            hash_output = hasher.finalize().into();
            hash_output[0] &= 248;
            hash_output[31] &= 63;
            hash_output[31] |= 64;
            hash_output
        };

        Ok(SigningKey {
            az,
            public: secret[32..64].try_into().unwrap(),
        })
    }

    /// Returns the public key for verifying
    #[getter]
    pub fn verifier(&self) -> PyResult<VerifyingKey> {
        VerifyingKey::from(&self.public)
    }

    #[getter]
    pub fn public_key(&self) -> Cow<[u8]> {
        Cow::Owned(self.public.to_vec())
    }

    /// Signs messages
    pub fn sign(&self, msg: &[u8]) -> Cow<[u8]> {
        let nonce = {
            let mut hasher = Sha512::new();
            hasher.update(&self.az[32..64]);
            hasher.update(msg);
            let mut hash_output: [u8; 64] = hasher.finalize().into();
            sc_reduce(&mut hash_output[0..64]);
            hash_output
        };

        let mut signature: [u8; 64] = [0; 64];
        let r: GeP3 = ge_scalarmult_base(&nonce[0..32]);
        signature[0..32].copy_from_slice(&r.to_bytes());
        signature[32..64].copy_from_slice(&self.public);

        {
            let mut hasher = Sha512::new();
            hasher.update(signature.as_ref());
            hasher.update(msg);
            let mut hram: [u8; 64] = hasher.finalize().into();
            sc_reduce(&mut hram);
            sc_muladd(
                &mut signature[32..64],
                &hram[0..32],
                &self.az[0..32],
                &nonce[0..32],
            );
        }

        Cow::Owned(signature.to_vec())
    }
}

#[pyclass]
/// A class to verify messages signed with the corresponding secret key
pub struct VerifyingKey {
    public: [u8; 32],
}

#[pymethods]
impl VerifyingKey {
    #[new]
    /// Constructs a verifier from a public key
    pub fn from(public_key: &[u8]) -> PyResult<VerifyingKey> {
        if public_key.len() != 32 {
            return Err(PyAssertionError::new_err("Invalid public key!"));
        }

        Ok(VerifyingKey {
            public: public_key.try_into().unwrap(),
        })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }

        if !check_s_lt_l(&signature[32..64]) {
            return false;
        }

        let a = match GeP3::from_bytes_negate_vartime(&self.public) {
            Some(g) => g,
            None => {
                return false;
            }
        };
        let mut d = 0;
        for pk_byte in self.public.iter() {
            d |= *pk_byte;
        }
        if d == 0 {
            return false;
        }

        let mut hasher = Sha512::new();
        hasher.update(&signature[0..32]);
        hasher.update(self.public);
        hasher.update(message);
        let mut hash: [u8; 64] = hasher.finalize().into();
        sc_reduce(&mut hash);

        let r = GeP2::double_scalarmult_vartime(hash.as_ref(), a, &signature[32..64]);
        let rcheck = r.to_bytes();

        const_time_eq(rcheck.as_ref(), &signature[0..32])
    }
}
