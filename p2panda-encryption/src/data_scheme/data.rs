// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use crate::crypto::hkdf::{HkdfError, hkdf};
use crate::crypto::xchacha20::{XAeadError, XAeadKey, XAeadNonce, x_aead_decrypt, x_aead_encrypt};
use crate::data_scheme::group_secret::GroupSecret;

pub fn encrypt_data(
    plaintext: &[u8],
    group_secret: &GroupSecret,
    nonce: XAeadNonce,
) -> Result<Vec<u8>, XAeadError> {
    let ciphertext = x_aead_encrypt(group_secret.as_bytes(), plaintext, nonce, None)?;
    Ok(ciphertext)
}

pub fn decrypt_data(
    ciphertext: &[u8],
    group_secret: &GroupSecret,
    nonce: XAeadNonce,
) -> Result<Vec<u8>, XAeadError> {
    let plaintext = x_aead_decrypt(group_secret.as_bytes(), ciphertext, nonce, None)?;
    Ok(plaintext)
}

/// Encrypt auxiliary application data under a subkey of the group secret.
///
/// The AEAD key is derived with HKDF-SHA256 from the group secret and the caller-supplied `info`
/// domain label, separating these ciphertexts from group messages encrypted with
/// [`encrypt_data`]. This allows applications to encrypt data living outside the group's own
/// messages (for example external files) towards the same group.
pub fn encrypt_aux(
    plaintext: &[u8],
    group_secret: &GroupSecret,
    info: &[u8],
    nonce: XAeadNonce,
) -> Result<Vec<u8>, AuxError> {
    let key: XAeadKey = hkdf(&[], group_secret.as_bytes(), Some(info))?;
    let ciphertext = x_aead_encrypt(&key, plaintext, nonce, None)?;
    Ok(ciphertext)
}

/// Decrypt auxiliary application data encrypted with [`encrypt_aux`] using the same `info`
/// domain label.
pub fn decrypt_aux(
    ciphertext: &[u8],
    group_secret: &GroupSecret,
    info: &[u8],
    nonce: XAeadNonce,
) -> Result<Vec<u8>, AuxError> {
    let key: XAeadKey = hkdf(&[], group_secret.as_bytes(), Some(info))?;
    let plaintext = x_aead_decrypt(&key, ciphertext, nonce, None)?;
    Ok(plaintext)
}

#[derive(Debug, Error)]
pub enum AuxError {
    #[error(transparent)]
    Hkdf(#[from] HkdfError),

    #[error(transparent)]
    XAead(#[from] XAeadError),
}

#[cfg(test)]
mod tests {
    use crate::Rng;
    use crate::crypto::xchacha20::XAeadNonce;
    use crate::data_scheme::GroupSecret;

    use super::{decrypt_aux, decrypt_data, encrypt_aux, encrypt_data};

    #[test]
    fn encrypt_decrypt() {
        let rng = Rng::from_seed([1; 32]);

        let group_secret = GroupSecret::from_rng(&rng).unwrap();
        let nonce: XAeadNonce = rng.random_array().unwrap();

        let message = encrypt_data(b"Service! Service!", &group_secret, nonce).unwrap();
        let receive = decrypt_data(&message, &group_secret, nonce).unwrap();
        assert_eq!(receive, b"Service! Service!");
    }

    #[test]
    fn encrypt_decrypt_aux() {
        let rng = Rng::from_seed([1; 32]);

        let group_secret = GroupSecret::from_rng(&rng).unwrap();
        let nonce: XAeadNonce = rng.random_array().unwrap();

        let ciphertext = encrypt_aux(b"Au revoir!", &group_secret, b"test/v1", nonce).unwrap();
        let receive = decrypt_aux(&ciphertext, &group_secret, b"test/v1", nonce).unwrap();
        assert_eq!(receive, b"Au revoir!");
    }

    #[test]
    fn aux_uses_derived_key() {
        let rng = Rng::from_seed([1; 32]);

        let group_secret = GroupSecret::from_rng(&rng).unwrap();
        let nonce: XAeadNonce = rng.random_array().unwrap();

        let aux = encrypt_aux(b"Au revoir!", &group_secret, b"test/v1", nonce).unwrap();
        let data = encrypt_data(b"Au revoir!", &group_secret, nonce).unwrap();
        assert_ne!(aux, data);

        assert!(decrypt_data(&aux, &group_secret, nonce).is_err());
    }

    #[test]
    fn decrypt_aux_fails_on_wrong_parameters() {
        let rng = Rng::from_seed([1; 32]);

        let group_secret = GroupSecret::from_rng(&rng).unwrap();
        let nonce: XAeadNonce = rng.random_array().unwrap();

        let ciphertext = encrypt_aux(b"Au revoir!", &group_secret, b"test/v1", nonce).unwrap();

        assert!(decrypt_aux(&ciphertext, &group_secret, b"test/v2", nonce).is_err());

        let other_secret = GroupSecret::from_rng(&rng).unwrap();
        assert!(decrypt_aux(&ciphertext, &other_secret, b"test/v1", nonce).is_err());

        let other_nonce: XAeadNonce = rng.random_array().unwrap();
        assert!(decrypt_aux(&ciphertext, &group_secret, b"test/v1", other_nonce).is_err());
    }
}
