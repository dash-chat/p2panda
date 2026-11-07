// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access to a space's encryption secrets for encrypting auxiliary application data.
use p2panda_encryption::crypto::xchacha20::XAeadNonce;
use p2panda_encryption::data_scheme::{AuxError, GroupSecretId, decrypt_aux, encrypt_aux};
use p2panda_encryption::{Rng, RngError};
use thiserror::Error;

use crate::types::EncryptionGroupState;

/// Handle on a space's current encryption secrets, letting applications encrypt auxiliary data
/// (data living outside the space's own messages, for example external files) towards the space
/// without ever touching key material.
///
/// Auxiliary ciphertexts are encrypted with a subkey derived from a group secret and the
/// caller-supplied `info` domain label, so they can never be confused with the space's own
/// application messages.
///
/// The handle borrows the space state it was created from and can not outlive it; it is handed to
/// closures by [`Space::with_secrets`](crate::space::Space::with_secrets).
#[derive(Debug)]
pub struct SpaceSecrets<'a> {
    encryption_y: &'a EncryptionGroupState,
    rng: &'a Rng,
}

impl<'a> SpaceSecrets<'a> {
    pub(crate) fn new(encryption_y: &'a EncryptionGroupState, rng: &'a Rng) -> Self {
        Self { encryption_y, rng }
    }

    /// Id of the group secret new auxiliary data will be encrypted with: the same "latest" secret
    /// the space's next application message would use.
    ///
    /// `None` if the encryption group is not yet established for us.
    pub fn latest_secret_id(&self) -> Option<GroupSecretId> {
        if !self.encryption_y.is_welcomed {
            return None;
        }
        self.encryption_y.secrets.latest().map(|secret| secret.id())
    }

    /// Encrypt auxiliary data towards the space under the latest group secret, with a fresh
    /// random nonce and a subkey derived from the `info` domain label.
    ///
    /// Returns the id of the secret that was used, the nonce and the ciphertext. Both id and
    /// nonce are needed to [decrypt](Self::decrypt_aux) again and should travel with a reference
    /// to the ciphertext.
    ///
    /// Fails with [`SecretsError::NotEstablished`] when we haven't been welcomed into the
    /// encryption group yet or no group secret exists; callers may retry once the space's key
    /// agreement has progressed.
    pub fn encrypt_aux(
        &self,
        info: &[u8],
        plaintext: &[u8],
    ) -> Result<(GroupSecretId, XAeadNonce, Vec<u8>), SecretsError> {
        if !self.encryption_y.is_welcomed {
            return Err(SecretsError::NotEstablished);
        }
        let Some(secret) = self.encryption_y.secrets.latest() else {
            return Err(SecretsError::NotEstablished);
        };
        let nonce: XAeadNonce = self.rng.random_array()?;
        let ciphertext = encrypt_aux(plaintext, secret, info, nonce)?;
        Ok((secret.id(), nonce, ciphertext))
    }

    /// Decrypt auxiliary data encrypted with [`encrypt_aux`](Self::encrypt_aux), using the group
    /// secret pinned by `group_secret_id` (never the latest one).
    ///
    /// Fails with [`SecretsError::UnknownSecret`] when we don't hold that secret (yet); since
    /// secret bundles are retained across rotations and shipped whole in welcomes, callers may
    /// retry once the space's key agreement has progressed. A failure to decrypt with a known
    /// secret ([`SecretsError::Aux`]) is permanent.
    pub fn decrypt_aux(
        &self,
        group_secret_id: GroupSecretId,
        info: &[u8],
        nonce: XAeadNonce,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SecretsError> {
        let Some(secret) = self.encryption_y.secrets.get(&group_secret_id) else {
            return Err(SecretsError::UnknownSecret(group_secret_id));
        };
        let plaintext = decrypt_aux(ciphertext, secret, info, nonce)?;
        Ok(plaintext)
    }
}

#[derive(Debug, Error)]
pub enum SecretsError {
    /// We haven't been welcomed into the space's encryption group yet, or no group secret exists.
    /// Retriable once key agreement has progressed.
    #[error("space encryption group not yet established")]
    NotEstablished,

    /// We don't hold the group secret with this id (yet). Retriable once key agreement has
    /// progressed.
    #[error("unknown group secret {0:x?}")]
    UnknownSecret(GroupSecretId),

    /// Encryption or decryption itself failed; for decryption this is permanent (corrupt
    /// ciphertext or wrong parameters).
    #[error(transparent)]
    Aux(#[from] AuxError),

    #[error(transparent)]
    Rng(#[from] RngError),
}
