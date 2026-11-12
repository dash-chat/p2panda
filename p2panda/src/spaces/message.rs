// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Borrow;

use p2panda_core::traits::{Digest, Provenance};
use p2panda_core::{Body, Hash, VerifyingKey};

use crate::operation::Operation;
use crate::spaces::types::SpacesArgs;

#[derive(Clone, Debug)]
pub struct SpacesMessage {
    operation: Operation,
    args: Option<SpacesArgs>,
}

impl SpacesMessage {
    pub fn into_operation(self) -> Operation {
        self.operation
    }
}

impl From<Operation> for SpacesMessage {
    fn from(operation: Operation) -> Self {
        let args = operation
            .header
            .extensions
            .spaces_args()
            .map(|args| with_ciphertext_from_body(args, operation.body.as_ref()));
        Self { operation, args }
    }
}

/// Spaces arguments as the spaces protocol sees them: an application message's ciphertext is
/// carried by the operation body, not by the arguments in the header.
pub(crate) fn with_ciphertext_from_body(args: SpacesArgs, body: Option<&Body>) -> SpacesArgs {
    match args {
        SpacesArgs::Application {
            space_id,
            space_dependencies,
            proof,
            group_secret_id,
            nonce,
            ciphertext: _,
        } => SpacesArgs::Application {
            space_id,
            space_dependencies,
            proof,
            group_secret_id,
            nonce,
            ciphertext: body.map(|body| body.to_bytes()),
        },
        args => args,
    }
}

impl Borrow<SpacesArgs> for SpacesMessage {
    fn borrow(&self) -> &SpacesArgs {
        match &self.args {
            Some(args) => args,
            None => unreachable!("at this point we're only dealing with space extensions"),
        }
    }
}

impl Digest<Hash> for SpacesMessage {
    fn hash(&self) -> Hash {
        self.operation.hash
    }
}

impl Provenance<VerifyingKey> for SpacesMessage {
    fn author(&self) -> VerifyingKey {
        self.operation.author()
    }

    fn verify(&self) -> bool {
        self.operation.verify()
    }
}
