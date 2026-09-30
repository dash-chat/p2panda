// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::NodeId;

/// Nodes appearing on and leaving the local-area network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalNodeEvent {
    /// A node's local-area network addresses were found (or changed) and are in the address book.
    Found(NodeId),

    /// A node stopped answering on the local-area network.
    Lost(NodeId),
}
