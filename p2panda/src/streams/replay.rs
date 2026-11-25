// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;

use futures_util::StreamExt;
use p2panda_core::logs::LogRanges;
use p2panda_core::{Cursor, Hash, Topic, VerifyingKey};
use p2panda_store::{SqliteError, SqliteStore};
use p2panda_sync::api::{LogEntry, log_ranges};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::debug;

use crate::operation::{Extensions, LogId, Operation};
use crate::processor::Pipeline;
use crate::streams::stream::{Source, process_operation_in};
use crate::streams::{ForwardEvent, StreamEvent};

/// Determines the starting point of a subscription stream.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub enum StreamFrom {
    /// Stream all events from the beginning, including already acknowledged ones.
    ///
    /// `Start` is useful if the application doesn't keep any materialised state around and needs to
    /// repeat all messages from the beginning. Another use-case is the roll-out of an application
    /// update where all state needs to be re-materialised.
    Start,

    /// Stream only unacknowledged events from where we've ended last.
    ///
    /// We keep an internal cursor around for each topic which is used to track acknowledged
    /// operations.
    #[default]
    Frontier,

    /// Stream all events from _after_ the given cursor position.
    Cursor(Cursor<VerifyingKey, LogId>),
}

impl From<Cursor<VerifyingKey, LogId>> for StreamFrom {
    fn from(cursor: Cursor<VerifyingKey, LogId>) -> Self {
        Self::Cursor(cursor)
    }
}

/// Re-play and re-process locally stored operations.
pub(crate) async fn replay_log_ranges<M>(
    topic: Topic,
    store: &SqliteStore,
    to_output_tx: &mpsc::Sender<Vec<ForwardEvent<M>>>,
    pipeline: &Pipeline<LogId, Extensions, Topic>,
    ranges: LogRanges<VerifyingKey, LogId>,
) -> Result<(), ReplayError>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    let total_operations = total_operations(&ranges);
    debug!("replay {total_operations} operations");

    if total_operations == 0 {
        return Ok(());
    }

    // Stream re-played operations into pipeline to re-process them.
    to_output_tx
        .send(vec![StreamEvent::ReplayStarted { total_operations }.into()])
        .await
        .map_err(|_| ReplayError::CriticalError)?;

    let mut entries = log_ranges(store, ranges);
    let mut operations = Vec::new();
    while let Some(result) = entries.next().await {
        let LogEntry {
            entry: operation, ..
        } = result?;
        operations.push(
            operation
                .try_into()
                .expect("operations from database have already validated extensions"),
        );
    }

    for operation in causal_order(operations) {
        process_operation_in(operation, Source::Replay, topic, pipeline, None, None).await;
    }

    to_output_tx
        .send(vec![StreamEvent::ReplayEnded.into()])
        .await
        .map_err(|_| ReplayError::CriticalError)?;

    debug!("finished replaying {total_operations} operations");

    Ok(())
}

/// `operations` reordered so that each one comes after the ones among them it depends on,
/// otherwise keeping their order.
///
/// Replayed operations come out of the store log by log, and the orderer may have marked all of
/// them ready already (they are unacknowledged, not unprocessed), in which case it forwards them
/// in the order they arrive. Its state is shared by every stream on the topic, so the replay
/// orders them itself instead of resetting it. Dependencies outside `operations` are left to the
/// orderer.
fn causal_order(operations: Vec<Operation>) -> Vec<Operation> {
    let index: HashMap<Hash, usize> = operations
        .iter()
        .enumerate()
        .map(|(i, operation)| (operation.hash, i))
        .collect();
    let dependencies: Vec<Vec<usize>> = operations
        .iter()
        .map(|operation| {
            operation
                .header
                .extensions
                .spaces_args(operation.body.as_ref())
                .map(|args| args.dependencies())
                .unwrap_or_default()
                .iter()
                .filter_map(|hash| index.get(hash).copied())
                .collect()
        })
        .collect();

    // Depth-first, with an explicit stack: a dependency chain can be as long as the replay.
    let mut state = vec![Visit::New; operations.len()];
    let mut order = Vec::with_capacity(operations.len());
    for root in 0..operations.len() {
        let mut stack = vec![(root, 0)];
        while let Some((i, next)) = stack.pop() {
            if state[i] == Visit::Placed {
                continue;
            }
            state[i] = Visit::OnStack;
            match dependencies[i].get(next) {
                Some(&dependency) => {
                    stack.push((i, next + 1));
                    if state[dependency] == Visit::New {
                        stack.push((dependency, 0));
                    }
                }
                None => {
                    state[i] = Visit::Placed;
                    order.push(i);
                }
            }
        }
    }

    let mut operations: Vec<Option<Operation>> = operations.into_iter().map(Some).collect();
    order
        .into_iter()
        .map(|i| operations[i].take().expect("each operation is placed once"))
        .collect()
}

#[derive(Clone, Copy, PartialEq)]
enum Visit {
    New,
    OnStack,
    Placed,
}

/// Returns the number of all operations in the given log ranges.
fn total_operations<A, L>(log_ranges: &LogRanges<A, L>) -> u32 {
    log_ranges.iter().fold(0, |mut acc, (_, logs)| {
        logs.iter().for_each(|(_, (after, until))| {
            // Ignore open-ended ranges.
            if let Some(until) = until {
                if after.is_none() {
                    // First operation seq_num = 0 counts as an item.
                    //
                    // TODO: Range semantics might be a bit confusing here. See related issue:
                    // https://github.com/p2panda/p2panda/issues/1184
                    acc += 1;
                }

                // Add all other operations following.
                let after = after.unwrap_or_default();
                acc += until - after
            }
        });

        acc
    })
}

/// Topic stream could not re-play events due to an internal error.
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("an error occurred while querying the store: {0}")]
    Store(#[from] SqliteError),

    #[error("a critical error occurred in the replay task")]
    CriticalError,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p2panda_core::logs::LogRanges;
    use p2panda_core::{SigningKey, VerifyingKey};

    use super::total_operations;

    #[test]
    fn calculate_total_operations() {
        let author_1 = SigningKey::generate().verifying_key();
        let author_2 = SigningKey::generate().verifying_key();
        let author_3 = SigningKey::generate().verifying_key();

        let ranges_1 = {
            let mut result: LogRanges<VerifyingKey, usize> = BTreeMap::new();
            let logs = result.entry(author_1).or_default();
            // [0 1 2 3 4 5 6 7 8 9 10 11 12] = 13
            logs.insert(0, (None, Some(12)));
            result
        };
        assert_eq!(total_operations(&ranges_1), 13);

        let ranges_2 = {
            let mut result: LogRanges<VerifyingKey, usize> = BTreeMap::new();
            let logs = result.entry(author_1).or_default();
            // [1 2 3 4 5 6 7 8 9 10 11 12] = 12
            logs.insert(0, (Some(0), Some(12)));
            // [6 7] = 2
            logs.insert(1, (Some(5), Some(7)));
            // [78 79 80] = 3
            logs.insert(2, (Some(77), Some(80)));
            let logs = result.entry(author_2).or_default();
            // [0 1 2 3] = 4
            logs.insert(3, (None, Some(3)));
            let logs = result.entry(author_3).or_default();
            // [11 12 13 14 15 16 17 18 19 20] = 10
            logs.insert(4, (Some(10), Some(20)));
            result
        };
        assert_eq!(total_operations(&ranges_2), 12 + 2 + 3 + 4 + 10);

        let ranges_3 = {
            let mut result: LogRanges<VerifyingKey, usize> = BTreeMap::new();
            let logs = result.entry(author_1).or_default();
            // Ignore this one, since it is an open-ended (invalid) range.
            logs.insert(0, (Some(100), None));
            result
        };
        assert_eq!(total_operations(&ranges_3), 0);

        let ranges_4 = {
            let mut result: LogRanges<VerifyingKey, usize> = BTreeMap::new();
            let logs = result.entry(author_1).or_default();
            // [ 0 ] = 1
            logs.insert(0, (None, Some(0)));
            result
        };
        assert_eq!(total_operations(&ranges_4), 1);

        let ranges_5 = {
            let mut result: LogRanges<VerifyingKey, usize> = BTreeMap::new();
            let logs = result.entry(author_1).or_default();
            // [] = 0
            logs.insert(0, (Some(0), Some(0)));
            result
        };
        assert_eq!(total_operations(&ranges_5), 0);

        let ranges_6 = {
            let mut result: LogRanges<VerifyingKey, usize> = BTreeMap::new();
            let logs = result.entry(author_1).or_default();
            // No range given.
            logs.insert(0, (None, None));
            result
        };
        assert_eq!(total_operations(&ranges_6), 0);

        let ranges_7 = {
            let mut result: LogRanges<VerifyingKey, usize> = BTreeMap::new();
            let logs = result.entry(author_1).or_default();
            // [] = 0
            logs.insert(0, (Some(1), Some(1)));
            result
        };
        assert_eq!(total_operations(&ranges_7), 0);
    }
}
