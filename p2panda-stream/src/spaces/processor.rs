// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::VecDeque;

use p2panda_auth::traits::Conditions;
use p2panda_core::Hash;
use p2panda_spaces::manager::{GLOBAL_GROUPS_CONTEXT_ID, Manager, ManagerError, ProcessOutput};
use p2panda_spaces::{AuthMessage, Event, SpacesStoreState};
use p2panda_spaces::{Forge, SpacesArgs};
use p2panda_store::Transaction;
use p2panda_store::groups::GroupsStore;
use p2panda_store::key_registry::KeyRegistryStore;
use p2panda_store::key_secrets::KeySecretsStore;

/// How often a message whose dependency has not been applied yet is retried, and how long to
/// wait between attempts, see `Spaces::process`.
const MISSING_DEPENDENCY_RETRIES: usize = 40;
const MISSING_DEPENDENCY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);
use p2panda_store::spaces::{SpacesMessageStore, SpacesStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Notify;

use crate::Processor;
use crate::spaces::SpacesProcessorArgs;

pub type SpacesManager<S, F, C> = Manager<S, F, C>;

pub type SpacesManagerError<F, C> = ManagerError<F, C>;

/// Processor for spaces operations.
pub struct Spaces<T, S, F, C> {
    store: S,
    manager: SpacesManager<S, F, C>,
    notify: Notify,
    queue: RefCell<VecDeque<(T, SpacesResult<C>)>>,
}

impl<T, S, F, C> Spaces<T, S, F, C> {
    pub fn new(store: S, manager: SpacesManager<S, F, C>) -> Self {
        Self {
            store,
            manager,
            notify: Notify::new(),
            queue: RefCell::new(VecDeque::new()),
        }
    }
}

impl<T, S, F, C> Processor<T> for Spaces<T, S, F, C>
where
    T: Borrow<SpacesProcessorArgs<C>>,
    S: Clone
        + SpacesStore<SpacesStoreState<C>>
        + SpacesMessageStore<SpacesArgs<C>>
        + GroupsStore<AuthMessage<C>, C>
        + KeyRegistryStore
        + KeySecretsStore
        + Transaction,
    F: Forge<C>,
    C: Conditions + Serialize + for<'a> Deserialize<'a>,
{
    type Output = (T, SpacesResult<C>);

    type Error = (T, SpacesError);

    async fn process(&self, input: T) -> Result<(), Self::Error> {
        let input_args: &SpacesProcessorArgs<C> = input.borrow();

        let result = match input_args {
            SpacesProcessorArgs::Process { msg } => {
                // Held until the resulting state is committed, so no other pipeline or local
                // change persists a state computed from what we are about to overwrite.
                let mut mutating = self.manager.mutation_guard().await;

                // Process incoming event.
                //
                // Every topic stream has its own pipeline and orderer. A dependency of this
                // message may have been ingested through another topic's pipeline (group logs
                // are associated with every space they concern), which satisfies this pipeline's
                // orderer before that other pipeline's spaces processor has applied it. Give it
                // time rather than failing the message for good.
                //
                // TODO: This should be solved upstream, by ordering spaces processing across
                // pipelines instead of per topic.
                let mut attempts = 0;
                let ProcessOutput {
                    groups_y,
                    space_y,
                    mut events,
                } = loop {
                    match self.manager.process(msg).await {
                        Ok(result) => break result,
                        Err(err)
                            if attempts < MISSING_DEPENDENCY_RETRIES
                                && err.to_string().contains("missing dependency") =>
                        {
                            attempts += 1;
                            drop(mutating);
                            tokio::time::sleep(MISSING_DEPENDENCY_RETRY_DELAY).await;
                            mutating = self.manager.mutation_guard().await;
                        }
                        Err(err) => {
                            return Err((input, SpacesError::SpacesManager(err.to_string())));
                        }
                    }
                };
                let _mutating = mutating;

                // Persist resulting new states into database in one atomic transaction.
                let permit = match self.store.begin().await {
                    Ok(permit) => permit,
                    Err(err) => return Err((input, SpacesError::Store(err.to_string()))),
                };

                if let Some(y) = groups_y {
                    // TODO: Hashing every time when processing feels a bit redundant. We either want to
                    // hard-code the hash itself or change the id type in p2panda-store to a string OR
                    // have the constant in p2panda-store.
                    if let Err(err) = self
                        .store
                        .set_groups_state_tx(Hash::digest(GLOBAL_GROUPS_CONTEXT_ID), &y)
                        .await
                    {
                        return Err((input, SpacesError::Store(err.to_string())));
                    }
                }

                if let Some(y) = space_y {
                    let space_id = y.space_id;

                    // Filter out application events if the author has concurrently lost their write
                    // access.
                    //
                    // This case occurs if a member published messages before receiving the control
                    // message which removed them. Their claim to have access write is still
                    // historically valid, however we have already learned that they have actually
                    // been removed.
                    //
                    // NOTE: Application _and_ control messages are partially-ordered based on their
                    // causal relationships, application messages are always emitted together with the
                    // member's (create/add) welcome message. For that reason application messages
                    // from members which have been removed at a causally later point (not
                    // concurrently) will not be affected by this filter and are correctly forwarded
                    // to the application layer.
                    if msg.is_application_message() {
                        let mut is_member = false;

                        // Check if the message author is still a member of the group from our local
                        // perspective.
                        for (member, access) in y.groups_y.members(y.group_id) {
                            if member == msg.author && (access.is_write() || access.is_manage()) {
                                is_member = true;
                            }
                        }

                        if !is_member {
                            events.retain(|event| !matches!(event, Event::Application { .. }));
                        };
                    }

                    if let Err(err) = self
                        .store
                        .set_space_state_tx(&space_id, &SpacesStoreState::from(y))
                        .await
                    {
                        return Err((input, SpacesError::Store(err.to_string())));
                    }
                }

                if let Err(err) = self.store.commit(permit).await {
                    return Err((input, SpacesError::Store(err.to_string())));
                }

                (input, SpacesResult::Processed { events })
            }
            // For locally created operations the spaces args have already been processed and
            // resulting events are included in the processor args here. All that's needed from
            // the processor is to forward them onto any consumers.
            SpacesProcessorArgs::AlreadyProcessed { events, .. } => {
                let events = events.clone();
                (input, SpacesResult::Processed { events })
            }
            SpacesProcessorArgs::Ignore => (input, SpacesResult::Ignored),
        };

        self.queue.borrow_mut().push_back(result);
        self.notify.notify_one();

        Ok(())
    }

    async fn next(&self) -> Result<Self::Output, Self::Error> {
        loop {
            if let Some(item) = self.queue.borrow_mut().pop_front() {
                return Ok(item);
            }

            self.notify.notified().await;
        }
    }
}

#[derive(Clone, Debug)]
pub enum SpacesResult<C> {
    Processed { events: Vec<Event<C>> },
    Ignored,
}

impl<C> SpacesResult<C> {
    pub fn was_processed(self) -> bool {
        match self {
            Self::Processed { .. } => true,
            Self::Ignored => false,
        }
    }
}

#[derive(Clone, Debug, Error)]
pub enum SpacesError {
    /// Error occurred when processing -spaces event in manager.
    #[error("spaces processing error: {0}")]
    SpacesManager(String),

    /// Critical storage failure occurred. This is usually a reason to panic.
    #[error("critical storage failure: {0}")]
    Store(String),
}
