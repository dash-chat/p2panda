// SPDX-License-Identifier: MIT OR Apache-2.0

use ractor::thread_local::{ThreadLocalActor, ThreadLocalActorSpawner};
use rand::SeedableRng;
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;

use crate::address_book::AddressBook;
use crate::discovery::actors::{DiscoveryManager, DiscoveryManagerArgs};
use crate::discovery::config::DiscoveryConfig;
use crate::discovery::{Discovery, DiscoveryError};
use crate::iroh_endpoint::Endpoint;
use crate::iroh_mdns::MdnsDiscovery;

pub struct Builder {
    config: Option<DiscoveryConfig>,
    rng: Option<ChaCha20Rng>,
    address_book: AddressBook,
    endpoint: Endpoint,
    mdns: Option<MdnsDiscovery>,
}

impl Builder {
    pub fn new(address_book: AddressBook, endpoint: Endpoint) -> Self {
        Self {
            config: None,
            rng: None,
            address_book,
            endpoint,
            mdns: None,
        }
    }

    pub fn config(mut self, config: DiscoveryConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Discover nodes found on the local-area network right away, instead of waiting for a random
    /// walk to come across them.
    pub fn mdns(mut self, mdns: MdnsDiscovery) -> Self {
        self.mdns = Some(mdns);
        self
    }

    #[cfg(test)]
    pub fn rng(mut self, rng: ChaCha20Rng) -> Self {
        self.rng = Some(rng);
        self
    }

    pub(crate) fn build_args(self) -> DiscoveryManagerArgs {
        let config = self.config.unwrap_or_default();
        let rng = self
            .rng
            .unwrap_or(ChaCha20Rng::try_from_rng(&mut SysRng).expect("enough entropy"));
        (config, rng, self.address_book, self.endpoint, self.mdns)
    }

    pub async fn spawn(self) -> Result<Discovery, DiscoveryError> {
        let args = self.build_args();

        let (actor_ref, _) = {
            let thread_pool = ThreadLocalActorSpawner::new();
            DiscoveryManager::spawn(None, args.clone(), thread_pool).await?
        };

        Ok(Discovery::new(Some(actor_ref), args))
    }
}
