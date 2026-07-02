// SPDX-License-Identifier: MIT OR Apache-2.0

//! A DNS [`Resolver`] backed by the operating system resolver (`getaddrinfo`).
//!
//! iroh's default resolver reads nameserver configuration directly (via hickory),
//! which is unreliable on Android: it cannot read the system DNS servers, so relay
//! and name resolution fail with "Resolve failed" even though ordinary HTTP works.
//! Resolving through `getaddrinfo` uses the same path the platform uses for
//! everything else (on Android: bionic -> netd -> the active network's DNS,
//! including private DNS), so it works there and follows network changes.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::pin::Pin;

use iroh::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
use n0_error::AnyError;

/// Boxed future matching the return type of iroh's [`Resolver`] methods.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// A [`Resolver`] that delegates name resolution to the OS resolver
/// (`getaddrinfo`) instead of querying nameservers directly.
#[derive(Debug, Clone, Default)]
pub struct OsResolver;

/// Resolve `host` to IP addresses via `getaddrinfo`. That call is blocking, so it
/// runs on tokio's blocking pool. A bare IP literal is returned without a lookup.
async fn resolve(host: String) -> Result<Vec<IpAddr>, DnsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    match tokio::task::spawn_blocking(move || (host.as_str(), 0u16).to_socket_addrs()).await {
        Ok(Ok(addrs)) => Ok(addrs.map(|addr| addr.ip()).collect()),
        Ok(Err(err)) => Err(AnyError::from_std(err).into()),
        Err(err) => Err(AnyError::from_std(err).into()),
    }
}

impl Resolver for OsResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(async move {
            let iter = resolve(host).await?.into_iter().filter_map(|ip| match ip {
                IpAddr::V4(addr) => Some(addr),
                IpAddr::V6(_) => None,
            });
            Ok(Box::new(iter) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async move {
            let iter = resolve(host).await?.into_iter().filter_map(|ip| match ip {
                IpAddr::V6(addr) => Some(addr),
                IpAddr::V4(_) => None,
            });
            Ok(Box::new(iter) as BoxIter<Ipv6Addr>)
        })
    }

    /// `getaddrinfo` cannot resolve TXT records. TXT lookups are only used for
    /// pkarr / `dns.iroh.link` endpoint-id discovery, which this node does not
    /// rely on (it uses its own address book), so return an empty result.
    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        Box::pin(async move { Ok(Box::new(std::iter::empty()) as BoxIter<TxtRecordData>) })
    }

    fn clear_cache(&self) {}

    /// `getaddrinfo` re-reads the OS configuration on every call, so a fresh
    /// instance is all that is needed after a network change.
    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(OsResolver)
    }
}
