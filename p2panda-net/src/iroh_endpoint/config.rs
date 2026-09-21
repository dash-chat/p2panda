// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohConfig {
    /// IPv4 address to bind to.
    pub bind_ip_v4: Ipv4Addr,

    /// Port used for IPv4 socket address.
    ///
    /// Setting the port to `0` will use a random port. If the port specified is already in use, it
    /// will fallback to choosing a random port.
    pub bind_port_v4: u16,

    /// IPv6 address to bind to.
    pub bind_ip_v6: Ipv6Addr,

    /// Port used for IPv6 socket address.
    ///
    /// Setting the port to `0` will use a random port. If the port specified is already in use, it
    /// will fallback to choosing a random port.
    pub bind_port_v6: u16,

    /// Period of inactivity before a keep-alive packet is sent on a connection. Must be
    /// shorter than the idle timeout of both peers to keep an idle connection alive.
    pub keep_alive_interval: Duration,

    /// Period of inactivity after which a connection is considered dead and closed.
    pub max_idle_timeout: Duration,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            bind_ip_v4: Ipv4Addr::UNSPECIFIED,
            bind_port_v4: 0,
            bind_ip_v6: Ipv6Addr::UNSPECIFIED,
            bind_port_v6: 0,
            keep_alive_interval: Duration::from_secs(5),
            max_idle_timeout: Duration::from_secs(10),
        }
    }
}
