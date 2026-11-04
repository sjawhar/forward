use std::net::{IpAddr, Ipv4Addr};

use super::{Config, ConfigError, parse_ip};

impl Config {
    pub fn is_multi_peer(&self) -> bool {
        self.peers.is_some()
    }

    pub fn has_peers(&self) -> bool {
        self.peers.is_some() || !self.peer.is_empty()
    }

    /// Canonical, deduplicated addresses: one feed and one doctor row per VM.
    pub fn peer_ips(&self) -> Result<Vec<IpAddr>, ConfigError> {
        let (field, values) = self.peer_values()?;
        let mut peers = Vec::with_capacity(values.len());
        for value in values {
            let ip = peer_ip(field, value)?;
            if !peers.contains(&ip) {
                peers.push(ip);
            }
        }
        Ok(peers)
    }

    /// Fail closed for the entire config, not just malformed list entries.
    /// The inbound hot path parses without allocating a temporary address list.
    pub(crate) fn admits_peer(&self, remote: IpAddr) -> bool {
        let Ok((field, values)) = self.peer_values() else {
            return false;
        };
        let mut found = false;
        for value in values {
            let Ok(peer) = peer_ip(field, value) else {
                return false;
            };
            found |= peer == remote.to_canonical();
        }
        found
    }

    pub(super) fn single_peer_ip(&self) -> Result<Option<IpAddr>, ConfigError> {
        let (field, values) = self.peer_values()?;
        let mut peer = None;
        let mut multiple = false;
        for value in values {
            let value = peer_ip(field, value)?;
            multiple |= peer.is_some_and(|previous| previous != value);
            peer = Some(value);
        }
        if multiple {
            Err(ConfigError::MultiplePeers)
        } else {
            Ok(peer)
        }
    }

    fn peer_values(&self) -> Result<(&'static str, &[String]), ConfigError> {
        match self.peers.as_deref() {
            Some(_) if !self.peer.is_empty() => Err(ConfigError::PeerConflict),
            Some([]) => Err(ConfigError::EmptyPeers),
            Some(peers) => Ok(("peers", peers)),
            None if self.peer.is_empty() => Ok(("peer", &[])),
            None => Ok(("peer", std::slice::from_ref(&self.peer))),
        }
    }
}

fn peer_ip(field: &'static str, value: &str) -> Result<IpAddr, ConfigError> {
    let ip = parse_ip(field, value)?.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
        return Err(ConfigError::Address {
            field,
            value: value.to_owned(),
        });
    }
    Ok(ip)
}
