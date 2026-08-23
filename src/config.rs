use std::path::{Path, PathBuf};

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(default = "default_opener")]
    pub opener: Vec<String>,
    #[serde(default)]
    pub notifier: Vec<String>,
    #[serde(default)]
    pub clipboard: Vec<String>,
    #[serde(default = "default_forward_ttl_secs")]
    pub forward_ttl_secs: u64,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub peer: String,
    #[serde(default = "default_bridge_port")]
    pub bridge_port: u16,
    /// Port for the browser relay channel on the laptop's tailnet address.
    #[serde(default = "default_relay_port")]
    pub relay_port: u16,
    /// Override for the laptop's relay token file. Normally unset: the token
    /// lives at the derived per-machine path (see [`Config::relay_token_path`]),
    /// never in `config.toml`, which is committed to dotfiles and symlinked
    /// into place — a secret or a machine-local path in it would be published.
    #[serde(default)]
    pub relay_token_file: Option<PathBuf>,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Allowlist,
    Auto,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("forward: {field} must be a literal IP address, got {value:?}")]
    Address { field: &'static str, value: String },
    #[error("forward: a non-loopback listen address requires an explicit peer")]
    PeerRequired,
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(Config::default_values())
        }
        Err(source) => Err(ConfigError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

impl Config {
    pub fn listen_ip(&self) -> Result<std::net::IpAddr, ConfigError> {
        parse_ip("listen", &self.listen)
    }

    /// The counterpart's address, or `None` when none is configured.
    ///
    /// Always a literal address. There is no hostname counterpart to this
    /// field: every outbound connection dials this literal value, so no name
    /// is ever resolved and no DNS or admin-console state can move the
    /// identity the inbound check in `peer::authorized` compares against.
    pub fn peer_ip(&self) -> Result<Option<std::net::IpAddr>, ConfigError> {
        if self.peer.is_empty() {
            return Ok(None);
        }
        parse_ip("peer", &self.peer).map(Some)
    }

    /// Where the laptop's relay token lives: the `relay_token_file` override
    /// if set, else `$XDG_CONFIG_HOME/forward/relay.token`, else
    /// `$HOME/.config/forward/relay.token` — the same derivation the binary
    /// already uses for `config.toml` itself. `None` when no override is set
    /// and neither variable is an absolute path; every caller treats `None`
    /// as "no token", which refuses every relay connection.
    pub fn relay_token_path(&self) -> Option<PathBuf> {
        relay_token_path_from(
            self.relay_token_file.clone(),
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        )
    }

    /// Fail closed: a routable listen address without a named counterpart
    /// would accept anything that can reach it.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let listen = self.listen_ip()?;
        // A wildcard bind exposes the path-serving port on every interface;
        // require one specific address even when a peer is configured.
        if listen.is_unspecified() {
            return Err(ConfigError::Address {
                field: "listen",
                value: self.listen.clone(),
            });
        }
        let peer = self.peer_ip()?;
        if let Some(peer) = peer
            && (peer.is_unspecified()
                || peer.is_multicast()
                || peer == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST))
        {
            // These values do not name an individual counterpart, so they must
            // not satisfy the peer requirement for a routable listener.
            return Err(ConfigError::Address {
                field: "peer",
                value: self.peer.clone(),
            });
        }
        if !listen.is_loopback() && peer.is_none() {
            return Err(ConfigError::PeerRequired);
        }
        Ok(())
    }

    /// Build the on-disk defaults without touching the filesystem.
    ///
    /// `#[doc(hidden)] pub` and deliberately **not** `#[cfg(test)]`: the
    /// integration tests under `tests/` are separate crates that link this one
    /// normally, so a `#[cfg(test)]` item compiles here and then fails to
    /// resolve there. Hidden from the rendered docs, not from the linker.
    #[doc(hidden)]
    pub fn default_values_for_test() -> Self {
        Self::default_values()
    }

    fn default_values() -> Self {
        Self {
            mode: default_mode(),
            opener: default_opener(),
            notifier: Vec::new(),
            clipboard: Vec::new(),
            forward_ttl_secs: default_forward_ttl_secs(),
            listen: default_listen(),
            peer: String::new(),
            bridge_port: default_bridge_port(),
            relay_port: default_relay_port(),
            relay_token_file: None,
            allow: Vec::new(),
        }
    }
}

fn default_mode() -> Mode {
    Mode::Allowlist
}

fn default_opener() -> Vec<String> {
    vec!["xdg-open".to_owned()]
}

fn default_forward_ttl_secs() -> u64 {
    300
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

fn default_bridge_port() -> u16 {
    12_801
}

pub(crate) fn default_relay_port() -> u16 {
    12_803
}

fn relay_token_path_from(
    override_path: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(path) = override_path {
        return Some(path);
    }
    if let Some(config_home) = xdg_config_home.filter(|path| path.is_absolute()) {
        return Some(config_home.join("forward/relay.token"));
    }
    home.filter(|path| path.is_absolute())
        .map(|home| home.join(".config/forward/relay.token"))
}

fn parse_ip(field: &'static str, value: &str) -> Result<std::net::IpAddr, ConfigError> {
    value.parse().map_err(|_| ConfigError::Address {
        field,
        value: value.to_owned(),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod token_path_tests;
