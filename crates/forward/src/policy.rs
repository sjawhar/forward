use url::Url;

use crate::config::{Config, Mode};

#[derive(Debug, PartialEq)]
pub enum Decision {
    Open,
    Notify,
}

pub fn decide(cfg: &Config, url: &Url) -> Decision {
    match cfg.mode {
        Mode::Auto => Decision::Open,
        Mode::Allowlist => {
            if cfg.allow.iter().any(|pattern| allow_matches(pattern, url)) {
                Decision::Open
            } else {
                Decision::Notify
            }
        }
    }
}

/// Matches `hostpart[:port][/path-prefix]`: host matching is case-insensitive, `*.d` matches
/// subdomains only, inner `*` matches exactly one label, loopback aliases are equivalent,
/// and path prefixes match on segment boundaries. A specified port must match the URL's
/// effective port, so `localhost:80` also matches `http://localhost/`.
pub fn allow_matches(pattern: &str, url: &Url) -> bool {
    let (host_pattern, path_prefix) = match pattern.split_once('/') {
        Some((host_pattern, path_prefix)) => (host_pattern, path_prefix),
        None => (pattern, ""),
    };
    let (host_pattern, pattern_port) = split_host_and_port(host_pattern);
    if pattern_port.is_some_and(|port| url.port_or_known_default() != Some(port)) {
        return false;
    }
    let host_pattern = host_pattern.to_ascii_lowercase();
    let host = match url.host_str() {
        Some(host) => host.to_ascii_lowercase(),
        None => return false,
    };
    let host = normalize_loopback_alias(&host);
    let host_pattern = normalize_loopback_alias(&host_pattern);
    let mut host_labels = host.split('.');
    let mut pattern_labels = host_pattern.split('.');

    loop {
        match (pattern_labels.next(), host_labels.next()) {
            (None, None) => break,
            (Some("*"), Some(_)) => continue,
            (Some(pattern_label), Some(host_label)) if pattern_label == host_label => continue,
            _ => return false,
        }
    }

    let path_prefix = path_prefix.trim_end_matches('/');
    let path = url.path();
    let prefix = format!("/{path_prefix}");
    path_prefix.is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn split_host_and_port(host_pattern: &str) -> (&str, Option<u16>) {
    if host_pattern.starts_with('[') {
        return host_pattern.find(']').map_or((host_pattern, None), |end| {
            let suffix = &host_pattern[end + 1..];
            suffix
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .map_or((host_pattern, None), |port| {
                    (&host_pattern[..=end], Some(port))
                })
        });
    }

    host_pattern
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse().ok().map(|port| (host, Some(port))))
        .unwrap_or((host_pattern, None))
}

fn normalize_loopback_alias(host: &str) -> &str {
    match host {
        "127.0.0.1" | "[::1]" => "localhost",
        _ => host,
    }
}

#[cfg(test)]
mod tests;
