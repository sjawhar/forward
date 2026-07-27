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
    #[serde(default = "default_ssh")]
    pub ssh: Vec<String>,
    #[serde(default = "default_tunnel")]
    pub tunnel_host: String,
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
    fn default_values() -> Self {
        Self {
            mode: default_mode(),
            opener: default_opener(),
            notifier: Vec::new(),
            ssh: default_ssh(),
            tunnel_host: default_tunnel(),
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

fn default_ssh() -> Vec<String> {
    vec!["ssh".to_owned()]
}

fn default_tunnel() -> String {
    "devbox-tunnel".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults() {
        let cfg = load(std::path::Path::new("/no/such/config.toml")).unwrap();
        assert_eq!(cfg.mode, Mode::Allowlist);
        assert_eq!(cfg.opener, vec!["xdg-open".to_string()]);
        assert!(cfg.allow.is_empty());
    }

    #[test]
    fn parses_full_config() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            &f,
            r#"
mode = "auto"
opener = ["firefox"]
allow = ["localhost", "*.awsapps.com"]
"#,
        )
        .unwrap();
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.mode, Mode::Auto);
        assert_eq!(cfg.opener, vec!["firefox".to_string()]);
        assert!(cfg.notifier.is_empty());
        assert_eq!(cfg.ssh, vec!["ssh".to_string()]);
        assert_eq!(cfg.tunnel_host, "devbox-tunnel");
        assert_eq!(cfg.allow.len(), 2);
    }

    #[test]
    fn unknown_field_errors() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(&f, "moed = \"auto\"\n").unwrap();
        assert!(load(f.path()).is_err());
    }

    #[test]
    fn malformed_toml_errors() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(&f, "mode = [\n").unwrap();
        assert!(load(f.path()).is_err());
    }

    #[test]
    fn directory_errors_as_read() {
        let directory = tempfile::tempdir().unwrap();
        let err = load(directory.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }
}
