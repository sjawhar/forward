use std::path::{Path, PathBuf};

use super::super::SourceRoot;
use super::*;

#[test]
fn parses_roots_in_declaration_order() {
    // Given two source roots, with the first path relative to the configured home directory.
    let text = "[source.zebra]\npath = \"~/zebra\"\n[source.alpha]\npath = \"/srv/alpha\"\n";

    // When the source configuration is parsed.
    let sources = parse(text).unwrap();

    // Then declaration order and expanded paths are preserved.
    let described: Vec<(&str, &Path)> = sources
        .roots
        .iter()
        .map(|root| (root.name.as_str(), root.path.as_path()))
        .collect();
    assert_eq!(
        described,
        vec![
            ("zebra", Path::new("/home/u/zebra")),
            ("alpha", Path::new("/srv/alpha")),
        ]
    );
}

#[test]
fn parses_a_home_directory_path() {
    // Given a root whose path is exactly the home-directory marker.
    let text = "[source.dotfiles]\npath = \"~\"\n";

    // When the source configuration is parsed.
    let sources = parse(text).unwrap();

    // Then the marker expands to the supplied home directory.
    assert_eq!(
        sources.roots.first().map(|root| root.path.as_path()),
        Some(Path::new("/home/u"))
    );
}

#[test]
fn rejects_relative_paths() {
    // Given a root with a non-home relative path.
    let text = "[source.dotfiles]\npath = \"dotfiles\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing reports the unsafe relative path.
    assert!(matches!(result, Err(ConfigError::RelativePath(path)) if path == "dotfiles"));
}

#[test]
fn rejects_unsupported_user_home_paths() {
    // Given a root with another user's home-directory marker.
    let text = "[source.dotfiles]\npath = \"~other/dotfiles\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing treats it as an unsupported relative path.
    assert!(matches!(result, Err(ConfigError::RelativePath(path)) if path == "~other/dotfiles"));
}

#[test]
fn rejects_empty_and_relative_home_directories() {
    // Given home-directory values that cannot produce absolute source-root paths.
    let text = "[source.dotfiles]\npath = \"~/dotfiles\"\n";

    // When each home-directory value is used for parsing.
    let results = [Path::new(""), Path::new("relhome")].map(|home| Sources::parse(text, home));

    // Then parsing refuses both values before expanding source paths.
    assert!(matches!(results[0], Err(ConfigError::NoHome)));
    assert!(matches!(results[1], Err(ConfigError::NoHome)));
}

#[test]
fn rejects_bad_root_names() {
    // Given source names outside the lowercase-hyphenated grammar.
    let texts = [
        "[source.Dotfiles]\npath = \"/srv/dotfiles\"\n",
        "[source.1x]\npath = \"/srv/one\"\n",
    ];

    // When each source configuration is parsed.
    let results = texts.map(parse);

    // Then each name is rejected as invalid.
    assert!(matches!(
        &results[0],
        Err(ConfigError::BadRootName(name)) if name == "Dotfiles"
    ));
    assert!(matches!(
        &results[1],
        Err(ConfigError::BadRootName(name)) if name == "1x"
    ));
}

#[test]
fn rejects_unknown_source_fields() {
    // Given a source table with an unexpected field.
    let text = "[source.dotfiles]\npath = \"/srv/dotfiles\"\nextra = 1\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then deserialization rejects the unknown field.
    assert!(matches!(result, Err(ConfigError::Toml(message)) if message.contains("unknown field")));
}

#[test]
fn rejects_unknown_top_level_tables() {
    // Given a document with an unrelated top-level table.
    let text = "[source.dotfiles]\npath = \"/srv/dotfiles\"\n[other]\nk = 1\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing refuses the unsupported configuration shape.
    assert!(
        matches!(result, Err(ConfigError::Toml(message)) if message.contains("exactly one top-level source table"))
    );
}

#[test]
fn rejects_a_document_without_source_roots() {
    // Given a document with an empty source table.
    let text = "[source]\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing reports that no roots were configured.
    assert!(matches!(result, Err(ConfigError::NoRoots)));
}

#[test]
fn rejects_duplicate_resolved_paths() {
    // Given two root names resolving to one directory.
    let text =
        "[source.dotfiles]\npath = \"~/dotfiles\"\n[source.private]\npath = \"/home/u/dotfiles\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing reports the first and duplicate root names in declaration order.
    assert!(matches!(
        result,
        Err(ConfigError::DuplicatePath(first, duplicate))
            if first == "dotfiles" && duplicate == "private"
    ));
}

#[test]
fn rejects_duplicate_source_tables() {
    // Given duplicate TOML tables for a source name.
    let text = "[source.dotfiles]\npath = \"/srv/one\"\n[source.dotfiles]\npath = \"/srv/two\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then the TOML parser rejects the duplicate table.
    assert!(matches!(result, Err(ConfigError::Toml(message)) if message.contains("duplicate")));
}

#[test]
fn rejects_parent_directory_segments() {
    // Given absolute and home-expanded source paths containing parent-directory segments.
    let texts = [
        "[source.dotfiles]\npath = \"/srv/x/../a\"\n",
        "[source.dotfiles]\npath = \"~/../escape\"\n",
    ];

    // When each configuration is parsed.
    let results = texts.map(parse);

    // Then neither path can escape its configured lexical root.
    assert!(matches!(&results[0], Err(ConfigError::RelativePath(path)) if path == "/srv/x/../a"));
    assert!(matches!(&results[1], Err(ConfigError::RelativePath(path)) if path == "~/../escape"));
}

#[test]
fn derives_the_agent_and_human_paths() {
    // Given a parsed source root.
    let root = SourceRoot {
        name: "dotfiles".to_owned(),
        path: PathBuf::from("/srv/dotfiles"),
    };

    // When its derived paths are requested.
    let agent_files = root.agent_files();
    let human_dir = root.human_dir();

    // Then the agent tier checks the local file before the shared file and the human tier uses its directory.
    assert_eq!(
        agent_files,
        [
            PathBuf::from("/srv/dotfiles/secrets.local.env"),
            PathBuf::from("/srv/dotfiles/secrets.env"),
        ]
    );
    assert_eq!(human_dir, PathBuf::from("/srv/dotfiles/secrets.human.d"));
}
