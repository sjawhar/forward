use super::*;

fn u(s: &str) -> url::Url {
    url::Url::parse(s).unwrap()
}

#[test]
fn exact_host() {
    assert!(allow_matches(
        "accounts.google.com",
        &u("https://accounts.google.com/o/oauth2")
    ));
}

#[test]
fn exact_host_rejects_other() {
    assert!(!allow_matches(
        "accounts.google.com",
        &u("https://evil.com/accounts.google.com")
    ));
}

#[test]
fn pattern_host_is_case_insensitive() {
    assert!(allow_matches(
        "GitHub.com/login",
        &u("https://github.com/login/device")
    ));
}

#[test]
fn subdomain_wildcard() {
    assert!(allow_matches(
        "*.awsapps.com",
        &u("https://d-123.awsapps.com/start")
    ));
}

#[test]
fn wildcard_not_bare_domain() {
    assert!(!allow_matches("*.awsapps.com", &u("https://awsapps.com/")));
}

#[test]
fn inner_label_wildcard() {
    assert!(allow_matches(
        "device.sso.*.amazonaws.com",
        &u("https://device.sso.us-east-1.amazonaws.com/x")
    ));
}

#[test]
fn path_prefix() {
    assert!(allow_matches(
        "github.com/login",
        &u("https://github.com/login/device")
    ));
    assert!(!allow_matches(
        "github.com/login",
        &u("https://github.com/sjawhar")
    ));
}

#[test]
fn path_prefix_matches_exact_path() {
    assert!(allow_matches(
        "github.com/login",
        &u("https://github.com/login")
    ));
}

#[test]
fn path_prefix_rejects_partial_segment() {
    assert!(!allow_matches(
        "github.com/login",
        &u("https://github.com/loginx")
    ));
}

#[test]
fn trailing_slash_path_prefix_matches_directory_scope() {
    let child = u("https://github.com/login/device");
    let directory = u("https://github.com/login");
    assert!(allow_matches("github.com/login", &child));
    assert!(allow_matches("github.com/login/", &child));
    assert!(allow_matches("github.com/login", &directory));
    assert!(allow_matches("github.com/login/", &directory));
}

#[test]
fn url_host_is_case_insensitive_for_non_special_schemes() {
    assert!(allow_matches(
        "github.com/login",
        &u("forward://GitHub.com/login/device")
    ));
}

#[test]
fn localhost_aliases() {
    assert!(allow_matches("localhost", &u("http://127.0.0.1:8400/cb")));
    assert!(allow_matches(
        "localhost",
        &u("http://localhost:12802/home/u/x.md")
    ));
}

#[test]
fn port_qualified_localhost_matches_exact_loopback_port() {
    assert!(allow_matches(
        "localhost:12802",
        &u("http://localhost:12802/x")
    ));
    assert!(allow_matches(
        "localhost:12802",
        &u("http://127.0.0.1:12802/x")
    ));
}

#[test]
fn port_qualified_localhost_rejects_other_port() {
    assert!(!allow_matches(
        "localhost:12802",
        &u("http://localhost:3000/")
    ));
}

#[test]
fn portless_localhost_pattern_matches_any_port() {
    assert!(allow_matches("localhost", &u("http://localhost:3000/")));
}

#[test]
fn port_qualified_localhost_matches_the_scheme_default_port() {
    assert!(allow_matches("localhost:80", &u("http://localhost/")));
    assert!(!allow_matches("localhost:80", &u("https://localhost/")));
}

#[test]
fn loopback_pattern_matches_localhost() {
    assert!(allow_matches("127.0.0.1", &u("http://localhost:8400/")));
}

#[test]
fn localhost_matches_ipv6_loopback() {
    assert!(allow_matches("localhost", &u("http://[::1]:8400/cb")));
}

#[test]
fn wildcard_matches_exactly_one_label() {
    assert!(!allow_matches(
        "*.awsapps.com",
        &u("https://nested.d-123.awsapps.com/start")
    ));
}

#[test]
fn auto_mode_always_opens() {
    let cfg = crate::config::Config {
        mode: crate::config::Mode::Auto,
        ..test_cfg(vec![])
    };
    assert_eq!(decide(&cfg, &u("https://anything.example")), Decision::Open);
}

#[test]
fn allowlist_miss_notifies() {
    let cfg = test_cfg(vec!["github.com/login".into()]);
    assert_eq!(decide(&cfg, &u("https://example.com/")), Decision::Notify);
}

#[test]
fn allowlist_hit_opens() {
    let cfg = test_cfg(vec!["github.com/login".into()]);
    assert_eq!(
        decide(&cfg, &u("https://github.com/login/device")),
        Decision::Open
    );
}

#[test]
fn empty_allowlist_notifies_everything() {
    let cfg = test_cfg(vec![]);
    assert_eq!(
        decide(&cfg, &u("https://github.com/login/device")),
        Decision::Notify
    );
}

fn test_cfg(allow: Vec<String>) -> crate::config::Config {
    crate::config::Config {
        mode: crate::config::Mode::Allowlist,
        opener: vec!["xdg-open".into()],
        notifier: vec![],
        ssh: vec!["ssh".into()],
        tunnel_host: "devbox-tunnel".into(),
        allow,
    }
}
