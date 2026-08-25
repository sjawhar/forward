use super::daemon_support::{send, start, stub, wait_for};

#[test]
fn opener_stripping_reentry_marker_is_rate_limited() {
    // Given: an opener that strips its marker before resending the URL to the daemon.
    let dir = tempfile::tempdir().unwrap();
    let reentries = dir.path().join("reentries");
    let port_file = dir.path().join("daemon-port");
    let opener = stub(
        dir.path(),
        "opener",
        &format!(
            r#"
count_file={}
count=$(cat "$count_file" 2>/dev/null || printf 0)
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
if [ "$count" -le 3 ]; then
  env -u FORWARD_OPENER_REENTRY bash -c 'test -z "${{FORWARD_OPENER_REENTRY+x}}" || exit 1; exec 3<>/dev/tcp/127.0.0.1/"$(cat "$1")"; printf "%s\n" "$2" >&3' -- "{}" "$1"
fi
"#,
            reentries.display(),
            port_file.display()
        ),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );
    std::fs::write(&port_file, port.to_string()).unwrap();

    // When: the opener loops the same URL back after removing the marker.
    send(port, "https://example.com/redirect");

    // Then: the fourth open is rejected before another opener process starts.
    daemon.wait_for_log(
        "dropping https://example.com/redirect: opened 4 times in 2s, refusing to loop",
    );
    assert_eq!(wait_for(&reentries).trim(), "3");
}
