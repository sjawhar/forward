use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use forward::config::Config;
use url::Url;

use crate::process::{WaitResult, run_command, stderr};

const NOTIFIER_APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

// COSMIC delivers no notification action callbacks (pop-os/cosmic-notifications#100), so the
// built-in notifier hands the URL off instead of pretending to gate it; a configured notifier
// can gate because it owns its UI and returns an explicit approval result.
pub(super) fn notify_url(cfg: &Config, url: &Url) -> bool {
    let Some((program, arguments)) = cfg.notifier.split_first() else {
        notify_builtin(cfg, url);
        return false;
    };
    let mut command = Command::new(program);
    command.args(arguments).arg(url.as_str());
    notify_with_approval(command, url)
}

fn notify_builtin(cfg: &Config, url: &Url) {
    let copied = copy_url(cfg, url);
    let summary = if copied {
        "forward: not in allowlist — URL copied"
    } else {
        "forward: not in allowlist — URL not copied"
    };
    let mut command = Command::new("notify-send");
    command.args([
        "--app-name=forward",
        "--urgency=critical",
        summary,
        url.as_str(),
    ]);
    spawn_notification(command, url);
    if copied {
        eprintln!("forward: not allowlisted; notified user and copied to clipboard: {url}");
    } else if cfg.clipboard.is_empty() {
        eprintln!("forward: not allowlisted; notified user (no clipboard configured): {url}");
    } else {
        eprintln!("forward: not allowlisted; notified user but clipboard copy failed: {url}");
    }
}

fn spawn_notification(mut command: Command, url: &Url) {
    match command.spawn() {
        Ok(mut child) => {
            let url = url.to_string();
            drop(thread::spawn(move || match child.wait() {
                Ok(status) if !status.success() => {
                    eprintln!("forward: notification failed for {url}: {status}");
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("forward: failed to wait for notification for {url}: {error}")
                }
            }));
        }
        Err(error) => eprintln!("forward: failed to notify for {url}: {error}"),
    }
}

fn copy_url(cfg: &Config, url: &Url) -> bool {
    let Some((program, arguments)) = cfg.clipboard.split_first() else {
        return false;
    };
    let mut command = Command::new(program);
    // No inherited pipes beyond stdin: a clipboard tool has to keep a process alive
    // to own the selection, and wl-copy does that by forking. A piped stderr would be
    // inherited by that survivor, so reading it to EOF never returns and the calling
    // thread blocks forever. Status alone is enough to branch on, so discard the rest.
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("forward: clipboard failed for {url}: {error}");
            return false;
        }
    };
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("clipboard stdin was unavailable"))
        .and_then(|mut stdin| stdin.write_all(url.as_str().as_bytes()));
    // wait(), not wait_with_output(): the forked survivor holds no pipe of ours, but it
    // does outlive its parent, so only the parent is waited on. That also reaps it
    // instead of leaving a zombie per copy.
    match (write_result, child.wait()) {
        (Ok(()), Ok(status)) if status.success() => true,
        (Ok(()), Ok(status)) => {
            eprintln!("forward: clipboard failed for {url}: {status}");
            false
        }
        (Err(error), _) | (Ok(()), Err(error)) => {
            eprintln!("forward: clipboard failed for {url}: {error}");
            false
        }
    }
}

fn notify_with_approval(command: Command, url: &Url) -> bool {
    match run_command(command, NOTIFIER_APPROVAL_TIMEOUT) {
        Ok(WaitResult::Exited(output)) if !output.status.success() => {
            eprintln!(
                "forward: notification failed for {url}: {:?}",
                stderr(&output)
            );
            false
        }
        Ok(WaitResult::Exited(output)) => {
            let received = String::from_utf8_lossy(&output.stdout);
            if received.trim() == "default" {
                true
            } else if received.is_empty() {
                eprintln!("forward: notification declined: {url}");
                false
            } else {
                eprintln!("forward: notification declined: {url}: {received:?}");
                false
            }
        }
        Ok(WaitResult::TimedOut) => {
            // A killed notifier may have a captured `default`, but it is untrusted and never approves.
            eprintln!("{}", notification_expired_message(url));
            false
        }
        Err(error) => {
            eprintln!("forward: failed to notify for {url}: {error}");
            false
        }
    }
}

fn notification_expired_message(url: &Url) -> String {
    format!("forward: notification expired without approval: {url}")
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::notification_expired_message;

    #[test]
    fn notification_expiry_log_names_unapproved_url() {
        // Given: an approval prompt for a non-allowlisted URL.
        let url = Url::parse("https://example.com/expired").unwrap();

        // When: the notifier reaches its bounded approval timeout.
        let message = notification_expired_message(&url);

        // Then: the daemon reports expiry without implying a response was received.
        assert_eq!(
            message,
            "forward: notification expired without approval: https://example.com/expired"
        );
    }
}
