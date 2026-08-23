use crate::browser::request::{self, GrantStatus};

/// Report whether the invoking session holds a live grant. Informational,
/// like the pcsc row: holding no grant is not ill health.
pub(super) fn report() {
    super::print_line(line(request::status(&request::socket_path())));
}

fn line(status: GrantStatus) -> String {
    match status {
        GrantStatus::Unreachable => {
            "browser grant: info — no request socket answered; forward serve is not running here (grants are devbox-side)"
                .to_owned()
        }
        GrantStatus::None => {
            "browser grant: none for this session — secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m"
                .to_owned()
        }
        GrantStatus::Live {
            port,
            remaining_secs,
        } => format!(
            "browser grant: live for this session at http://127.0.0.1:{port} ({remaining_secs}s left)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_grant_state_renders_its_own_row() {
        assert!(line(GrantStatus::Unreachable).contains("forward serve is not running"));
        let none = line(GrantStatus::None);
        assert!(none.contains("none for this session"));
        assert!(none.contains("forward browser grant --ttl 30m"));
        let live = line(GrantStatus::Live {
            port: 12_811,
            remaining_secs: 900,
        });
        assert!(live.contains("http://127.0.0.1:12811"));
        assert!(live.contains("900s left"));
    }
}
