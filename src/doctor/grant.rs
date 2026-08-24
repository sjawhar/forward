use crate::browser::request::{self, GrantStatus};

/// Report whether the invoking session holds a live grant. Informational,
/// like the pcsc row: holding no grant is not ill health.
pub(super) fn report() {
    super::print_line(line(request::status(&request::socket_path())));
}

fn line(status: GrantStatus) -> String {
    match status {
        GrantStatus::Unreachable => {
            "browser grant: info — grant status unavailable; no valid STATUS reply from the local request socket"
                .to_owned()
        }
        GrantStatus::None => {
            "browser grant: none for this session — forward browser grant --ttl 30m".to_owned()
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
        assert_eq!(
            line(GrantStatus::Unreachable),
            "browser grant: info — grant status unavailable; no valid STATUS reply from the local request socket"
        );
        assert_eq!(
            line(GrantStatus::None),
            "browser grant: none for this session — forward browser grant --ttl 30m"
        );
        let live = line(GrantStatus::Live {
            port: 12_811,
            remaining_secs: 900,
        });
        assert!(live.contains("http://127.0.0.1:12811"));
        assert!(live.contains("900s left"));
    }
}
