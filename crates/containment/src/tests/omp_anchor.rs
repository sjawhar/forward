use super::SESSION;
use super::omp_walk::{is_omp, lookup, table};
use crate::anchored::{AnchoredPeer, anchor_for_with};
use crate::omp::{nearest_omp_from_with, omp_anchor_for_with};

const GRANT: &[&str] = &["forward", "browser", "grant"];
const RPC: &[&str] = &["omp", "--model", "@default", "--mode", "rpc"];

#[test]
fn omp_anchor_cases_use_the_nearest_omp_executable() {
    let cases = [
        (
            "rpc omp directly above the command",
            table(&[(40, "forward", GRANT, 30, 400), (30, "omp", RPC, 1, 300)]),
            Some(AnchoredPeer::new(30, 300)),
            AnchoredPeer::new(30, 300),
        ),
        (
            "rpc omp above script and sh",
            table(&[
                (40, "forward", GRANT, 39, 400),
                (39, "sh", &["sh", "-c", "forward"], 38, 390),
                (38, "script", &["script", "-qec", "forward"], 30, 380),
                (30, "omp", RPC, 1, 300),
            ]),
            Some(AnchoredPeer::new(30, 300)),
            AnchoredPeer::new(30, 300),
        ),
        (
            "resume omp without an inner omp",
            table(&[
                (40, "forward", GRANT, 30, 400),
                (30, "omp", &["omp", "--resume", SESSION], 1, 300),
            ]),
            Some(AnchoredPeer::new(30, 300)),
            AnchoredPeer::new(30, 300),
        ),
        (
            "rpc omp inside a resume omp",
            table(&[
                (40, "forward", GRANT, 12, 400),
                (12, "sh", &["sh", "-c", "forward"], 11, 390),
                (11, "omp", &["omp", "--mode", "rpc"], 10, 380),
                (10, "omp", &["omp", "--resume", SESSION], 1, 300),
            ]),
            Some(AnchoredPeer::new(11, 380)),
            AnchoredPeer::new(11, 380),
        ),
        (
            "argv claims omp but its executable is not omp",
            table(&[
                (40, "forward", GRANT, 30, 400),
                (30, "sh", &["omp", "--resume", SESSION], 20, 300),
                (20, "sh", &["sh"], 1, 200),
            ]),
            None,
            AnchoredPeer::new(30, 300),
        ),
        (
            "no omp ancestor",
            table(&[
                (40, "forward", GRANT, 30, 400),
                (30, "sh", &["sh"], 20, 300),
                (20, "sshd", &["sshd"], 1, 200),
            ]),
            None,
            AnchoredPeer::new(30, 300),
        ),
    ];

    for (name, processes, expected_omp, expected_fallback) in cases {
        let omp = nearest_omp_from_with(
            40,
            &mut lookup(processes.clone()),
            &mut is_omp(processes.clone()),
        );
        let omp_anchor = omp_anchor_for_with(
            40,
            &mut lookup(processes.clone()),
            &mut is_omp(processes.clone()),
        );
        let anchor = anchor_for_with(40, &mut lookup(processes.clone()), &mut is_omp(processes));

        assert_eq!(
            omp_anchor,
            omp.map(|omp| AnchoredPeer::new(omp.pid, omp.start)),
            "{name}"
        );
        assert_eq!(anchor, omp_anchor.or(Some(expected_fallback)), "{name}");
        assert_eq!(omp_anchor, expected_omp, "{name}");
    }
}

#[test]
fn omp_anchor_admits_the_omp_process_and_rejects_a_reused_pid() {
    let processes = table(&[
        (40, "forward", &["forward"], 30, 400),
        (30, "omp", &["omp", "--mode", "rpc"], 1, 300),
    ]);
    let anchor = omp_anchor_for_with(
        40,
        &mut lookup(processes.clone()),
        &mut is_omp(processes.clone()),
    )
    .expect("omp anchor");

    assert!(anchor.contains_with(30, &mut lookup(processes.clone())));
    let mut recycled = processes;
    recycled.get_mut(&30).expect("omp entry").start = 301;
    assert!(!anchor.contains_with(30, &mut lookup(recycled)));
}
