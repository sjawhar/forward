use std::collections::HashMap;

use crate::anchored::{AnchoredPeer, Process};
use crate::omp::{OmpProcess, nearest_omp_from_with, omp_anchor_for_with};

#[derive(Clone)]
pub(super) struct Entry {
    executable: &'static str,
    argv: &'static [&'static str],
    parent: u32,
    pub(super) start: u64,
}

pub(super) type Table = HashMap<u32, Entry>;

pub(super) fn table(entries: &[(u32, &'static str, &'static [&'static str], u32, u64)]) -> Table {
    entries
        .iter()
        .map(|&(pid, executable, argv, parent, start)| {
            (
                pid,
                Entry {
                    executable,
                    argv,
                    parent,
                    start,
                },
            )
        })
        .collect()
}

fn process(entry: &Entry) -> Process {
    Process {
        argv: entry.argv.iter().map(|part| (*part).to_owned()).collect(),
        parent: entry.parent,
        start: entry.start,
    }
}

pub(super) fn lookup(table: Table) -> impl FnMut(u32) -> Option<Process> {
    move |pid| table.get(&pid).map(process)
}

pub(super) fn is_omp(table: Table) -> impl FnMut(u32) -> bool {
    move |pid| matches!(table.get(&pid), Some(entry) if entry.executable == "omp")
}

fn chain(omp_hop: u32) -> Table {
    let mut processes = table(&[(100, "forward", &["forward"], 99, 1_000)]);
    let mut pid: u32 = 99;
    for hop in 1..=13 {
        let parent = if hop == 13 { 1 } else { pid.saturating_sub(1) };
        processes.insert(
            pid,
            Entry {
                executable: if hop == omp_hop { "omp" } else { "sh" },
                argv: if hop == omp_hop { &["omp"] } else { &["sh"] },
                parent,
                start: u64::from(pid),
            },
        );
        pid = parent;
    }
    processes
}

#[test]
fn omp_anchor_walk_boundaries_and_termination() {
    let cases = [
        (
            "twelfth ancestor",
            chain(12),
            Some(AnchoredPeer::new(88, 88)),
        ),
        ("thirteenth ancestor", chain(13), None),
        (
            "cycle",
            table(&[
                (100, "forward", &["forward"], 99, 100),
                (99, "sh", &["sh"], 98, 99),
                (98, "sh", &["sh"], 99, 98),
            ]),
            None,
        ),
        (
            "init parent",
            table(&[(100, "forward", &["forward"], 1, 100)]),
            None,
        ),
    ];

    for (name, processes, expected) in cases {
        let pinned = nearest_omp_from_with(
            100,
            &mut lookup(processes.clone()),
            &mut is_omp(processes.clone()),
        );
        let anchor =
            omp_anchor_for_with(100, &mut lookup(processes.clone()), &mut is_omp(processes));

        assert_eq!(anchor, expected, "{name}");
        assert_eq!(
            anchor,
            pinned.map(|omp| AnchoredPeer::new(omp.pid, omp.start)),
            "{name}"
        );
    }
}

#[test]
fn omp_anchor_rejects_a_start_change_while_reading_the_executable() {
    let mut candidate_reads = 0;
    let mut lookup = move |pid| match pid {
        40 => Some(Process {
            argv: vec!["forward".to_owned()],
            parent: 30,
            start: 400,
        }),
        30 => {
            candidate_reads += 1;
            Some(Process {
                argv: vec!["omp".to_owned()],
                parent: 1,
                start: if candidate_reads == 1 { 300 } else { 301 },
            })
        }
        _ => None,
    };

    assert_eq!(
        omp_anchor_for_with(40, &mut lookup, &mut |pid| pid == 30),
        None
    );
}

#[test]
fn omp_anchor_process_running_states() {
    let omp = OmpProcess {
        pid: 30,
        start: 300,
    };
    let cases = [
        ("same start", Some((300, 'S')), true),
        ("other start", Some((301, 'S')), false),
        ("zombie", Some((300, 'Z')), false),
        ("dead state", Some((300, 'X')), false),
        ("unreadable", None, false),
    ];

    for (name, state, expected) in cases {
        assert_eq!(omp.is_running_with(&mut |_| state), expected, "{name}");
    }
}
