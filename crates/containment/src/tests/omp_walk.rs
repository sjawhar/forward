use std::collections::HashMap;

use crate::anchored::{AnchoredPeer, Process};
use crate::omp::{OmpProcess, is_omp_name, nearest_omp_from_with, omp_anchor_for_with};

#[derive(Clone)]
pub(super) struct Entry {
    name: &'static str,
    argv: &'static [&'static str],
    parent: u32,
    pub(super) start: u64,
}

pub(super) type Table = HashMap<u32, Entry>;

pub(super) fn table(entries: &[(u32, &'static str, &'static [&'static str], u32, u64)]) -> Table {
    entries
        .iter()
        .map(|&(pid, name, argv, parent, start)| {
            (
                pid,
                Entry {
                    name,
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
        omp: is_omp_name(entry.name),
    }
}

pub(super) fn lookup(table: Table) -> impl FnMut(u32) -> Option<Process> {
    move |pid| table.get(&pid).map(process)
}

fn chain(omp_hop: u32) -> Table {
    let mut processes = table(&[(100, "forward", &["forward"], 99, 1_000)]);
    let mut pid: u32 = 99;
    for hop in 1..=13 {
        let parent = if hop == 13 { 1 } else { pid.saturating_sub(1) };
        processes.insert(
            pid,
            Entry {
                name: if hop == omp_hop { "omp" } else { "sh" },
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
    // These boundary cases are written for the 12-hop cap; fail here, not
    // with a confusing table mismatch, if the cap changes.
    assert_eq!(crate::MAX_ANCESTRY_HOPS, 12);
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
        let pinned = nearest_omp_from_with(100, &mut lookup(processes.clone()));
        let anchor = omp_anchor_for_with(100, &mut lookup(processes));

        assert_eq!(anchor, expected, "{name}");
        assert_eq!(
            anchor,
            pinned.map(|omp| AnchoredPeer::new(omp.pid, omp.start)),
            "{name}"
        );
    }
}

#[test]
fn omp_walk_reads_each_process_once_and_keeps_the_start_of_that_read() {
    // Any second read of a pid sees another start time, as a pid recycled
    // between two reads would; the walk decides on the name and records the
    // start of the one read it made.
    let mut reads: Vec<u32> = Vec::new();
    let mut lookup = |pid: u32| {
        let again = reads.contains(&pid);
        reads.push(pid);
        let (name, parent, start): (&str, u32, u64) = match pid {
            40 => ("forward", 30, 400),
            30 => ("omp", 1, 300),
            _ => return None,
        };
        Some(Process {
            argv: Vec::new(),
            parent,
            start: if again {
                start.saturating_add(1)
            } else {
                start
            },
            omp: is_omp_name(name),
        })
    };

    let anchor = omp_anchor_for_with(40, &mut lookup);

    assert_eq!(anchor, Some(AnchoredPeer::new(30, 300)));
    assert_eq!(
        reads,
        [40, 30],
        "the caller, then its omp parent, each once"
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

// Reads this process's own `/proc` entry, which miri's isolation forbids.
#[test]
#[cfg_attr(miri, ignore)]
fn omp_anchor_stat_lookup_reports_what_the_full_read_does() {
    let pid = std::process::id();
    let stat = crate::omp::stat_process(pid).expect("stat lookup");
    let full = crate::anchored::read_process(pid).expect("full read");

    assert_eq!(
        (stat.parent, stat.start, stat.omp),
        (full.parent, full.start, full.omp)
    );
    assert!(stat.argv.is_empty(), "the walk never reads argv");
    assert!(!full.argv.is_empty(), "the full read still carries argv");
}
