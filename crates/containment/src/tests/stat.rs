use crate::{Stat, parse_stat};

/// A `stat` line whose name field is `name`: state `S`, parent 99 and
/// starttime 123456.
fn line(name: &str) -> String {
    format!("4242 ({name}) S 99 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000 10")
}

#[test]
fn parse_stat_reads_state_parent_start_time_and_the_name_omp() {
    assert_eq!(
        parse_stat(&line("omp")),
        Some(Stat {
            state: 'S',
            parent: 99,
            start: 123_456,
            omp: true,
        })
    );
}

#[test]
fn only_the_name_omp_exactly_is_omp() {
    // omp's worker daemon broker runs the file `omp` and sets its own name with
    // prctl(PR_SET_NAME); the kernel keeps 15 bytes of it, `omp daemon brok`.
    // And the kernel never names a running omp `omp (deleted)`, even one whose
    // binary was deleted. The name starts after the first `(`, so `x (omp` is
    // not omp, though the text after its last `(` is.
    for name in [
        "omp daemon brok",
        "omp (deleted)",
        "xomp",
        "omp ",
        "omp)",
        "",
        "x (omp",
    ] {
        assert_eq!(
            parse_stat(&line(name)),
            Some(Stat {
                state: 'S',
                parent: 99,
                start: 123_456,
                omp: false,
            }),
            "{name:?}"
        );
    }
}

#[test]
fn a_comm_with_a_paren_and_spaces_cannot_move_the_stat_fields() {
    // The comm is `x) Z 1 2 3`: read after its first `)`, the line would say
    // zombie, parent 1. The fields begin after the last `)`.
    let line = "4242 (x) Z 1 2 3) R 77 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 1000 10";

    assert_eq!(
        parse_stat(line),
        Some(Stat {
            state: 'R',
            parent: 77,
            start: 555,
            omp: false,
        })
    );
}

#[test]
fn a_name_holding_a_paren_and_fields_is_not_omp_and_cannot_move_the_fields() {
    // Each name holds `) S 1 2 (`; the second one reads as `omp`, parent 1, if
    // the name ended at its first `)`. The name runs to the last `)`, and the
    // fields after it give parent 99 and starttime 123456.
    for name in ["x) S 1 2 (y", "omp) S 1 2 (y"] {
        assert_eq!(
            parse_stat(&line(name)),
            Some(Stat {
                state: 'S',
                parent: 99,
                start: 123_456,
                omp: false,
            }),
            "{name:?}"
        );
    }
}

#[test]
fn parse_stat_refuses_a_line_cut_before_the_start_time() {
    assert_eq!(parse_stat("4242 (omp) S 99 4242 4242 0"), None);
    assert_eq!(parse_stat("4242 (truncated"), None);
}

#[test]
fn parse_stat_refuses_a_line_with_no_open_paren_before_the_last_close_paren() {
    // `4242 omp) S 99 …`: no `(` at all, then one only after the last `)`.
    let unopened = line("omp").replacen('(', "", 1);
    assert_eq!(parse_stat(&unopened), None);
    assert_eq!(parse_stat(&format!("{unopened} (")), None);
}
