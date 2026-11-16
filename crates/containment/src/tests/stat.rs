use crate::{Stat, parse_stat};

#[test]
fn parse_stat_reads_state_parent_and_start_time() {
    let line = "4242 (omp) S 99 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000 10";

    assert_eq!(
        parse_stat(line),
        Some(Stat {
            state: 'S',
            parent: 99,
            start: 123_456,
        })
    );
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
        })
    );
}

#[test]
fn parse_stat_refuses_a_line_cut_before_the_start_time() {
    assert_eq!(parse_stat("4242 (omp) S 99 4242 4242 0"), None);
    assert_eq!(parse_stat("4242 (truncated"), None);
}
