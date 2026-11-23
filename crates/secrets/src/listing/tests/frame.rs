use super::*;
use crate::proto::MAX_FRAME_BYTES;

/// One capability row at 100 s before its deadline: 33 bytes.
const CAPABILITY_ROW: &str = "capability\tbrowser\t-\tactive\t100s\n";

/// Fill the secret-grant table with `full` rows of 128-byte keys and one row
/// of a `last`-byte key, each row its key and `\tsession\t43200s\n` (16 bytes),
/// and return that table as the answer writes it alone.
fn first_table(tables: &mut Tables, t: Instant, full: usize, last: usize) -> String {
    for index in 0..full {
        let key = format!("K{index:0>127}");
        tables.grant(session(), &key, t, Duration::from_hours(12));
    }
    tables.grant(session(), &"L".repeat(last), t, Duration::from_hours(12));
    tables.render(t)
}

/// 200 capability grants with this deadline: past one frame of rows.
fn many_capability_grants(tables: &mut Tables, deadline: Instant) {
    for _ in 0..200 {
        tables.capability(deadline);
    }
}

/// Assert that `answer` is `before`, the KIND header, whole capability rows
/// and a `more` row counting the rest of the 200, in one frame, with no room
/// left for one more row.
fn assert_capability_rows_held_to_frame(answer: &str, before: &str) {
    let shown = answer.matches(CAPABILITY_ROW).count();
    assert!(shown > 0);
    let dropped = 200_usize.checked_sub(shown).unwrap();
    assert_eq!(
        answer,
        format!(
            "{before}{KIND}{}more\t-\t-\t{dropped} not shown\t-\n",
            CAPABILITY_ROW.repeat(shown)
        )
    );
    assert!(answer.len() <= MAX_FRAME_BYTES);
    // One more row would add its bytes less at most one digit of the count.
    let one_more_row = answer.len().saturating_add(CAPABILITY_ROW.len());
    assert!(one_more_row.saturating_sub(1) > MAX_FRAME_BYTES);
}

#[test]
fn a_kind_table_past_one_frame_alone_ends_in_a_more_row() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    many_capability_grants(&mut tables, t + secs(100));

    let answer = tables.render(t);

    assert!(answer.starts_with(KIND));
    assert_capability_rows_held_to_frame(&answer, "");
}

#[test]
fn a_kind_table_past_one_frame_beside_a_short_first_table_ends_in_a_more_row() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    tables.grant(session(), "K", t, Duration::from_hours(12));
    many_capability_grants(&mut tables, t + secs(100));

    let answer = tables.render(t);

    let first = format!("{SECRET_GRANT}K\tsession\t43200s\n\n");
    assert_capability_rows_held_to_frame(&answer, &first);
}

#[test]
fn a_request_row_that_does_not_fit_is_counted_in_the_more_row() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let first = first_table(&mut tables, t, 27, 37);
    assert_eq!(first.len(), 3968);
    tables.request(session(), &"R".repeat(128), t);

    let answer = tables.render(t);

    assert_eq!(
        answer,
        format!("{first}\n{KIND}more\t-\t-\t1 not shown\t-\n")
    );
    assert!(!answer.contains("request\t"));
    assert!(answer.len() <= MAX_FRAME_BYTES);
}

#[test]
fn a_first_table_with_no_room_for_header_and_more_row_leaves_out_the_second() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let first = first_table(&mut tables, t, 27, 111);
    assert_eq!(first.len(), 4042);
    tables.request(session(), "R", t);
    assert_eq!(
        tables.render(t),
        format!("{first}\n{KIND}more\t-\t-\t1 not shown\t-\n"),
        "the empty line, the header and the more row take the last 54 bytes"
    );

    let (mut tables, t) = (Tables::new(), Instant::now());
    let first = first_table(&mut tables, t, 27, 112);
    assert_eq!(first.len(), 4043);
    tables.request(session(), "R", t);

    let answer = tables.render(t);

    assert_eq!(answer, first);
    assert_ne!(answer, NONE);
}

#[test]
fn a_first_table_past_one_frame_is_written_whole_without_the_second() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let first = first_table(&mut tables, t, 29, 1);
    assert!(first.len() > MAX_FRAME_BYTES);
    assert!(first.starts_with(SECRET_GRANT));
    assert_eq!(first.lines().count(), 31);
    tables.request(session(), "R", t);
    tables.capability(t + secs(100));

    let answer = tables.render(t);

    assert_eq!(answer, first);
    assert!(!answer.contains(KIND));
}
