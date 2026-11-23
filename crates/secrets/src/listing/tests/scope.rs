use super::*;

#[test]
fn tty_and_omp_scopes_are_written_as_tty_path_and_omp_pid() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let tty = "/dev/pts/3".to_owned();
    let boot_id = "boot".to_owned();
    tables.grant(Scope::Tty { tty, boot_id }, "T", t, secs(100));
    let omp = Scope::Omp {
        pid: 4242,
        start: 7,
    };
    tables.request(omp, "CAP_BROWSER", t);

    let expected = format!(
        "{SECRET_GRANT}T\ttty /dev/pts/3\t100s\n\n\
         {KIND}request\tCAP_BROWSER\tomp 4242\tpending, id 1\t90s\n"
    );
    assert_eq!(tables.render(t), expected);
}

#[test]
fn a_tty_is_written_with_each_control_character_escaped() {
    let (mut tables, t) = (Tables::new(), Instant::now());
    let tty = "/x\0\x1b[2Ky\r".to_owned();
    let boot_id = "boot".to_owned();
    tables.request(Scope::Tty { tty, boot_id }, "K", t);

    let answer = tables.render(t);
    let row = format!(
        "request\tK\ttty {}\tpending, id 1\t90s\n",
        r"/x\0\u{001B}[2Ky\r"
    );
    assert_eq!(answer, format!("{KIND}{row}"));
    let control = |byte: u8| (byte < 0x20 && !matches!(byte, b'\t' | b'\n')) || byte == 0x7f;
    assert!(!answer.bytes().any(control), "{answer:?}");
}
