use super::*;

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_grant_table_keeps_omp_for_tokens_and_revokes_a_vanished_process() {
    let mut table = GrantTable::default();
    let now = Instant::now();
    let omp_scope = Scope::Omp {
        pid: u32::MAX,
        start: 0,
    };
    table.insert(
        Scope::Session(token(0xaa)),
        name("SESSION"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );
    table.insert(
        omp_scope.clone(),
        name("OMP"),
        secret("v"),
        now,
        origin("test"),
        Duration::from_hours(12),
    );

    table.revoke_tokens(&[token(0xaa)]);
    assert!(table.lookup(&omp_scope, &name("OMP"), now).is_some());
    assert_eq!(
        listed(&table, now),
        [("OMP".to_owned(), "omp 4294967295".to_owned(), 43_200)]
    );

    table.revoke_vanished_scopes();
    assert!(table.is_empty());
}
