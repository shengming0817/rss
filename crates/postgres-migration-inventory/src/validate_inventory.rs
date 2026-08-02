//! Shared Hard-gate inventory validation for build.rs and unit tests.
//!
//! Anti-vacuity: these checks must remain executable outside `build.rs` so
//! duplicate / leftover / non-positive version / non-forward failures cannot
//! silently drift.

/// Reject reversible / down migrations — RSS only ships simple forward `.sql`.
pub fn ensure_forward_migration(path: &str, is_simple: bool) -> Result<(), String> {
    if is_simple {
        Ok(())
    } else {
        Err(format!(
            "only simple forward migrations are allowed (no .up.sql / .down.sql): {path}"
        ))
    }
}

/// Validate resolved forward-migration identities before embedding.
///
/// - leftover on-disk `.sql` not consumed by resolve → Err
/// - empty inventory → Err
/// - any `version < 1` → Err
/// - duplicate versions → Err (message lists all conflicting paths)
///
/// On success, `identities` are sorted by version ascending.
/// Each identity is `(version, checksum, path)`.
pub fn validate_inventory_identities(
    identities: &mut [(i64, [u8; 48], String)],
    leftover_sql_paths: &[String],
) -> Result<(), String> {
    if !leftover_sql_paths.is_empty() {
        return Err(format!(
            "migration .sql files not recognized by sqlx resolve_blocking: {}",
            leftover_sql_paths.join(", ")
        ));
    }

    if identities.is_empty() {
        return Err("migration inventory must not be empty".into());
    }

    identities.sort_by_key(|(version, _, _)| *version);

    for (version, _, path) in identities.iter() {
        if *version < 1 {
            return Err(format!(
                "migration version {version} is not a positive integer (must be >= 1): {path}"
            ));
        }
    }

    let mut i = 0;
    while i < identities.len() {
        let version = identities[i].0;
        let mut j = i + 1;
        while j < identities.len() && identities[j].0 == version {
            j += 1;
        }
        if j - i > 1 {
            let paths: Vec<&str> = identities[i..j]
                .iter()
                .map(|(_, _, path)| path.as_str())
                .collect();
            return Err(format!(
                "duplicate migration version {version}: {}",
                paths.join(", ")
            ));
        }
        i = j;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_forward_migration, validate_inventory_identities};

    fn id(version: i64, path: &str) -> (i64, [u8; 48], String) {
        let mut checksum = [0_u8; 48];
        checksum[0] = version.rem_euclid(256) as u8;
        (version, checksum, path.to_string())
    }

    #[test]
    fn validate_inventory_table() {
        let cases: &[(&str, Vec<(i64, [u8; 48], String)>, &[&str], bool, &[i64])] = &[
            (
                "unique positive versions",
                vec![id(1, "1.sql"), id(3, "3.sql"), id(2, "2.sql")],
                &[],
                true,
                &[1, 2, 3],
            ),
            (
                "gap allowed",
                vec![id(1, "1.sql"), id(3, "3.sql")],
                &[],
                true,
                &[1, 3],
            ),
            (
                "duplicate version",
                vec![id(1, "1a.sql"), id(2, "2a.sql"), id(2, "2b.sql")],
                &[],
                false,
                &[],
            ),
            (
                "leftover sql unresolved",
                vec![id(1, "1.sql")],
                &["/tmp/orphan.sql"],
                false,
                &[],
            ),
            (
                "version zero rejected",
                vec![id(0, "0.sql"), id(1, "1.sql")],
                &[],
                false,
                &[],
            ),
            (
                "negative version rejected",
                vec![id(-1, "n.sql"), id(1, "1.sql")],
                &[],
                false,
                &[],
            ),
            ("empty inventory", vec![], &[], false, &[]),
        ];

        for (label, mut identities, leftovers, expect_ok, expect_versions) in cases.iter().cloned()
        {
            let leftover_owned: Vec<String> = leftovers.iter().map(|s| (*s).to_string()).collect();
            let result = validate_inventory_identities(&mut identities, &leftover_owned);
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "{label}: expected ok={expect_ok}, got {result:?}"
            );
            if expect_ok {
                let versions: Vec<i64> = identities.iter().map(|(v, _, _)| *v).collect();
                assert_eq!(
                    versions, expect_versions,
                    "{label}: must sort to expected versions"
                );
            }
            if label == "duplicate version" {
                let err = result.expect_err("duplicate must err");
                assert!(
                    err.contains("2a.sql") && err.contains("2b.sql"),
                    "duplicate err must list conflicting paths: {err}"
                );
            }
        }
    }

    #[test]
    fn forward_only_rejects_non_simple() {
        assert!(ensure_forward_migration("0001_init.sql", true).is_ok());
        let down = ensure_forward_migration("0001_init.down.sql", false);
        assert!(down.is_err(), "{down:?}");
        assert!(
            down.unwrap_err().contains("0001_init.down.sql"),
            "err must include path"
        );
        let up = ensure_forward_migration("0001_init.up.sql", false);
        assert!(up.is_err(), "{up:?}");
    }
}
