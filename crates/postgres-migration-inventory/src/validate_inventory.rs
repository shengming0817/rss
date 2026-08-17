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

    struct InventoryCase {
        label: &'static str,
        identities: Vec<(i64, [u8; 48], String)>,
        leftovers: &'static [&'static str],
        expected: Expected,
    }

    enum Expected {
        Sorted(&'static [i64]),
        Rejected(&'static [&'static str]),
    }

    #[test]
    fn validate_inventory_table() -> Result<(), String> {
        let cases = [
            InventoryCase {
                label: "unique positive versions",
                identities: vec![id(1, "1.sql"), id(3, "3.sql"), id(2, "2.sql")],
                leftovers: &[],
                expected: Expected::Sorted(&[1, 2, 3]),
            },
            InventoryCase {
                label: "gap allowed",
                identities: vec![id(1, "1.sql"), id(3, "3.sql")],
                leftovers: &[],
                expected: Expected::Sorted(&[1, 3]),
            },
            InventoryCase {
                label: "duplicate version",
                identities: vec![id(1, "1a.sql"), id(2, "2a.sql"), id(2, "2b.sql")],
                leftovers: &[],
                expected: Expected::Rejected(&[
                    "duplicate migration version 2",
                    "2a.sql",
                    "2b.sql",
                ]),
            },
            InventoryCase {
                label: "leftover sql unresolved",
                identities: vec![id(1, "1.sql")],
                leftovers: &["/tmp/orphan.sql"],
                expected: Expected::Rejected(&["not recognized", "/tmp/orphan.sql"]),
            },
            InventoryCase {
                label: "version zero rejected",
                identities: vec![id(0, "0.sql"), id(1, "1.sql")],
                leftovers: &[],
                expected: Expected::Rejected(&["version 0", "0.sql"]),
            },
            InventoryCase {
                label: "negative version rejected",
                identities: vec![id(-1, "n.sql"), id(1, "1.sql")],
                leftovers: &[],
                expected: Expected::Rejected(&["version -1", "n.sql"]),
            },
            InventoryCase {
                label: "empty inventory",
                identities: vec![],
                leftovers: &[],
                expected: Expected::Rejected(&["must not be empty"]),
            },
        ];

        for mut case in cases {
            let leftovers = case
                .leftovers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            match (
                validate_inventory_identities(&mut case.identities, &leftovers),
                case.expected,
            ) {
                (Ok(()), Expected::Sorted(expected)) => {
                    let versions = case
                        .identities
                        .iter()
                        .map(|(version, _, _)| *version)
                        .collect::<Vec<_>>();
                    assert_eq!(versions, expected, "{}: sorted versions", case.label);
                }
                (Err(error), Expected::Rejected(fragments)) => {
                    assert!(
                        fragments.iter().all(|fragment| error.contains(fragment)),
                        "{}: missing expected error fragment in {error:?}",
                        case.label
                    );
                }
                (Ok(()), Expected::Rejected(_)) => {
                    return Err(format!("{}: expected rejection", case.label));
                }
                (Err(error), Expected::Sorted(_)) => {
                    return Err(format!(
                        "{}: expected sorted inventory: {error}",
                        case.label
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn forward_only_rejects_non_simple() -> Result<(), String> {
        assert!(ensure_forward_migration("0001_init.sql", true).is_ok());
        match ensure_forward_migration("0001_init.down.sql", false) {
            Err(error) => assert!(
                error.contains("0001_init.down.sql"),
                "err must include path"
            ),
            Ok(()) => return Err("down migration must be rejected".into()),
        }
        assert!(
            ensure_forward_migration("0001_init.up.sql", false)
                .is_err_and(|error| error.contains("0001_init.up.sql")),
            "up migration must be rejected with its path"
        );
        Ok(())
    }
}
