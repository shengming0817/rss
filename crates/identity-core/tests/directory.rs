use rss_identity_core::directory::{AccountQuery, Field};

#[test]
fn principal_uuid_operands_are_canonical_for_equal_and_set_queries() {
    use rss_identity_core::directory::Expression;
    let canonical = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    for representation in [
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa",
    ] {
        for operator in ["==", "!=", "=in=", "=out="] {
            let operand = if operator.contains("in") || operator.contains("out") {
                format!("('{representation}')")
            } else {
                format!("'{representation}'")
            };
            let query = AccountQuery::parse(
                Some(&format!("principalId{operator}{operand}")),
                None,
                None,
                None,
                50,
            )
            .unwrap();
            let Some(Expression::Compare { values, .. }) = query.filter() else {
                panic!("comparison required")
            };
            assert_eq!(values.as_slice(), [canonical.to_owned()]);
        }
    }
}

#[test]
fn query_preserves_false_and_composes_only_explicit_sources() {
    let q = AccountQuery::parse(
        Some("enabled==false;(login=icontains='a\\'b',memberActive==true)"),
        Some("-login"),
        Some("principalId,enabled"),
        None,
        1,
    )
    .unwrap();
    assert_eq!(q.sort().last().unwrap().field, Field::PrincipalId);
    assert_eq!(q.fields(), [Field::PrincipalId, Field::Enabled]);
    assert!(q.filter().is_some());
    assert!(
        AccountQuery::parse(Some("email=icontains='example.test'"), None, None, None, 50).is_err()
    );
    let q = AccountQuery::parse(
        Some("email=icontains='example.test'"),
        Some("displayName"),
        Some("principalId,email,profileStatus"),
        Some("local"),
        50,
    )
    .unwrap();
    assert!(q.needs_profiles());
    assert!(!q.needs_departments());
}

#[test]
fn field_types_and_budgets_reject_unsupported_queries() {
    for filter in [
        "enabled==0",
        "enabled=icontains=true",
        "unknown==true",
        "login==x;",
        "login=in=()",
        "principalId==nope",
        "departmentSnapshot==x",
        "login=isnull=false",
    ] {
        assert!(
            AccountQuery::parse(Some(filter), None, None, None, 50).is_err(),
            "{filter}"
        );
    }
    assert_eq!(
        AccountQuery::parse(None, None, None, None, 1024)
            .unwrap()
            .limit(),
        1024
    );
    for limit in [0, 1025] {
        assert!(AccountQuery::parse(None, None, None, None, limit).is_err());
    }
    for fields in ["", "principalId,principalId", "department", "password"] {
        assert!(AccountQuery::parse(None, None, Some(fields), None, 50).is_err());
    }
    for sort in ["login,-login", "departmentSnapshot", "unknown"] {
        assert!(AccountQuery::parse(None, Some(sort), None, None, 50).is_err());
    }
    assert!(AccountQuery::parse(Some(&"(".repeat(20)), None, None, None, 50).is_err());
    assert!(
        AccountQuery::parse(
            Some(&format!("login=='{}'", "a".repeat(1025))),
            None,
            None,
            None,
            50
        )
        .is_err()
    );
}

#[test]
fn department_predicates_require_an_exact_idp_source() {
    let id = "11111111-1111-4111-8111-111111111111";
    for field in ["department", "departmentSubtree"] {
        let filter = format!("{field}=='dept-01'");
        assert!(AccountQuery::parse(Some(&filter), None, None, Some("local"), 50).is_err());
        let q = AccountQuery::parse(
            Some(&filter),
            None,
            Some("principalId,departmentStatus,departmentSnapshot"),
            Some(id),
            50,
        )
        .unwrap();
        assert!(q.needs_departments());
        assert!(!q.needs_profiles());
    }
}

#[test]
fn fields_used_by_a_continuation_include_nested_filters_and_ordering() {
    let q = AccountQuery::parse(
        Some("enabled==true;(login==alice,email=isnull=true)"),
        Some("-departmentStatus"),
        Some("principalId"),
        Some("11111111-1111-4111-8111-111111111111"),
        1,
    )
    .unwrap();
    for field in [
        Field::Enabled,
        Field::Login,
        Field::Email,
        Field::DepartmentStatus,
        Field::PrincipalId,
    ] {
        assert!(q.used_fields().contains(&field));
    }
    let plain = AccountQuery::parse(None, None, Some("principalId"), Some("local"), 1).unwrap();
    assert!(!plain.needs_profiles() && !plain.needs_departments());
}
