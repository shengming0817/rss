use rss_identity_core::department::DepartmentSnapshot;
use serde_json::{Value, json};

fn snapshot() -> Value {
    json!({"version":1,"sourceRevision":"revision-42","nodes":[
        {"id":"root","displayName":"Company","parentId":null},
        {"id":"engineering","displayName":"Engineering","parentId":"root"},
        {"id":"sales","displayName":"Sales","parentId":"root"}
    ],"memberships":["engineering"]})
}

#[test]
fn complete_tree_preserves_exact_ids_revision_and_explicit_unassigned() {
    let value = snapshot();
    let parsed: DepartmentSnapshot = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(parsed.source_revision(), "revision-42");
    assert_eq!(parsed.nodes().len(), 3);
    assert_eq!(parsed.memberships()[0].as_str(), "engineering");
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    let mut unassigned = snapshot();
    unassigned["memberships"] = json!([]);
    assert!(
        serde_json::from_value::<DepartmentSnapshot>(unassigned)
            .unwrap()
            .memberships()
            .is_empty()
    );
}

#[test]
fn rejects_incomplete_ambiguous_and_unversioned_assertions() {
    let base = snapshot();
    let mut invalid = vec![json!(null), json!("engineering"), json!([])];
    for (key, value) in [
        ("version", json!(2)),
        ("sourceRevision", json!("")),
        ("memberships", json!(["missing"])),
        ("memberships", json!(["engineering", "engineering"])),
        ("nodes", json!([])),
        ("issuer", json!("https://attacker.test")),
    ] {
        let mut input = base.clone();
        input[key] = value;
        invalid.push(input);
    }
    for key in ["version", "sourceRevision", "memberships", "nodes"] {
        let mut input = base.clone();
        input.as_object_mut().unwrap().remove(key);
        invalid.push(input);
    }
    for (index, key, value) in [
        (1, "id", json!("root")),
        (1, "parentId", json!("missing")),
        (1, "parentId", json!(null)),
        (0, "parentId", json!("engineering")),
        (1, "parentId", json!("sales")),
        (1, "id", json!(" engineering")),
        (1, "displayName", json!("")),
    ] {
        let mut input = base.clone();
        input["nodes"][index][key] = value;
        if index == 1 && input["nodes"][1]["parentId"] == "sales" {
            input["nodes"][2]["parentId"] = json!("engineering");
        }
        invalid.push(input);
    }
    let mut missing_parent = base.clone();
    missing_parent["nodes"][0]
        .as_object_mut()
        .unwrap()
        .remove("parentId");
    invalid.push(missing_parent);
    for input in invalid {
        assert!(
            serde_json::from_value::<DepartmentSnapshot>(input.clone()).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn tree_membership_and_depth_have_explicit_limits() {
    for (count, chain, members, valid) in [
        (1024, false, 1024, true),
        (1025, false, 1, false),
        (16, true, 1, true),
        (17, true, 1, false),
        (20, false, 17, true),
    ] {
        let nodes: Vec<_> = (0..count).map(|i| json!({"id":format!("n{i}"),"displayName":format!("Node {i}"),"parentId":if i == 0 {None} else {Some(format!("n{}",if chain {i-1} else {0}))}})).collect();
        let memberships: Vec<_> = (0..members).map(|i| format!("n{i}")).collect();
        let input =
            json!({"version":1,"sourceRevision":"r1","nodes":nodes,"memberships":memberships});
        assert_eq!(
            serde_json::from_value::<DepartmentSnapshot>(input).is_ok(),
            valid
        );
    }
}
