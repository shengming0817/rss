async fn behavior() -> Result<(), ()> {
    Ok(())
}

testkit::projection_target_conformance! {
    cases: {
        atomic_apply => { atomic_apply => behavior },
        same_fact_duplicate => { same_fact_duplicate => behavior },
        same_key_conflict => { same_key_conflict => behavior },
        persistent_out_of_order => { persistent_out_of_order => behavior },
        identity_mismatch => { identity_mismatch => behavior },
        confirmed_rollback => { confirmed_rollback => behavior },
        commit_unknown_replay => { commit_unknown_replay => behavior },
        rollback_failed => { rollback_failed => behavior },
    }
}

fn main() {}
