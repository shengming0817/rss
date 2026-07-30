use testkit::projection_conformance::{ProjectionConformanceError, ProjectionObservation};

async fn behavior() -> Result<ProjectionObservation, ProjectionConformanceError> {
    unreachable!()
}

testkit::projection_target_conformance! {
    cases: {
        same_fact_duplicate => { same_fact_duplicate => behavior },
        atomic_apply => { atomic_apply => behavior },
        same_key_conflict => { same_key_conflict => behavior },
        persistent_out_of_order => { persistent_out_of_order => behavior },
        identity_mismatch => { identity_mismatch => behavior },
        confirmed_rollback => { confirmed_rollback => behavior },
        commit_unknown_replay => { commit_unknown_replay => behavior },
        rollback_failed => { rollback_failed => behavior },
    }
}

fn main() {}
