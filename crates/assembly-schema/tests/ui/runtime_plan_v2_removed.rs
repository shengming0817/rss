use assembly_schema::{RuntimePlan, RuntimePlanV2Input};

fn legacy_runtime_plan(input: RuntimePlanV2Input) {
    let _ = RuntimePlan::compile_v2(input);
}

fn main() {}
