use assembly_schema::ParsedRuntimePlan;

fn main() {
    let _ = ParsedRuntimePlan::from_json_slice(b"{}");
}
