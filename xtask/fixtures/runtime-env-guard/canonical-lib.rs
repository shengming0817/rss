struct OperatorRuntimeCapability<'a>(&'a ());
struct RuntimeConfigSnapshot;
impl RuntimeConfigSnapshot { fn capture_process_snapshot() {} }
fn prepare_runtime_kernel() { RuntimeConfigSnapshot::capture_process_snapshot(); }
