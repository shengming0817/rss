use audit::ports::CrossTenantReadScope;

fn bypass() {
    let _scope = CrossTenantReadScope::from_durable_append(todo!());
}

fn main() {}
