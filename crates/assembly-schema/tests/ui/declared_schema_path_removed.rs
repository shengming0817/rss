use assembly_schema::repository_contract::DeclaredSchema;

fn leak_schema_path(schema: DeclaredSchema<'_>) {
    let _ = schema.path();
}

fn main() {}
