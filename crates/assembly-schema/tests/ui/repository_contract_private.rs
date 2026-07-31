use assembly_schema::repository_contract::RepositoryContract;

fn forge(base: RepositoryContract) -> RepositoryContract {
    RepositoryContract {
        path_domain: "forged".to_owned(),
        ..base
    }
}

fn main() {}
