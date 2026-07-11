struct ForgedConsistency;

impl vocab::http::HttpConsistencyClass for ForgedConsistency {
    const LEVEL: vocab::HttpConsistencyLevel = vocab::HttpConsistencyLevel::LocalOnly;
}

fn main() {}
