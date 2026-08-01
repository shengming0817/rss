use eventexec::{ProjectionId, ProjectionTargetDefinition};

fn forge() -> ProjectionTargetDefinition {
    ProjectionTargetDefinition {
        contract: vocab::ContractBinding::from_static(
            "audit",
            "audit.session-projection",
            "v2",
            "sha256:8750ef9b30912c837637ee30ee712e1572903fdaa59514fd486f2d0ab15fa071",
        ),
        projection: ProjectionId::parse("audit.session-projection").unwrap(),
        input_generation:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap(),
    }
}

fn main() {}
