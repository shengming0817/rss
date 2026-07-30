use consistency::{ProjectionApplyError, ProjectionApplyOutcome, ProjectionEventRecord};
use eventexec::{ProjectionId, ProjectionSelector, ProjectionTarget};
use futures::future::BoxFuture;
use vocab::ProjectionInputBinding;

struct RogueTarget;

impl ProjectionTarget for RogueTarget {
    fn projection(&self) -> &ProjectionId {
        unimplemented!()
    }

    fn bindings(&self) -> &[ProjectionInputBinding] {
        unimplemented!()
    }

    fn apply<'a>(
        &'a self,
        _selector: &'a ProjectionSelector,
        _event: ProjectionEventRecord,
    ) -> BoxFuture<'a, Result<ProjectionApplyOutcome, ProjectionApplyError>> {
        Box::pin(async { Ok(ProjectionApplyOutcome::Applied) })
    }
}

fn main() {}
