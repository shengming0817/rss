#![allow(dead_code)]

mod auth {
    fn authorization_core() {
        let _ = diagctx::correlation();
    }
}

mod auth_audit {
    fn allowed_after_decision() {
        let _ = diagctx::correlation();
    }
}

mod observability {
    fn allowed_without_authorization_impl() {
        let _ = diagctx::correlation();
    }
}

mod same_name_is_not_the_crate {
    mod diagctx {
        pub fn correlation() -> Option<()> {
            None
        }
    }

    fn allowed() {
        let _ = diagctx::correlation();
    }
}

fn main() {}
