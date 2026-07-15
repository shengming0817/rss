use identity::ports::RoleBindingLifecycle;

fn old_binding_read<T: RoleBindingLifecycle>() {
    let _ = T::list_for_subject;
}

fn main() {}
