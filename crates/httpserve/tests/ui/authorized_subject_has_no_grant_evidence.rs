fn inspect(subject: &httpserve::AuthorizedSubject) {
    let _ = subject.current_auth_grant();
}

fn main() {}
