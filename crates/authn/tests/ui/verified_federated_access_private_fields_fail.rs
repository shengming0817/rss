fn main() {
    let _forged = authn::VerifiedFederatedAccess {
        verified_jwt: jwt(),
        principal: principal(),
    };
}

fn jwt() -> authn::VerifiedJwt {
    loop {}
}

fn principal() -> std::sync::Arc<authn::Principal> {
    loop {}
}
