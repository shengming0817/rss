//! SAGA-OPERATOR-MINT-01: ordinary HTTP auth evidence authority cannot name the isolated Saga
//! operator mint crate.

fn main() {
    let _ = sagaauthmint::SagaOperatorMint::capability();
}
