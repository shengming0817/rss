use identity::ports::{
    EqualityOperand, EqualityOperator, EqualityPredicate, Operator, PolicyValue,
};

fn main() {
    let operator = Operator::Equality(EqualityOperator::new(
        EqualityPredicate::Eq,
        EqualityOperand::Literal(PolicyValue::boolean(true)),
    ));
    let Operator::Equality(_) = operator else {
        panic!("direct variant construction unexpectedly changed family");
    };
}
