fn requires_direct<C: generated::command::DirectCommandContract>() {}

fn main() {
    requires_direct::<generated::command::_seed_v1::Contract>();
}
