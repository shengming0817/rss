fn accepts_seed<C>(request: C::Request)
where
    C: generated::command::CommandContract<
        Request = generated::command::_seed_v1::SeedDoThingRequest,
    >,
{
    let _ = request;
}

fn main() {
    accepts_seed::<generated::command::_seed_v1::Contract>(String::from("wrong request"));
}
