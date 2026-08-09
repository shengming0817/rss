use platform_application_waist_contract::Contract;

type Provider<C: Contract> = <C as Contract>::Provider;
type Registry<C: Contract> = <C as Contract>::Registry;
type Runtime<C: Contract> = <C as Contract>::Runtime;

fn main() {
}
