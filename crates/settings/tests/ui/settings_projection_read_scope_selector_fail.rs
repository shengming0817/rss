use eventexec::ProjectionSelector;
use settings::ports::SettingsProjectionReadScope;

fn bad(selector: ProjectionSelector) {
    let _scope: SettingsProjectionReadScope = selector.into();
}

fn main() {}
