use settings::ports::SettingsPortEffect;

struct ForgedReadPort;

impl SettingsPortEffect for ForgedReadPort {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

fn main() {}
