use audit::ports::AuditPortEffect;

struct Forged;

impl AuditPortEffect for Forged {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

fn main() {}
