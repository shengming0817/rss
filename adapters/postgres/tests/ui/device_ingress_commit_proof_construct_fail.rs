use identity::ports::device_certificate::DraftEligibility;
use postgres::PgDeviceIngressCommitProof;

fn main() {
    let _ = PgDeviceIngressCommitProof::<DraftEligibility> {};
    let _ = PgDeviceIngressCommitProof::<DraftEligibility>::committed();
}
