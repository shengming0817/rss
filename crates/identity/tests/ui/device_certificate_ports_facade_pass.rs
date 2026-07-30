use identity::ports::device_certificate::{
    DeviceCertificateRepository, DeviceCertificateScope, ReportedStateWrite,
};

fn accepts_port<R: DeviceCertificateRepository>(
    _repository: &R,
    _scope: DeviceCertificateScope,
    _report: ReportedStateWrite,
) {
}

fn main() {}
