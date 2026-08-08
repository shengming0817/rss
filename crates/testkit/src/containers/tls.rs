use super::{CopyTargetOptions, GenericImage, ImageExt, Result};

pub(super) struct TlsMaterial {
    pub(super) ca_pem: String,
    pub(super) wrong_ca_pem: String,
    pub(super) server_cert_pem: String,
    pub(super) server_key_pem: String,
}

pub(super) fn tls_dns_names<'a>(dns_name: &'a str) -> [&'a str; 2] {
    ["localhost", dns_name]
}

pub(super) fn tls_material(dns_name: &str) -> Result<TlsMaterial> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, SanType,
    };

    let issuer = |label: &str| -> Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, label);
        Ok(CertifiedIssuer::self_signed(params, KeyPair::generate()?)?)
    };
    let ca = issuer("rss-test-private-ca")?;
    let wrong_ca = issuer("rss-test-wrong-private-ca")?;
    let server_key = KeyPair::generate()?;
    let mut server = CertificateParams::default();
    server.is_ca = IsCa::ExplicitNoCa;
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut sans = Vec::with_capacity(4);
    for name in tls_dns_names(dns_name) {
        sans.push(SanType::DnsName(name.try_into()?));
    }
    sans.push(SanType::IpAddress("127.0.0.1".parse()?));
    sans.push(SanType::IpAddress("::1".parse()?));
    server.subject_alt_names = sans;
    let server_cert = server.signed_by(&server_key, &ca)?;
    Ok(TlsMaterial {
        ca_pem: ca.pem(),
        wrong_ca_pem: wrong_ca.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
    })
}

pub(super) fn copied_tls_image(
    image: GenericImage,
    material: &TlsMaterial,
) -> testcontainers::ContainerRequest<GenericImage> {
    image
        .with_copy_to("/rss-tls/ca.pem", material.ca_pem.as_bytes().to_vec())
        .with_copy_to(
            "/rss-tls/server.pem",
            material.server_cert_pem.as_bytes().to_vec(),
        )
        .with_copy_to(
            // testcontainers archive extraction owns copied files as root, while the official
            // Redis/RabbitMQ images drop privileges before reading their TLS key.
            CopyTargetOptions::new("/rss-tls/server-key.pem").with_mode(0o644),
            material.server_key_pem.as_bytes().to_vec(),
        )
}
