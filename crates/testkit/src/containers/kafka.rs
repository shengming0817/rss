//! Real Kafka KRaft fixture with mTLS and SCRAM-SHA-512 over verified TLS.
//! ref: apache/kafka docker/resources/common-scripts/configure@4.1.1
use super::{Result, runtime};
use testcontainers::{
    ContainerAsync, Image, ImageExt as _,
    core::{CmdWaitFor, ContainerPort, ContainerState, ExecCommand, WaitFor},
};

/// Select a trusted certificate whose SAN either matches or rejects the published endpoint.
#[derive(Clone, Copy)]
pub enum KafkaTlsServerIdentity {
    MatchingHost,
    UnmatchedHost,
}

/// Owns the broker; authentication material is explicit and never included in Debug.
pub struct KafkaTlsFixture {
    _container: ContainerAsync<KafkaImage>,
    brokers: String,
    scram_brokers: String,
    untrusted_client: String,
    ca: String,
    wrong_ca: String,
    certificate: String,
    key: String,
}
impl KafkaTlsFixture {
    pub fn brokers(&self) -> &str {
        &self.brokers
    }
    pub fn scram_brokers(&self) -> &str {
        &self.scram_brokers
    }
    pub fn scram_username(&self) -> &str {
        "rss-fixture-user"
    }
    pub fn scram_password(&self) -> &str {
        "fixture-only"
    }
    pub fn untrusted_client_certificate_pem(&self) -> &str {
        &self.untrusted_client
    }
    /// Read the test topic end offset through the unexposed internal listener.
    pub async fn topic_end_offset(&self) -> Result<i64> {
        let output = runtime::run_container_command_output(
            &self._container,
            "kafka-topic-offset",
            &[
                "/opt/kafka/bin/kafka-get-offsets.sh",
                "--bootstrap-server",
                "127.0.0.1:29092",
                "--topic",
                "events-v1",
            ],
        )
        .await?;
        if output.exit_code != Some(0) {
            return Err(output.failure("kafka-topic-offset"));
        }
        Ok(output
            .stdout
            .trim()
            .strip_prefix("events-v1:0:")
            .ok_or_else(|| anyhow::anyhow!("unexpected topic offset response"))?
            .parse()?)
    }
    pub fn ca_pem(&self) -> &str {
        &self.ca
    }
    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca
    }
    pub fn client_certificate_pem(&self) -> &str {
        &self.certificate
    }
    pub fn client_key_pem(&self) -> &str {
        &self.key
    }
}
struct Material {
    ca: String,
    wrong_ca: String,
    server: String,
    server_key: String,
    client: String,
    untrusted_client: String,
    client_key: String,
}
fn material(identity: KafkaTlsServerIdentity) -> Result<Material> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, SanType,
    };
    let issuer = |name: &str| -> Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        Ok(CertifiedIssuer::self_signed(params, KeyPair::generate()?)?)
    };
    let ca = issuer("rss-kafka-ca")?;
    let wrong = issuer("rss-kafka-wrong-ca")?;
    let server_key = KeyPair::generate()?;
    let mut server = CertificateParams::new(vec!["localhost".into()])?;
    if matches!(identity, KafkaTlsServerIdentity::MatchingHost) {
        server
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse()?));
    } else {
        server.subject_alt_names = vec![SanType::DnsName("unmatched.invalid".try_into()?)];
    }
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = server.signed_by(&server_key, &ca)?;
    let client_key = KeyPair::generate()?;
    let mut client = CertificateParams::default();
    client
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rss-fixture-client");
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let untrusted_client = client.signed_by(&client_key, &wrong)?;
    let client = client.signed_by(&client_key, &ca)?;
    Ok(Material {
        ca: ca.pem(),
        wrong_ca: wrong.pem(),
        server: server.pem(),
        server_key: server_key.serialize_pem(),
        client: client.pem(),
        untrusted_client: untrusted_client.pem(),
        client_key: client_key.serialize_pem(),
    })
}
/// Start a single-node test-only Kafka cluster with host-published mTLS and SCRAM listeners.
/// The internal controller/broker listeners stay inside the fixture container.
pub async fn kafka_tls(identity: KafkaTlsServerIdentity) -> Result<KafkaTlsFixture> {
    let material = material(identity)?;
    let port = "__RSS_ADVERTISED_PORT__";
    let pem = |value: &str| value.replace('\n', "\\n");
    let mut properties = format!(
        r#"process.roles=broker,controller
node.id=1
controller.quorum.voters=1@127.0.0.1:9093
listeners=CLIENT://0.0.0.0:9092,SCRAM://0.0.0.0:9094,INTERNAL://127.0.0.1:29092,CONTROLLER://127.0.0.1:9093
advertised.listeners=CLIENT://127.0.0.1:{port},SCRAM://127.0.0.1:__RSS_SCRAM_PORT__,INTERNAL://127.0.0.1:29092
listener.security.protocol.map=CLIENT:SSL,SCRAM:SASL_SSL,INTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT
inter.broker.listener.name=INTERNAL
controller.listener.names=CONTROLLER
listener.name.client.ssl.keystore.type=PEM
listener.name.client.ssl.keystore.certificate.chain={}
listener.name.client.ssl.keystore.key={}
listener.name.client.ssl.truststore.type=PEM
listener.name.client.ssl.truststore.certificates={}
listener.name.client.ssl.client.auth=required
log.dirs=/tmp/rss-kafka-data
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
num.partitions=1
auto.create.topics.enable=false
"#,
        pem(&material.server),
        pem(&material.server_key),
        pem(&material.ca)
    );
    properties.push_str(&format!(r#"listener.name.scram.ssl.keystore.type=PEM
listener.name.scram.ssl.keystore.certificate.chain={}
listener.name.scram.ssl.keystore.key={}
listener.name.scram.ssl.client.auth=none
listener.name.scram.sasl.enabled.mechanisms=SCRAM-SHA-512
listener.name.scram.scram-sha-512.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required;
sasl.enabled.mechanisms=SCRAM-SHA-512
"#, pem(&material.server), pem(&material.server_key)));
    let image = KafkaImage { properties }.with_env_var("KAFKA_HEAP_OPTS", "-Xms128m -Xmx256m");
    let container = runtime::start(image).await?;
    let port = container
        .get_host_port_ipv4(ContainerPort::Tcp(9092))
        .await?;
    runtime::run_container_command(
        &container,
        "create-kafka-topic",
        &[
            "/opt/kafka/bin/kafka-topics.sh",
            "--bootstrap-server",
            "127.0.0.1:29092",
            "--create",
            "--topic",
            "events-v1",
            "--partitions",
            "1",
            "--replication-factor",
            "1",
        ],
    )
    .await?;
    let scram_port = container
        .get_host_port_ipv4(ContainerPort::Tcp(9094))
        .await?;
    runtime::run_container_command(
        &container,
        "create-scram-user",
        &[
            "/opt/kafka/bin/kafka-configs.sh",
            "--bootstrap-server",
            "127.0.0.1:29092",
            "--alter",
            "--add-config",
            "SCRAM-SHA-512=[iterations=4096,password=fixture-only]",
            "--entity-type",
            "users",
            "--entity-name",
            "rss-fixture-user",
        ],
    )
    .await?;
    Ok(KafkaTlsFixture {
        _container: container,
        brokers: format!("127.0.0.1:{port}"),
        scram_brokers: format!("127.0.0.1:{scram_port}"),
        untrusted_client: material.untrusted_client,
        ca: material.ca,
        wrong_ca: material.wrong_ca,
        certificate: material.client,
        key: material.client_key,
    })
}

/// Docker allocates the client port atomically; the pre-readiness hook then writes its advertisement.
struct KafkaImage {
    properties: String,
}
impl Image for KafkaImage {
    fn name(&self) -> &str {
        "apache/kafka"
    }
    fn tag(&self) -> &str {
        "4.1.1@sha256:0bc1bb2478f45b6cea78864df86acdc11e8df2c5172477819a4d12942cbe5d40"
    }
    fn entrypoint(&self) -> Option<&str> {
        Some("/bin/sh")
    }
    fn expose_ports(&self) -> &[ContainerPort] {
        &[ContainerPort::Tcp(9092), ContainerPort::Tcp(9094)]
    }
    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stdout("Kafka Server started")]
    }
    fn cmd(&self) -> impl IntoIterator<Item = impl Into<std::borrow::Cow<'_, str>>> {
        [
            "-c",
            "set -eu; while [ ! -f /tmp/rss-kafka-ready ]; do sleep 0.01; done; /opt/kafka/bin/kafka-storage.sh format -t MkU3OEVBNTcwNTJENDM2Qk -c /tmp/rss-kafka.properties; exec /opt/kafka/bin/kafka-server-start.sh /tmp/rss-kafka.properties",
        ]
    }
    fn exec_before_ready(
        &self,
        state: ContainerState,
    ) -> testcontainers::core::error::Result<Vec<ExecCommand>> {
        let port = state.host_port_ipv4(ContainerPort::Tcp(9092))?;
        let scram_port = state.host_port_ipv4(ContainerPort::Tcp(9094))?;
        let properties = self
            .properties
            .replace("__RSS_ADVERTISED_PORT__", &port.to_string())
            .replace("__RSS_SCRAM_PORT__", &scram_port.to_string());
        Ok(vec![ExecCommand::new(vec!["/bin/sh".to_owned(), "-c".to_owned(), "set -eu; printf '%s' \"$1\" > /tmp/rss-kafka.properties; touch /tmp/rss-kafka-ready".to_owned(), "rss-config".to_owned(), properties]).with_cmd_ready_condition(CmdWaitFor::exit())])
    }
}
