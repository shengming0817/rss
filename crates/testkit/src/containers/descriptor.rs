//! Private, versioned client connection parameters shared by launcher and test processes.
use super::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    pub version: u8,
    pub amqp: Option<RabbitConnection>,
    pub kafka: Option<KafkaConnection>,
    pub mqtt: Option<MqttConnection>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RabbitConnection {
    pub container: String,
    pub host: String,
    pub port: u16,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KafkaConnection {
    pub container: String,
    pub brokers: String,
    pub scram_brokers: String,
    pub untrusted_client: String,
    pub ca: String,
    pub wrong_ca: String,
    pub certificate: String,
    pub key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MqttConnection {
    pub container: String,
    pub port: u16,
    pub ca: String,
    pub wrong_ca: String,
    pub certificate: String,
    pub key: String,
}
fn connection(id: &str, fields: &[&str]) -> Result<()> {
    anyhow::ensure!(
        id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid fixture container endpoint"
    );
    anyhow::ensure!(
        fields.iter().all(|value| !value.is_empty()),
        "empty fixture connection field"
    );
    Ok(())
}
impl Descriptor {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.version == 1, "unsupported fixture descriptor version");
        if let Some(d) = &self.amqp {
            connection(&d.container, &[&d.host])?;
            anyhow::ensure!(d.port != 0, "invalid AMQP fixture port");
        }
        if let Some(d) = &self.kafka {
            connection(
                &d.container,
                &[
                    &d.brokers,
                    &d.scram_brokers,
                    &d.untrusted_client,
                    &d.ca,
                    &d.wrong_ca,
                    &d.certificate,
                    &d.key,
                ],
            )?;
        }
        if let Some(d) = &self.mqtt {
            connection(&d.container, &[&d.ca, &d.wrong_ca, &d.certificate, &d.key])?;
            anyhow::ensure!(d.port != 0, "invalid MQTT fixture port");
        }
        Ok(())
    }
}
pub(super) fn read() -> Result<Descriptor> {
    let path = std::env::var("RSS_TEST_FIXTURES")
        .map_err(|_| anyhow::anyhow!("shared fixture requires the Make test launcher"))?;
    let descriptor: Descriptor = serde_json::from_reader(std::fs::File::open(path)?)?;
    descriptor.validate()?;
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_parameters_roundtrip_and_reject_invalid_shape() -> Result<()> {
        let d = Descriptor {
            version: 1,
            amqp: Some(RabbitConnection {
                container: "a".repeat(64),
                host: "localhost".into(),
                port: 5672,
            }),
            kafka: Some(KafkaConnection {
                container: "b".repeat(64),
                brokers: "localhost:9000".into(),
                scram_brokers: "localhost:9001".into(),
                untrusted_client: "untrusted".into(),
                ca: "ca".into(),
                wrong_ca: "wrong-ca".into(),
                certificate: "cert".into(),
                key: "key".into(),
            }),
            mqtt: Some(MqttConnection {
                container: "c".repeat(64),
                port: 8883,
                ca: "ca".into(),
                wrong_ca: "wrong-ca".into(),
                certificate: "cert".into(),
                key: "key".into(),
            }),
        };
        let encoded = serde_json::to_value(&d)?;
        let decoded: Descriptor = serde_json::from_value(encoded.clone())?;
        decoded.validate()?;
        assert_eq!(serde_json::to_value(decoded)?, encoded);
        for patch in [
            serde_json::json!({"version":2}),
            serde_json::json!({"amqp":{"container":"bad","host":"localhost","port":5672}}),
        ] {
            let mut invalid = encoded.clone();
            for (key, value) in patch
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid test patch"))?
            {
                invalid[key] = value.clone();
            }
            let parsed: Descriptor = serde_json::from_value(invalid)?;
            assert!(parsed.validate().is_err());
        }
        for value in [0, 65536] {
            let mut invalid = encoded.clone();
            invalid["mqtt"]["port"] = value.into();
            assert!(
                serde_json::from_value::<Descriptor>(invalid)
                    .and_then(|d| d.validate().map_err(serde::de::Error::custom))
                    .is_err()
            );
        }
        let mut invalid = encoded;
        invalid["mqtt"]["server_key"] = "must not transfer".into();
        assert!(serde_json::from_value::<Descriptor>(invalid).is_err());
        Ok(())
    }
}
