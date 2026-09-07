//! Real Mosquitto with a private CA, client certificate and password authentication.
use super::{GenericImage, ImageExt, Result, copied_tls_image, runtime, tls};
use testcontainers::core::{IntoContainerPort, WaitFor};

pub struct MqttTlsFixture {
    container: runtime::Container<GenericImage>,
    port: u16,
    material: tls::TlsMaterial,
}
impl MqttTlsFixture {
    pub const fn port(&self) -> u16 {
        self.port
    }
    pub fn ca_pem(&self) -> &str {
        &self.material.ca_pem
    }
    pub fn wrong_ca_pem(&self) -> &str {
        &self.material.wrong_ca_pem
    }
    pub fn client_cert_pem(&self) -> &str {
        &self.material.client_cert_pem
    }
    pub fn client_key_pem(&self) -> &str {
        &self.material.client_key_pem
    }
    /// Restart the same broker with its persisted data directory intact.
    pub async fn restart(&self) -> Result<()> {
        anyhow::ensure!(
            matches!(self.container, runtime::Container::Owned(_)),
            "broker restart requires exclusive_mqtt_tls"
        );
        super::runtime::run_container_command(
            &self.container,
            "restart mqtt",
            &["killall", "-TERM", "mosquitto"],
        )
        .await
    }
}
/// A broker fixture only; it does not implement an application identity or device protocol.
pub async fn exclusive_mqtt_tls(matching_host: bool) -> Result<MqttTlsFixture> {
    let material = tls::tls_material_for_host("mqtt-test", matching_host)?;
    let image = GenericImage::new("eclipse-mosquitto", "2.0.22")
        .with_exposed_port(8883.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "mosquitto version 2.0.22 running",
        ));
    let config = "listener 8883\ncafile /rss-tls/ca.pem\ncertfile /rss-tls/server.pem\nkeyfile /rss-tls/server-key.pem\nrequire_certificate true\nallow_anonymous false\npassword_file /tmp/mqtt-passwords\npersistence true\npersistence_location /mosquitto/data/\nautosave_interval 1\nlog_dest stderr\n";
    let request = copied_tls_image(image, &material)
        .with_copy_to("/mosquitto/config/mosquitto.conf", config.as_bytes().to_vec())
        .with_cmd(["sh", "-c", "mosquitto_passwd -b -c /tmp/mqtt-passwords mqtt fixture-only && chmod 644 /tmp/mqtt-passwords && while true; do mosquitto -c /mosquitto/config/mosquitto.conf; sleep 0.1; done"]);
    let container = runtime::start(request).await?;
    let port = container.get_host_port_ipv4(8883.tcp()).await?;
    Ok(MqttTlsFixture {
        container: runtime::Container::Owned(Box::new(container)),
        port,
        material,
    })
}

impl MqttTlsFixture {
    pub(super) fn descriptor(&self) -> serde_json::Value {
        use runtime::ContainerId as _;
        serde_json::json!({"container": self.container.container_id(), "port": self.port,
            "ca": self.ca_pem(), "wrong_ca": self.wrong_ca_pem(),
            "certificate": self.client_cert_pem(), "key": self.client_key_pem()})
    }
}
/// Borrow client connection material; the launcher retains server keys and lifecycle ownership.
pub async fn shared_mqtt_tls() -> Result<MqttTlsFixture> {
    let d = super::launcher::descriptor("mqtt")?;
    let get = |key| super::launcher::text(&d, key);
    Ok(MqttTlsFixture {
        container: runtime::Container::Shared(get("container")?),
        port: super::launcher::port(&d, "port")?,
        material: tls::TlsMaterial {
            ca_pem: get("ca")?,
            wrong_ca_pem: get("wrong_ca")?,
            client_cert_pem: get("certificate")?,
            client_key_pem: get("key")?,
            // reason: borrowed clients never construct a TLS server.
            server_cert_pem: String::new(),
            server_key_pem: String::new(),
        },
    })
}
