//! Scripted TLS peer for protocol windows that cannot be scheduled through a real broker.
use bytes::BytesMut;
use rumqttc::mqttbytes::v5::{ConnAck, ConnectReturnCode, Packet, PubAck, PubAckReason, Publish};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub struct Peer {
    pub listener: TcpListener,
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub client_tls: Arc<rustls::ClientConfig>,
}
impl Peer {
    pub async fn new() -> anyhow::Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone())?;
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            listener: TcpListener::bind("127.0.0.1:0").await?,
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server)),
            client_tls: Arc::new(client),
        })
    }
    pub fn config(&self, id: &str) -> anyhow::Result<rss_mqtt::MqttConfig> {
        Ok(rss_mqtt::MqttConfig::new(
            "localhost",
            self.listener.local_addr()?.port(),
            id,
            "scripted",
            self.client_tls.clone(),
            rss_mqtt::Limits::new(4, 4, 4, 65536)?,
        )?)
    }
    pub async fn accept(&self, session_present: bool) -> anyhow::Result<Wire> {
        self.accept_code(session_present, ConnectReturnCode::Success)
            .await
    }
    pub async fn accept_code(
        &self,
        session_present: bool,
        code: ConnectReturnCode,
    ) -> anyhow::Result<Wire> {
        self.accept_properties(session_present, code, None).await
    }
    pub async fn accept_properties(
        &self,
        session_present: bool,
        code: ConnectReturnCode,
        properties: Option<rumqttc::mqttbytes::v5::ConnAckProperties>,
    ) -> anyhow::Result<Wire> {
        let stream = self
            .acceptor
            .accept(self.listener.accept().await?.0)
            .await?;
        let mut wire = Wire(stream);
        anyhow::ensure!(
            matches!(wire.read().await?, Packet::Connect(..)),
            "expected CONNECT"
        );
        wire.write(Packet::ConnAck(ConnAck {
            session_present,
            code,
            properties,
        }))
        .await?;
        Ok(wire)
    }
}
pub struct Wire(pub tokio_rustls::server::TlsStream<TcpStream>);
impl Wire {
    pub async fn read(&mut self) -> anyhow::Result<Packet> {
        let first = self.0.read_u8().await?;
        let mut data = BytesMut::from(&[first][..]);
        let mut len = 0;
        let mut multiplier = 1;
        for _ in 0..4 {
            let b = self.0.read_u8().await?;
            data.extend_from_slice(&[b]);
            len += (b as usize & 127) * multiplier;
            if b & 128 == 0 {
                break;
            }
            multiplier *= 128;
        }
        anyhow::ensure!(len < 65536, "test packet limit");
        let head = data.len();
        data.resize(head + len, 0);
        self.0.read_exact(&mut data[head..]).await?;
        Ok(Packet::read(&mut data, Some(65536))?)
    }
    pub async fn write(&mut self, packet: Packet) -> anyhow::Result<()> {
        let mut bytes = BytesMut::new();
        packet.write(&mut bytes, Some(65536))?;
        self.0.write_all(&bytes).await?;
        self.0.flush().await?;
        Ok(())
    }
    pub async fn publish(&mut self) -> anyhow::Result<Publish> {
        loop {
            match self.read().await? {
                Packet::Publish(p) => return Ok(p),
                Packet::PingReq => self.write(Packet::PingResp).await?,
                _ => anyhow::bail!("expected PUBLISH"),
            }
        }
    }
    pub async fn ack(&mut self, pkid: u16, reason: PubAckReason) -> anyhow::Result<()> {
        self.write(Packet::PubAck(PubAck {
            pkid,
            reason,
            properties: None,
        }))
        .await
    }
}
