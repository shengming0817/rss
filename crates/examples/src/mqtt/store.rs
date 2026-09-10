use rumqttc::{PersistedSession, SessionStore, SessionStoreKey};
#[derive(Debug)]
pub struct FileStore {
    dir: std::path::PathBuf,
    gate: tokio::sync::Mutex<()>,
}
impl FileStore {
    pub fn new(dir: std::path::PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            gate: tokio::sync::Mutex::new(()),
        })
    }
    fn path(&self, key: &SessionStoreKey) -> std::path::PathBuf {
        // Collision-free byte encoding; test backend accepts arbitrary caller scope and client ID.
        let name: String = format!("{}\0{}", key.scope(), key.client_id())
            .bytes()
            .map(|v| format!("{v:02x}"))
            .collect();
        self.dir.as_path().join(name)
    }
}
impl SessionStore for FileStore {
    fn load<'a>(
        &'a self,
        key: &'a SessionStoreKey,
    ) -> SessionStoreFuture<'a, Option<PersistedSession>> {
        Box::pin(async move {
            let _guard = self.gate.lock().await;
            match tokio::fs::read(self.path(key)).await {
                Ok(bytes) => Ok(Some(PersistedSession::decode(&bytes)?)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }
    fn save<'a>(
        &'a self,
        key: &'a SessionStoreKey,
        session: &'a PersistedSession,
    ) -> SessionStoreFuture<'a, ()> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let _guard = self.gate.lock().await;
            let path = self.path(key);
            let temp = path.with_extension("new");
            let mut file = tokio::fs::File::create(&temp).await?;
            file.write_all(&session.encode()?).await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(temp, path).await?;
            tokio::fs::File::open(self.dir.as_path())
                .await?
                .sync_all()
                .await?;
            Ok(())
        })
    }
    fn clear<'a>(&'a self, key: &'a SessionStoreKey) -> SessionStoreFuture<'a, ()> {
        Box::pin(async move {
            let _guard = self.gate.lock().await;
            match tokio::fs::remove_file(self.path(key)).await {
                Ok(()) => {
                    tokio::fs::File::open(self.dir.as_path())
                        .await?
                        .sync_all()
                        .await?;
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
    }
}

pub type SessionStoreFuture<'a, T> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<T, rumqttc::SessionStoreError>> + Send + 'a>,
>;
