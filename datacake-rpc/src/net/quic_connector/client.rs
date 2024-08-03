use std::io;
use quinn::{Connection, Endpoint};

use super::stream::QuicStream;
use super::config::ClientConnectConfig;

#[derive(Clone)]
/// A client channel backed by QUIC.
pub struct QuicChannel {
    endpoint: Endpoint,
    connection: Connection,
}

impl QuicChannel {
    /// Connect to the target QUIC server.
    pub(crate) async fn connect(config: ClientConnectConfig) -> anyhow::Result<Self> {
        let mut endpoint = Endpoint::client(config.connect_addr())?;
        endpoint.set_default_client_config(config.client_config());

        let connection = endpoint
            .connect(config.connect_addr(), config.server_name())?
            .await?;

        Ok(Self {
            endpoint,
            connection,
        })
    }

    pub(crate) async fn open_stream(&self) -> anyhow::Result<QuicStream> {
        let (tx, rx) = self.connection
            .open_bi()
            .await?;

        todo!()
    }
}

