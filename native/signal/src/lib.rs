//! Signal linked-device adapter, loaded only by Liaison.
use anyhow::{Result, bail};
use futures::{StreamExt, channel::oneshot};
use liaison_paired::{Backend, Shared, now_ms};
use presage::{Manager, manager::Registered, store::ContentsStore, model::{identity::OnNewIdentity, messages::Received},
    libsignal_service::{configuration::SignalServers, content::{ContentBody, DataMessage}, protocol::ServiceId}};
use presage_store_sqlite::SqliteStore;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};

struct Signal { manager: Manager<SqliteStore, Registered>, receiver: tokio::task::JoinHandle<()> }
impl Backend for Signal {
    const PROVIDER: &'static str = "signal";
    async fn open(path: PathBuf, key: String, pair: bool, shared: Arc<Shared>) -> Result<Self> {
        let store = SqliteStore::open_with_passphrase(path.join("protocol.db").to_str().unwrap(), Some(&key), OnNewIdentity::Reject).await?;
        let mut manager = match Manager::load_registered(store.clone()).await {
            Ok(manager) => manager,
            Err(_) if pair && shared.snapshot().identity.is_none() => {
                let (tx, rx) = oneshot::channel::<url::Url>(); let state = shared.clone();
                tokio::task::spawn_local(async move { if let Ok(url) = rx.await { state.qr(url.to_string(), 120); } });
                tokio::time::timeout(std::time::Duration::from_secs(120), Manager::link_secondary_device(store, SignalServers::Production, "Typednotes".into(), tx)).await??
            }
            Err(_) => bail!("device needs pairing"),
        };
        let identity = ServiceId::from(manager.registration_data().service_ids.aci()).service_id_string();
        let mut receiver_manager = manager.clone(); let state = shared.clone();
        let ready = shared.clone();
        let receiver = tokio::task::spawn_local(async move {
            loop {
                let stream = match receiver_manager.receive_messages().await {
                    Ok(stream) => stream,
                    Err(_) => { state.disconnected("Reconnecting to Signal"); tokio::time::sleep(std::time::Duration::from_secs(5)).await; continue; }
                };
                futures::pin_mut!(stream);
                while let Some(event) = stream.next().await {
                    match event {
                        Received::QueueEmpty => { if ready.connected(identity.clone()).is_err() { return; } },
                        Received::Content(content) => {
                            if let ContentBody::DataMessage(message) = &content.body {
                                if message.group_v2.is_some() { continue; }
                                if let Some(body) = &message.body {
                                    let peer = content.metadata.sender.service_id_string();
                                    let timestamp = content.metadata.client_timestamp.timestamp_millis() as u64;
                                    if state.push(format!("{peer}:{timestamp}"), peer, body.clone(), timestamp).is_err() {
                                        state.disconnected("Could not persist the received message"); return;
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
                state.disconnected("Reconnecting to Signal");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        // Contact sync is protocol housekeeping, never a disclosed contact-list operation.
        let _ = manager.request_contacts().await;
        Ok(Self { manager, receiver })
    }
    async fn send(&mut self, peer: String, text: String) -> Result<Value> {
        let recipient = if let Some(id) = ServiceId::parse_from_service_id_string(&peer) { id } else {
            let mut matches = self.manager.store().contacts().await?.collect::<Result<Vec<_>,_>>()?.into_iter()
                .filter(|contact| contact.phone_number.as_ref().is_some_and(|number| number.to_string() == peer));
            let contact = matches.next().ok_or_else(|| anyhow::anyhow!("use a Signal account ID or a synchronized contact's phone number"))?;
            if matches.next().is_some() { bail!("ambiguous contact identity"); }
            ServiceId::parse_from_service_id_string(&contact.uuid.to_string()).unwrap()
        };
        let timestamp = now_ms();
        self.manager.send_message(recipient, DataMessage { body: Some(text), ..Default::default() }, timestamp).await?;
        Ok(json!({"timestamp": timestamp}))
    }
    async fn unlink(&mut self) -> Result<()> {
        match self.manager.unlink_self().await {
            Ok(()) | Err(presage::Error::ServiceError(presage::libsignal_service::prelude::ServiceError::Unauthorized)) => {},
            Err(error) => return Err(error.into()),
        }
        self.receiver.abort();
        Ok(())
    }
}
liaison_paired::export_adapter!(Signal);
