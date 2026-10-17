//! WhatsApp linked-device adapter, loaded only by Liaison.
use anyhow::{Result, ensure};
use liaison_paired::{Backend, Shared};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use whatsapp_rust::{bot::Bot, Client, Jid, store::SqliteStore, waproto::whatsapp as wa, prelude::{MessageBuilderExt, MessageExt}};

struct WhatsApp { client: Arc<Client>, task: tokio::task::JoinHandle<()> }
impl Backend for WhatsApp {
    const PROVIDER: &'static str = "whatsapp";
    async fn open(path: PathBuf, _key: String, pair: bool, shared: Arc<Shared>) -> Result<Self> {
        ensure!(pair || shared.snapshot().identity.is_some(), "device has not been paired");
        let qr = shared.clone(); let connected = shared.clone(); let inbound = shared.clone(); let logout = shared.clone();
        let bot = Bot::builder()
            .with_backend(SqliteStore::new(path.join("protocol.db").to_str().unwrap()).await?)
            .on_qr_code(move |code, timeout| { let shared = qr.clone(); async move { shared.qr(code, timeout.as_secs()); } })
            .on_connected(move |client| { let shared = connected.clone(); async move {
                if let Some(jid) = client.pn() {
                    if shared.connected(jid.user.to_string()).is_err() { shared.disconnected("Device identity changed; unlink first"); client.disconnect().await; }
                }
            } })
            .on_logged_out(move |_| { let shared = logout.clone(); async move { shared.disconnected("Device was unlinked. Scan a new QR code"); } })
            .on_message(move |ctx| { let shared = inbound.clone(); async move {
                if ctx.info.source.is_from_me || ctx.info.source.is_group { return; }
                let Some(body) = ctx.message.text_content() else { return; };
                let chat = &ctx.info.source.chat;
                let server = chat.server.to_string();
                if !["s.whatsapp.net", "lid"].contains(&server.as_str()) { return; }
                // Preserve the exact direct-chat identity, including LID identities.
                let peer = if chat.server.to_string() == "s.whatsapp.net" { chat.user.to_string() } else { chat.to_string() };
                let id = format!("{peer}:{}", ctx.info.id);
                if shared.push(id, peer, body.to_string(), ctx.info.timestamp.timestamp_millis() as u64).is_err() {
                    shared.disconnected("Could not persist the received message"); ctx.client.disconnect().await;
                }
            } })
            .build().await?;
        let client = bot.client();
        let state = shared.clone();
        let task = tokio::task::spawn_local(async move { bot.run().await; state.disconnected("Connection closed; reconnect from settings"); });
        Ok(Self { client, task })
    }
    async fn send(&mut self, peer: String, text: String) -> Result<Value> {
        let jid: Jid = if peer.bytes().all(|c| c.is_ascii_digit()) && (6..=15).contains(&peer.len()) {
            format!("{peer}@s.whatsapp.net").parse()?
        } else {
            let jid: Jid = peer.parse()?;
            ensure!(jid.server.to_string() == "lid" && jid.device == 0, "only direct recipients are supported");
            jid
        };
        let sent = self.client.send_message(&jid, wa::Message::text(text)).await?;
        Ok(json!({"messages":[{"id":sent.message_id}]}))
    }
    async fn unlink(&mut self) -> Result<()> {
        self.client.logout().await;
        self.client.disconnect().await;
        self.task.abort();
        Ok(())
    }
}
liaison_paired::export_adapter!(WhatsApp);
