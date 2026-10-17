//! Offline protocol peer for the real compiled broker/C/Rust integration test.
//! Never included in an image or production adapter dependency graph.
use anyhow::Result;
use liaison_paired::{Backend, Shared};
use serde_json::{Value,json};
use std::{path::PathBuf,sync::Arc};
struct Fixture;
impl Backend for Fixture {
    #[cfg(feature="whatsapp")] const PROVIDER: &'static str="whatsapp";
    #[cfg(not(feature="whatsapp"))] const PROVIDER: &'static str="signal";
    async fn open(_path:PathBuf,_key:String,pair:bool,shared:Arc<Shared>)->Result<Self> {
        if pair && shared.snapshot().identity.is_none() {
            shared.qr("offline-fixture-qr".into(),60);
            tokio::task::spawn_local(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                shared.connected("sender".into()).unwrap();
                shared.push("a".into(),"alice".into(),"only alice".into(),1).unwrap();
                shared.push("b".into(),"bob".into(),"only bob".into(),2).unwrap();
            });
        }
        Ok(Self)
    }
    async fn send(&mut self,_peer:String,_text:String)->Result<Value> { Ok(json!({"messages":[{"id":"sent"}],"timestamp":1})) }
    async fn unlink(&mut self)->Result<()> { Ok(()) }
}
liaison_paired::export_adapter!(Fixture);
