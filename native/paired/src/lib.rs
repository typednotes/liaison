//! Shared in-process adapter boundary. Lean supplies only a checked plan; this
//! crate owns protocol sessions, bounded encrypted inboxes and filesystem IO.
use anyhow::{Result, bail, ensure};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, KeyInit, aead::Aead};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashMap, ffi::{CStr, CString, c_char}, fs::{self, File, OpenOptions},
    path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, mpsc}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::sync::{mpsc as async_mpsc, watch};

pub const MAX_INBOX: usize = 2048;
const MAX_WIRE: usize = 65536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Request {
    pub provider: String,
    pub organization: String,
    pub account: String,
    pub key: String,
    pub action: String,
    #[serde(default)] pub sender: String,
    #[serde(default)] pub peer: String,
    #[serde(default)] pub text: String,
    #[serde(default)] pub after: String,
    pub response_limit: usize,
}

impl Request {
    pub fn validate(&self, provider: &str) -> Result<()> {
        ensure!(self.provider == provider, "provider mismatch");
        ensure!(identifier(&self.organization), "invalid organization");
        let parts: Vec<_> = self.account.split('/').collect();
        ensure!(parts.len() == 2 && parts.iter().all(|part| identifier(part)), "invalid account");
        ensure!(self.key.len() == 64 && hex::decode(&self.key)?.len() == 32, "invalid key");
        ensure!((1024..=67108864).contains(&self.response_limit), "invalid byte limit");
        ensure!(["pair", "status", "unlink", "send", "read"].contains(&self.action.as_str()), "unknown action");
        if ["send", "read"].contains(&self.action.as_str()) {
            ensure!(!self.sender.is_empty(), "sender required");
            ensure!(self.peer.len() <= 255 && !self.peer.chars().any(char::is_control), "invalid peer");
        }
        if self.action == "send" {
            ensure!(!self.peer.is_empty() && !self.text.is_empty() && self.text.chars().count() <= 4000, "invalid message");
        }
        ensure!(self.after.is_empty() || self.after.parse::<u64>().map(|n| n.to_string() == self.after).unwrap_or(false), "invalid cursor");
        Ok(())
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub state: String,
    pub identity: Option<String>,
    pub qr: Option<String>,
    pub expires_at: u64,
    pub error: Option<String>,
}

pub fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }

#[derive(Clone, Serialize, Deserialize)]
pub struct Message { pub id: String, pub peer: String, pub body: String, pub timestamp: u64, pub sequence: u64 }

#[derive(Default, Serialize, Deserialize)]
struct Inbox { identity: Option<String>, sequence: u64, messages: Vec<Message> }

pub struct Shared {
    pub status: Mutex<Status>,
    inbox: Mutex<Inbox>,
    path: PathBuf,
    key: [u8; 32],
}

impl Shared {
    fn open(path: PathBuf, key: [u8; 32]) -> Result<Self> {
        let inbox = match fs::read(path.join("inbox.enc")) {
            Ok(data) => {
                ensure!(data.len() >= 24 && data.len() <= 16 * 1024 * 1024, "invalid inbox");
                let bytes = XChaCha20Poly1305::new((&key).into()).decrypt(XNonce::from_slice(&data[..24]), &data[24..])
                    .map_err(|_| anyhow::anyhow!("inbox key mismatch"))?;
                serde_json::from_slice(&bytes)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Inbox::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { status: Mutex::new(Status { state: "connecting".into(), identity: inbox.identity.clone(), ..Status::default() }), inbox: Mutex::new(inbox), path, key })
    }
    fn persist(&self, inbox: &Inbox) -> Result<()> {
        let mut nonce = [0; 24]; getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
        let encrypted = XChaCha20Poly1305::new((&self.key).into()).encrypt(XNonce::from_slice(&nonce), serde_json::to_vec(inbox)?.as_ref())
            .map_err(|_| anyhow::anyhow!("inbox encryption failed"))?;
        let mut data = nonce.to_vec(); data.extend(encrypted);
        let mut file = private_file(&self.path.join("inbox.pending"))?;
        use std::io::Write;
        file.set_len(0)?; file.write_all(&data)?; file.sync_all()?;
        fs::rename(self.path.join("inbox.pending"), self.path.join("inbox.enc"))?;
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
    pub fn qr(&self, code: String, seconds: u64) {
        *self.status.lock().unwrap() = Status { state: "pairing".into(), qr: Some(code), expires_at: now_ms() / 1000 + seconds, ..Status::default() };
    }
    pub fn connected(&self, identity: String) -> Result<()> {
        let mut inbox = self.inbox.lock().unwrap();
        if let Some(previous) = &inbox.identity { ensure!(previous == &identity, "paired identity changed; unlink first"); }
        inbox.identity = Some(identity.clone()); self.persist(&inbox)?;
        *self.status.lock().unwrap() = Status { state: "connected".into(), identity: Some(identity), ..Status::default() };
        Ok(())
    }
    pub fn disconnected(&self, error: &str) {
        let mut status = self.status.lock().unwrap();
        status.state = "disconnected".into(); status.qr = None; status.error = Some(error.into());
    }
    pub fn push(&self, id: String, peer: String, body: String, timestamp: u64) -> Result<()> {
        // Only ordinary direct text messages are advertised by this adapter.
        ensure!(id.len() <= 255 && peer.len() <= 255 && body.len() <= MAX_WIRE, "message exceeds inbox limits");
        let mut inbox = self.inbox.lock().unwrap();
        if inbox.messages.iter().any(|m| m.id == id && m.peer == peer) { return Ok(()); }
        inbox.sequence = inbox.sequence.checked_add(1).ok_or_else(|| anyhow::anyhow!("cursor exhausted"))?;
        let sequence = inbox.sequence;
        inbox.messages.push(Message { id, peer, body, timestamp, sequence });
        while inbox.messages.len() > MAX_INBOX || inbox.messages.iter().map(|m| m.body.len()).sum::<usize>() > 8 * 1024 * 1024 { inbox.messages.remove(0); }
        // JSON escaping can expand control characters sixfold. Bound the actual
        // representation too, so every saved inbox stays within its read limit.
        while serde_json::to_vec(&*inbox)?.len() > 8 * 1024 * 1024 { inbox.messages.remove(0); }
        self.persist(&inbox)
    }
    fn read(&self, request: &Request) -> Result<Value> {
        let inbox = self.inbox.lock().unwrap();
        ensure!(inbox.identity.as_deref() == Some(request.sender.as_str()), "sender identity mismatch");
        let after = request.after.parse::<u64>().unwrap_or(0);
        let mut messages = Vec::new();
        let mut next = after;
        for message in inbox.messages.iter().filter(|m| m.sequence > after) {
            if !request.peer.is_empty() && message.peer != request.peer { continue; }
            let candidate = json!({"messages": messages.iter().chain(std::iter::once(message)).collect::<Vec<_>>(), "next": message.sequence.to_string()});
            if serde_json::to_vec(&candidate)?.len() > request.response_limit {
                ensure!(!messages.is_empty(), "message exceeds response limit");
                break;
            }
            messages.push(message.clone()); next = message.sequence;
            if messages.len() == 100 { break; }
        }
        Ok(json!({"messages": messages, "next": next.to_string()}))
    }
    pub fn snapshot(&self) -> Status {
        let mut status = self.status.lock().unwrap().clone();
        if status.state == "pairing" && status.expires_at <= now_ms() / 1000 {
            status.state = "expired".into(); status.qr = None;
        }
        status
    }
}

pub trait Backend: Sized + 'static {
    const PROVIDER: &'static str;
    fn open(path: PathBuf, key: String, pair: bool, shared: Arc<Shared>) -> impl std::future::Future<Output = Result<Self>>;
    fn send(&mut self, peer: String, text: String) -> impl std::future::Future<Output = Result<Value>>;
    fn unlink(&mut self) -> impl std::future::Future<Output = Result<()>>;
}

struct Command { peer: String, text: String, reply: mpsc::SyncSender<Result<Value>> }
#[doc(hidden)]
pub struct Session { shared: Arc<Shared>, commands: async_mpsc::Sender<Command>, stop: watch::Sender<bool>, stopped: mpsc::Receiver<Result<()>>, _lock: Arc<File> }
type Sessions = Mutex<HashMap<String, Session>>;

fn private_file(path: &Path) -> Result<File> {
    if let Ok(meta) = fs::symlink_metadata(path) { ensure!(meta.is_file() && !meta.file_type().is_symlink(), "unsafe session file"); }
    let mut options = OpenOptions::new(); options.create(true).read(true).write(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    Ok(options.open(path)?)
}
fn directory(path: &Path) -> Result<()> {
    if !path.exists() { fs::create_dir(path)?; }
    let meta = fs::symlink_metadata(path)?;
    ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "unsafe session directory");
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(path, fs::Permissions::from_mode(0o700))?; }
    Ok(())
}
fn session_path(request: &Request) -> Result<PathBuf> {
    let root = PathBuf::from(std::env::var("LIAISON_PAIRED_DIR")?);
    ensure!(root.is_absolute() && root.is_dir(), "paired storage must be an existing absolute directory");
    directory(&root)?;
    let mut path = root;
    for part in std::iter::once(request.provider.as_str()).chain(std::iter::once(request.organization.as_str())).chain(request.account.split('/')) {
        path.push(part); directory(&path)?;
    }
    Ok(path)
}

fn execute<B: Backend>(sessions: &Sessions, request: Request) -> Result<Value> {
    request.validate(B::PROVIDER)?;
    let name = format!("{}/{}/{}", request.provider, request.organization, request.account);
    let mut sessions = sessions.lock().unwrap();
    if !sessions.contains_key(&name) {
        ensure!(sessions.len() < 128, "paired session capacity reached");
        let path = session_path(&request)?;
        let lock = Arc::new(private_file(&path.join("owner.lock"))?); lock.try_lock_exclusive()?;
        let key: [u8; 32] = hex::decode(&request.key)?.try_into().map_err(|_| anyhow::anyhow!("invalid key"))?;
        let shared = Arc::new(Shared::open(path.clone(), key)?);
        if request.action == "unlink" && shared.snapshot().identity.is_none() {
            fs::remove_dir_all(&path)?;
            return Ok(json!({"state":"unlinked"}));
        }
        let (commands, mut receive) = async_mpsc::channel::<Command>(8);
        let (stop, mut stopping) = watch::channel(false);
        let (finished, stopped) = mpsc::sync_channel(1);
        let state = shared.clone(); let key = request.key.clone(); let pair = request.action == "pair";
        let restoring = state.snapshot().identity.is_some();
        let worker_lock = lock.clone();
        // Protocol/crypto futures (especially libsignal's debug builds) exceed
        // the platform's 2 MiB thread default. Keep the same explicit stack
        // budget on the actor and Tokio's blocking workers.
        std::thread::Builder::new().name(format!("paired-{}", B::PROVIDER)).stack_size(16 * 1024 * 1024).spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().thread_stack_size(16 * 1024 * 1024).enable_all().build().expect("paired runtime");
            let outcome = tokio::task::LocalSet::new().block_on(&runtime, async {
                let opened = if restoring {
                    // A first request after restart can itself be unlink. Restore
                    // the existing device before honoring its queued stop signal.
                    tokio::time::timeout(Duration::from_secs(30), B::open(path, key, false, state.clone())).await
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("device restoration timed out")))
                } else { tokio::select! {
                    result = B::open(path, key, pair, state.clone()) => result,
                    _ = stopping.changed() => return Ok(()),
                } };
                match opened {
                    Ok(mut backend) => {
                        if *stopping.borrow() {
                            return tokio::time::timeout(Duration::from_secs(30), backend.unlink()).await
                                .unwrap_or_else(|_| Err(anyhow::anyhow!("remote unlink timed out")));
                        }
                        loop {
                        tokio::select! {
                            command = receive.recv() => match command {
                                Some(command) => {
                                    let result = tokio::time::timeout(Duration::from_secs(30), backend.send(command.peer, command.text)).await
                                        .unwrap_or_else(|_| Err(anyhow::anyhow!("send timed out; delivery may have occurred")));
                                    let _ = command.reply.send(result);
                                }
                                None => return Ok(()),
                            },
                            _ = stopping.changed() => {
                                match tokio::time::timeout(Duration::from_secs(30), backend.unlink()).await {
                                    Ok(result) => return result,
                                    Err(_) => return Err(anyhow::anyhow!("remote unlink timed out")),
                                }
                            }
                        }
                    } },
                    Err(_) => { state.disconnected("Connection failed. Unlink and scan a new QR code"); return Err(anyhow::anyhow!("device connection failed")); },
                }
            });
            // Drop the LocalSet/runtime (and every protocol task) before the
            // caller can erase state or hand the device lock to another worker.
            drop(runtime);
            drop(worker_lock);
            let _ = finished.send(outcome);
        })?;
        sessions.insert(name.clone(), Session { shared, commands, stop, stopped, _lock: lock });
    }
    let session = sessions.get_mut(&name).unwrap();
    ensure!(hex::decode(&request.key)?.as_slice() == session.shared.key, "credential changed; unlink first");
    match request.action.as_str() {
        "pair" | "status" => Ok(serde_json::to_value(session.shared.snapshot())?),
        "read" => session.shared.read(&request),
        "send" => {
            let status = session.shared.snapshot();
            ensure!(status.state == "connected" && status.identity.as_deref() == Some(request.sender.as_str()), "device is not connected or sender mismatch");
            let (reply, result) = mpsc::sync_channel(1);
            session.commands.try_send(Command { peer: request.peer, text: request.text, reply })?;
            drop(sessions);
            result.recv_timeout(Duration::from_secs(35))?
        }
        "unlink" => {
            let session = sessions.remove(&name).unwrap();
            drop(sessions);
            // An unpaired/expired worker can always be cancelled and erased.
            // Linked workers must complete remote unlink; a failure retains keys.
            let unpaired = session.shared.snapshot().identity.is_none();
            let _ = session.stop.send(true);
            match session.stopped.recv_timeout(Duration::from_secs(35)) {
                Ok(Ok(())) => {},
                Ok(Err(_)) if unpaired => {},
                _ => bail!("could not unlink device; retry"),
            }
            let path = session.shared.path.clone();
            // Lock remains held until every protocol task has stopped.
            fs::remove_dir_all(&path)?;
            drop(session);
            Ok(json!({"state":"unlinked"}))
        }
        _ => bail!("unknown action"),
    }
}

/// The only C-facing entry. Provider crates keep their registry private and
/// export this function only to the broker's dlopen shim. No HTTP listener.
///
/// # Safety
/// `input` must point to a NUL-terminated UTF-8 string owned by the caller.
pub unsafe fn ffi_call<B: Backend>(registry: &'static OnceLock<Sessions>, input: *const c_char) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> Result<Value> {
        ensure!(!input.is_null(), "missing input");
        let bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
        ensure!(bytes.len() <= MAX_WIRE, "request too large");
        let request: Request = serde_json::from_slice(bytes)?;
        let limit = request.response_limit;
        let body = execute::<B>(registry.get_or_init(|| Mutex::new(HashMap::new())), request)?;
        ensure!(serde_json::to_vec(&body)?.len() <= limit, "response exceeds byte limit");
        Ok(json!({"status":200,"body":body.to_string()}))
    });
    let response = match result {
        Ok(Ok(value)) => value,
        _ => json!({"status":502,"body":"{\"error\":\"paired_device_unavailable\"}"}),
    };
    CString::new(response.to_string()).unwrap().into_raw()
}

/// # Safety
/// `value` must be a pointer returned by this library's `ffi_call`, once only.
pub unsafe fn ffi_free(value: *mut c_char) { if !value.is_null() { drop(unsafe { CString::from_raw(value) }); } }

#[macro_export]
macro_rules! export_adapter {
    ($backend:ty) => {
        static SESSIONS: std::sync::OnceLock<$crate::Registry> = std::sync::OnceLock::new();
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn liaison_paired_call(input: *const std::ffi::c_char) -> *mut std::ffi::c_char {
            unsafe { $crate::ffi_call::<$backend>(&SESSIONS, input) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn liaison_paired_free(value: *mut std::ffi::c_char) { unsafe { $crate::ffi_free(value) } }
    };
}
#[doc(hidden)] pub type Registry = Sessions;

#[cfg(test)]
mod tests {
    use super::*;
    fn scratch() -> PathBuf {
        let parent = std::env::var("LIAISON_TEST_TEMP").expect("set LIAISON_TEST_TEMP to an approved scratch directory");
        let mut random = [0; 16]; getrandom::fill(&mut random).unwrap();
        let path = PathBuf::from(parent).join(hex::encode(random)); directory(&path).unwrap(); path
    }
    fn request() -> Request {
        Request { provider:"signal".into(), organization:"org".into(), account:"owner/connection".into(), key:hex::encode([7;32]),
            action:"read".into(), sender:"sender".into(), peer:"alice".into(), text:String::new(), after:"0".into(), response_limit:4096 }
    }
    #[test]
    fn rejects_boundary_overrides_before_session_creation() {
        let mut r=request(); assert!(r.validate("signal").is_ok());
        r.account="owner/../connection".into(); assert!(r.validate("signal").is_err());
        r=request(); r.organization="..".into(); assert!(r.validate("signal").is_err());
        r=request(); r.action="shell".into(); assert!(r.validate("signal").is_err());
        r=request(); r.key="not-a-key".into(); assert!(r.validate("signal").is_err());
        r=request(); r.after="01".into(); assert!(r.validate("signal").is_err());
        assert!(serde_json::from_value::<Request>(json!({"provider":"signal","url":"https://other"})).is_err());
    }
    #[test]
    fn encrypted_inbox_restores_identity_and_filters_before_disclosure() {
        let path=scratch();
        let shared=Shared::open(path.clone(),[7;32]).unwrap();
        shared.connected("sender".into()).unwrap();
        shared.push("a".into(),"alice".into(),"private alice message".into(),1).unwrap();
        shared.push("b".into(),"bob".into(),"private bob message".into(),2).unwrap();
        shared.push("a".into(),"alice".into(),"duplicate".into(),1).unwrap();
        let page=shared.read(&request()).unwrap();
        assert_eq!(page["messages"].as_array().unwrap().len(),1);
        assert_eq!(page["messages"][0]["body"],"private alice message");
        let raw=fs::read(path.join("inbox.enc")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("private"));
        drop(shared);
        assert!(Shared::open(path.clone(),[8;32]).is_err());
        let restored=Shared::open(path.clone(),[7;32]).unwrap();
        assert_eq!(restored.read(&request()).unwrap(),page);
        let mut changed=request(); changed.sender="other".into(); assert!(restored.read(&changed).is_err());
        changed=request(); changed.after="1".into(); assert_eq!(restored.read(&changed).unwrap()["messages"],json!([]));
        assert!(restored.connected("other".into()).is_err());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn filesystem_lock_and_symlink_boundaries() {
        let path=scratch(); let file=private_file(&path.join("lock")).unwrap(); file.try_lock_exclusive().unwrap();
        assert!(private_file(&path.join("lock")).unwrap().try_lock_exclusive().is_err());
        #[cfg(unix)] {
            std::os::unix::fs::symlink(path.join("lock"),path.join("link")).unwrap();
            assert!(private_file(&path.join("link")).is_err());
            assert!(directory(&path.join("link")).is_err());
        }
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn expired_qr_is_not_returned_and_small_pages_refuse_oversize_messages() {
        let path=scratch(); let shared=Shared::open(path.clone(),[7;32]).unwrap();
        shared.qr("sensitive pairing material".into(),0);
        assert_eq!(shared.snapshot().state,"expired"); assert!(shared.snapshot().qr.is_none());
        shared.connected("sender".into()).unwrap(); shared.push("a".into(),"alice".into(),"x".repeat(3000),1).unwrap();
        let mut small=request();small.response_limit=1024; assert!(shared.read(&small).is_err());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn unlink_after_restart_restores_before_remote_logout_and_cancels_pending_pairing() {
        use std::sync::atomic::{AtomicUsize,Ordering};
        static RESTORED: AtomicUsize=AtomicUsize::new(0);
        static UNLINKED: AtomicUsize=AtomicUsize::new(0);
        struct Restoring;
        impl Backend for Restoring {
            const PROVIDER: &'static str="signal";
            async fn open(_:PathBuf,_:String,pair:bool,shared:Arc<Shared>)->Result<Self> {
                if pair { shared.qr("fixture".into(),60); return std::future::pending().await; }
                tokio::time::sleep(Duration::from_millis(30)).await;
                RESTORED.fetch_add(1,Ordering::SeqCst); Ok(Self)
            }
            async fn send(&mut self,_:String,_:String)->Result<Value>{bail!("not used")}
            async fn unlink(&mut self)->Result<()>{UNLINKED.fetch_add(1,Ordering::SeqCst);Ok(())}
        }
        let root=scratch();
        let previous=std::env::var_os("LIAISON_PAIRED_DIR");
        // No other test changes this variable or starts an actor.
        unsafe { std::env::set_var("LIAISON_PAIRED_DIR",&root); }
        let mut r=request();r.action="unlink".into();
        let path=session_path(&r).unwrap();
        Shared::open(path.clone(),[7;32]).unwrap().connected("sender".into()).unwrap();
        let registry=Mutex::new(HashMap::new());
        assert_eq!(execute::<Restoring>(&registry,r).unwrap()["state"],"unlinked");
        assert_eq!(RESTORED.load(Ordering::SeqCst),1);assert_eq!(UNLINKED.load(Ordering::SeqCst),1);
        assert!(!path.exists());assert!(registry.lock().unwrap().is_empty());
        let mut r=request();r.action="pair".into();execute::<Restoring>(&registry,r).unwrap();
        let mut r=request();r.action="unlink".into();execute::<Restoring>(&registry,r).unwrap();
        assert!(!path.exists());assert!(registry.lock().unwrap().is_empty());
        assert_eq!(UNLINKED.load(Ordering::SeqCst),1);
        unsafe { match previous {Some(value)=>std::env::set_var("LIAISON_PAIRED_DIR",value),None=>std::env::remove_var("LIAISON_PAIRED_DIR")} }
        fs::remove_dir_all(root).unwrap();
    }
}
