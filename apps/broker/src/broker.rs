//! Transport-independent broker core: conversations, sessions, host list,
//! connect/lease bookkeeping, probes and the reaper. The HTTP layer (`api.rs`)
//! only parses requests and maps results to status codes.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::json;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::config::Config;
use crate::device::{proof_message, DeviceKey, DeviceProof};
use crate::directory::{DirError, Directory};
use crate::enrol::valid_passkey_mapping;
use crate::hbac::{assigned_hosts, DirectoryView, UserView};
use crate::kerberos::{Kerberos, KrbError, LoginOptions, UserTicket};
use crate::passkey::{Assertion, Challenge, PromptData};
use crate::pins::{PinCheck, PinStore};
use crate::probe::Prober;
use crate::ratelimit::{Attempt, RateLimiter};
use crate::relay::{Relay, RelayRequest};
use crate::sessions::{SessionRecord, SessionStore};
use crate::util::{random_token, sha256, valid_username, Clock};

mod admin_view;
mod enrol;
pub use enrol::{EnrolPrompt, EnrolReply, EnrolStartReply};

// ---------------------------------------------------------------- replies

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct Prompt {
    pub id: &'static str,
    pub style: &'static str,
    pub text: &'static str,
    /// Only on the `passkey` prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passkey: Option<PromptData>,
}

/// `auth/start` `method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    PasswordOtp,
    Passkey,
}

impl Method {
    /// Absent or `password_otp` → password + OTP; `passkey`; anything else is refused.
    pub fn parse(m: Option<&str>) -> Option<Method> {
        match m {
            None | Some("password_otp") => Some(Method::PasswordOtp),
            Some("passkey") => Some(Method::Passkey),
            Some(_) => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Method::PasswordOtp => "password_otp",
            Method::Passkey => "passkey",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ChallengeReply {
    pub state: &'static str,
    pub conversation_id: String,
    pub prompts: Vec<Prompt>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticatedReply {
    pub state: &'static str,
    pub session_token: String,
    pub expires_in: u64,
    pub username: String,
    /// Present (true) only for sessions bound to a device key (§14.2).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub device_bound: bool,
    /// Only after a fresh password + OTP sign-in, for a short-lived optional
    /// registration on this device. Absent for older clients and passkey logins.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub passkey_setup_available: bool,
}

/// A bearer credential as presented on one request: the token plus, for a
/// device-bound session, the proof headers (§14.2).
#[derive(Debug, Clone)]
pub struct Bearer<'a> {
    pub token: &'a str,
    pub proof: Option<DeviceProof>,
}

impl<'a> From<&'a str> for Bearer<'a> {
    fn from(token: &'a str) -> Self {
        Bearer { token, proof: None }
    }
}

impl<'a> From<&'a String> for Bearer<'a> {
    fn from(token: &'a String) -> Self {
        Bearer { token, proof: None }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct HostEntry {
    pub id: String,
    pub name: String,
    pub online: bool,
    pub busy: Option<bool>,
    pub in_use_by: Option<String>,
    pub connected_users: Vec<String>,
    pub connectable: bool,
    /// Set only by administrator admission policy, never Host discovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_desktop: Option<bool>,
    pub reason: Option<String>,
    /// SHA-256 (hex) of the host's image, present only when a valid one is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<String>,
}

/// `GET /v1/hosts/{id}/image`: a small PNG, base64 inside the usual JSON.
#[derive(Debug, Serialize)]
pub struct ImageReply {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub sha256: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct HostsReply {
    pub hosts: Vec<HostEntry>,
}

#[derive(Debug, Serialize)]
pub struct ConnectReply {
    /// `relay` (endpoint:port is a broker lease) or `direct` (endpoint:port is the host itself).
    pub route: &'static str,
    pub endpoint: String,
    pub port: u16,
    pub host_cert_sha256: String,
    pub username: String,
    pub gssapi_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_username: Option<String>,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct KeepaliveReply {
    pub state: &'static str,
    pub expires_in: u64,
}

#[derive(Debug, PartialEq)]
pub enum ApiError {
    /// Generic authentication failure: `{"state":"denied"}`.
    Denied,
    /// Missing/unknown/expired bearer.
    Unauthorized,
    RateLimited(u64),
    /// Host known and assigned but not usable now (offline, pin mismatch, …).
    Unavailable(&'static str),
    /// No live lease for keepalive.
    NoLease,
    /// Every session port is leased.
    Exhausted,
    BadRequest,
    /// Directory / KDC / relay failure.
    Internal(&'static str),
    /// No such resource for this caller (never says whether it exists for others).
    NotFound,
}

// ---------------------------------------------------------------- state

struct Conversation {
    username: String,
    ip: IpAddr,
    created: Instant,
    auth: ConvAuth,
    /// Device key from `auth/start` (§14): the session will be bound to it.
    device: Option<DeviceKey>,
}

enum ConvAuth {
    PasswordOtp,
    /// `None`: synthetic challenge (no KDC exchange behind it); `respond` is denied.
    Passkey(Option<PasskeyWorker>),
}

impl Conversation {
    fn method(&self) -> Method {
        match self.auth {
            ConvAuth::PasswordOtp => Method::PasswordOtp,
            ConvAuth::Passkey(_) => Method::Passkey,
        }
    }
}

/// A KDC exchange parked in the responder on a worker thread, waiting for the
/// client's assertion. Dropping it (respond, expiry, reaper) disconnects `answer`,
/// which aborts the exchange.
struct PasskeyWorker {
    challenge: Challenge,
    answer: SyncSender<Assertion>,
    result: tokio::sync::oneshot::Receiver<Result<UserTicket, KrbError>>,
}

/// Keeps `Broker::passkey_workers` accurate for the life of a worker thread.
struct WorkerCount(Arc<AtomicUsize>);
impl WorkerCount {
    fn new(c: &Arc<AtomicUsize>) -> WorkerCount {
        c.fetch_add(1, Ordering::SeqCst);
        WorkerCount(c.clone())
    }
}
impl Drop for WorkerCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How long `respond` waits for the KDC to judge a passkey answer.
const PASSKEY_VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// Session times are unix seconds: device-bound sessions are persisted and
/// outlive both the process and (after a reboot) any monotonic clock.
struct Session {
    /// Short correlation id for logs (prefix of the token hash).
    id: String,
    username: String,
    ccache: String,
    created_unix: u64,
    last_used_unix: u64,
    /// Absolute end. Unbound: min(session_absolute, TGT end). Bound: min(device
    /// absolute, renew_till); the TGT itself is renewed before `ticket_end_unix`.
    ends_unix: u64,
    /// Device key the session is bound to (§14), `None` for an unbound session.
    device: Option<DeviceKey>,
    ticket_end_unix: u64,
    renew_till_unix: u64,
    /// Accepted proofs (SHA-256 of the signature → proof time), for replay refusal.
    proofs: HashMap<[u8; 32], u64>,
    /// `last_used_unix` as last written to the session record.
    persisted_last_used: u64,
    /// Every (client, port) this session ever leased: flushed from conntrack at the end.
    ports_used: Vec<(Ipv4Addr, u16)>,
    /// Hosts admitted since startup, including expired leases with established flows.
    hosts_used: Vec<String>,
    /// Never persisted. A fresh OTP sign-in grants five minutes to add one
    /// key using this session's user Kerberos ticket and IPA self-service ACL.
    passkey_setup: Option<PendingPasskeySetup>,
    /// A repeated request with this exact mapping can confirm success after a
    /// lost HTTP reply, without retaining the password or writing IPA twice.
    completed_passkey_setup: Option<[u8; 32]>,
}

struct PendingPasskeySetup {
    created: Instant,
    attempts: u8,
    in_flight: bool,
}

const PASSKEY_SETUP_TTL: Duration = Duration::from_secs(300);
const PASSKEY_SETUP_ATTEMPTS: u8 = 3;

impl Session {
    fn record(&self, key: &[u8; 32]) -> Option<SessionRecord> {
        let device = self.device.as_ref()?;
        Some(SessionRecord {
            v: 1,
            key: hex::encode(key),
            id: self.id.clone(),
            username: self.username.clone(),
            ccache: self.ccache.clone(),
            device_key: SessionRecord::encode_device(device),
            created_unix: self.created_unix,
            last_used_unix: self.last_used_unix,
            ends_unix: self.ends_unix,
            ticket_end_unix: self.ticket_end_unix,
            renew_till_unix: self.renew_till_unix,
        })
    }
}

#[derive(Clone)]
struct Lease {
    session: [u8; 32],
    host: String,
    client: Ipv4Addr,
    target: Ipv4Addr,
    expires: Instant,
}

/// A `connect` answered with the host itself (client inside `direct_client_cidrs`).
/// Nothing is opened; it only lets keepalive keep the broker session alive while
/// the stream runs.
#[derive(Clone)]
struct DirectGrant {
    session: [u8; 32],
    host: String,
    client: Ipv4Addr,
    expires: Instant,
}

// Client-reported streaming presence, separate from transport grants: preparing
// a connection and browsing the dashboard must never imply a live stream.
struct Presence {
    host: String,
    sequence: u64,
    connected: bool,
    expires: Instant,
}

const PRESENCE_TTL: Duration = Duration::from_secs(60);
const MAX_PRESENCES_PER_SESSION: usize = 64;

#[derive(Default)]
struct State {
    conversations: HashMap<String, Conversation>,
    sessions: HashMap<[u8; 32], Session>,
    leases: HashMap<u16, Lease>,
    direct: Vec<DirectGrant>,
    presence: HashMap<([u8; 32], String), Presence>,
    next_port: u16,
    /// Passkey `auth/start` calls waiting for the KDC's challenge (reserved slots).
    passkey_starting: usize,
}

#[derive(Clone, Debug)]
pub struct HostStatus {
    pub online: bool,
    pub busy: Option<bool>,
    pub cert_sha256: Option<[u8; 32]>,
    pub pin_mismatch: bool,
    pub checked: Instant,
}

pub struct Deps {
    pub krb: Arc<dyn Kerberos>,
    pub dir: Arc<dyn Directory>,
    pub relay: Arc<dyn Relay>,
    pub prober: Arc<dyn Prober>,
    pub pins: Arc<PinStore>,
    pub audit: Arc<Audit>,
    pub clock: Arc<dyn Clock>,
    pub sessions: Arc<SessionStore>,
}

pub struct Broker {
    pub cfg: Config,
    pub(crate) diagnostic_writer: Arc<tokio::sync::Semaphore>,
    d: Deps,
    direct_nets: Vec<ipnet::Ipv4Net>,
    st: Mutex<State>,
    limiter: Arc<Mutex<RateLimiter>>,
    status: RwLock<HashMap<String, HostStatus>>,
    view: tokio::sync::Mutex<Option<(Instant, Arc<DirectoryView>)>>,
    users: Mutex<HashMap<String, (Instant, Option<UserView>)>>,
    /// Live passkey worker threads (including ones still winding down).
    passkey_workers: Arc<AtomicUsize>,
    passkey_rp_id: String,
    /// Enrolment conversations (§16), separate from sign-in conversations.
    enrol: Mutex<HashMap<String, enrol::EnrolConv>>,
    /// Enrolment password proofs per user in the last 24 h (`enrol.daily_cap`).
    enrol_daily: Mutex<HashMap<String, std::collections::VecDeque<Instant>>>,
    thumbs: Option<crate::thumbs::Thumbs>,
}

const PROMPTS: [Prompt; 2] = [
    Prompt { id: "password", style: "secret", text: "Password", passkey: None },
    Prompt { id: "otp", style: "otp", text: "Authenticator code", passkey: None },
];

/// A reserved per-user KDC attempt (see `RateLimiter::begin_attempt`). Owned, so the login
/// task can finish it after the HTTP request is gone; dropped unfinished it stays counted.
struct AttemptGuard {
    limiter: Arc<Mutex<RateLimiter>>,
    clock: Arc<dyn crate::util::Clock>,
    user: String,
    attempt: Option<Attempt>,
    done: bool,
}

impl AttemptGuard {
    fn finish(mut self, counted: bool) {
        self.done = true;
        let now = self.clock.now();
        self.limiter.lock().unwrap().end_attempt(&self.user, self.attempt, counted, now);
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        if !self.done {
            let now = self.clock.now();
            self.limiter.lock().unwrap().end_attempt(&self.user, self.attempt, true, now);
        }
    }
}

/// Only a wrong password feeds the directory's lockout counter: not a right one, not an
/// infrastructure problem and not a principal the directory does not know.
fn counts_as_wrong_password(res: &Result<UserTicket, KrbError>) -> bool {
    matches!(res, Err(KrbError::Denied(m)) if !m.starts_with("unknown principal"))
}

const PROMPTS_AD: [Prompt; 1] = [Prompt { id: "password", style: "secret", text: "Password", passkey: None }];

fn v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    }
}

impl Broker {
    pub fn new(cfg: Config, d: Deps) -> Arc<Broker> {
        let mut limiter = RateLimiter::new(&cfg.limits);
        if cfg.directory.backend == crate::config::DirectoryBackend::Ad {
            // AD's bad-password counter resets one observation window after the last failure.
            let w = cfg.ad.lockout_window_secs.unwrap_or(0) + cfg.ad.lockout_margin_secs;
            limiter = limiter.with_user_reset(Duration::from_secs(w));
        }
        let st = State { next_port: cfg.relay.port_min, ..Default::default() };
        let direct_nets = cfg.routing.direct_nets();
        let passkey_rp_id = cfg.passkey.rp_id(&cfg.kerberos.realm);
        let thumbs = cfg.thumbnails.as_ref().map(|t| crate::thumbs::Thumbs::new(t.directory.clone()));
        Arc::new(Broker {
            cfg,
            diagnostic_writer: Arc::new(tokio::sync::Semaphore::new(1)),
            d,
            direct_nets,
            st: Mutex::new(st),
            limiter: Arc::new(Mutex::new(limiter)),
            status: RwLock::new(HashMap::new()),
            view: tokio::sync::Mutex::new(None),
            users: Mutex::new(HashMap::new()),
            passkey_workers: Arc::new(AtomicUsize::new(0)),
            passkey_rp_id,
            enrol: Mutex::new(HashMap::new()),
            enrol_daily: Mutex::new(HashMap::new()),
            thumbs,
        })
    }

    fn now(&self) -> Instant {
        self.d.clock.now()
    }

    /// Active Directory backend: password-only sign-in, no passkeys, no enrolment.
    fn ad_mode(&self) -> bool {
        self.cfg.directory.backend == crate::config::DirectoryBackend::Ad
    }

    fn audit(&self, ev: &str, f: serde_json::Value) {
        self.d.audit.event(ev, f);
    }

    // ------------------------------------------------------------ auth

    /// Normalise the user name and apply the start rate limits.
    fn start_checks(&self, ip: IpAddr, username: &str) -> Result<String, ApiError> {
        let now = self.now();
        let username = username.trim().to_ascii_lowercase();
        if username.is_empty() || username.len() > 256 {
            return Err(ApiError::BadRequest);
        }
        let mut l = self.limiter.lock().unwrap();
        if let Some(r) = l.blocked(Some(&username), ip, now) {
            return Err(ApiError::RateLimited(r));
        }
        l.start(ip, now).map_err(ApiError::RateLimited)?;
        Ok(username)
    }

    /// Store a conversation under a fresh id (global table cap).
    fn insert_conversation(&self, st: &mut State, conv: Conversation) -> Result<String, ApiError> {
        let ttl = Duration::from_secs(self.cfg.limits.conversation_ttl_secs);
        let now = self.now();
        if st.conversations.len() >= self.cfg.limits.max_conversations {
            st.conversations.retain(|_, c| now.duration_since(c.created) < ttl);
            if st.conversations.len() >= self.cfg.limits.max_conversations {
                warn!("conversation table full");
                return Err(ApiError::RateLimited(10));
            }
        }
        let id = random_token();
        st.conversations.insert(id.clone(), conv);
        Ok(id)
    }

    pub fn auth_start(&self, ip: IpAddr, username: &str) -> Result<ChallengeReply, ApiError> {
        self.auth_start_device(ip, username, None)
    }

    fn auth_start_device(
        &self,
        ip: IpAddr,
        username: &str,
        device: Option<DeviceKey>,
    ) -> Result<ChallengeReply, ApiError> {
        let username = self.start_checks(ip, username)?;
        let conv = Conversation { username, ip, created: self.now(), auth: ConvAuth::PasswordOtp, device };
        let id = self.insert_conversation(&mut self.st.lock().unwrap(), conv)?;
        let prompts = if self.ad_mode() { PROMPTS_AD.to_vec() } else { PROMPTS.to_vec() };
        Ok(ChallengeReply { state: "challenge", conversation_id: id, prompts })
    }

    pub async fn auth_start_method(
        &self,
        ip: IpAddr,
        username: &str,
        method: Method,
        device: Option<DeviceKey>,
    ) -> Result<ChallengeReply, ApiError> {
        match method {
            Method::PasswordOtp => self.auth_start_device(ip, username, device),
            Method::Passkey if self.ad_mode() => Err(ApiError::BadRequest),
            Method::Passkey => self.auth_start_passkey_device(ip, username, device).await,
        }
    }

    /// Ticket options for a login: device-bound logins get a renewable TGT in a
    /// persistent ccache (§14.3).
    fn login_options(&self, device: &Option<DeviceKey>) -> LoginOptions {
        match device {
            Some(_) => LoginOptions {
                // "Never" at the application layer requests the largest renewal
                // interval supported by MIT's signed 32-bit krb5_deltat API.
                renew_life_secs: Some(match self.cfg.limits.device_session_absolute_secs {
                    0 => i32::MAX as u32,
                    secs => secs.min(i32::MAX as u64) as u32,
                }),
                persistent: true,
            },
            None => LoginOptions::default(),
        }
    }

    /// Passkey start: run the AS exchange on a worker thread until the KDC's
    /// challenge arrives and hand that to the client. A user the KDC offers no
    /// passkey challenge (unknown, OTP user, invalid name, KDC down or slow) gets a
    /// synthetic challenge of the same shape, so the reply never reveals which.
    pub async fn auth_start_passkey(&self, ip: IpAddr, username: &str) -> Result<ChallengeReply, ApiError> {
        self.auth_start_passkey_device(ip, username, None).await
    }

    async fn auth_start_passkey_device(
        &self,
        ip: IpAddr,
        username: &str,
        device: Option<DeviceKey>,
    ) -> Result<ChallengeReply, ApiError> {
        let username = self.start_checks(ip, username)?;
        let slot = self.reserve_passkey_slot()?;
        let opts = self.login_options(&device);
        let worker = if valid_username(&username) { self.spawn_passkey(&username, opts).await } else { None };
        let passkey = match &worker {
            Some(w) => {
                if w.challenge.domain != self.passkey_rp_id {
                    error!(
                        "KDC passkey domain {} differs from passkey.rp_id {}; assertions will fail",
                        w.challenge.domain, self.passkey_rp_id
                    );
                }
                PromptData::from_challenge(&w.challenge, &self.passkey_rp_id)
            }
            None => PromptData::synthetic(&self.passkey_rp_id),
        };
        let conv = Conversation { username, ip, created: self.now(), auth: ConvAuth::Passkey(worker), device };
        let id = {
            let mut st = self.st.lock().unwrap();
            st.passkey_starting -= 1;
            std::mem::forget(slot);
            self.insert_conversation(&mut st, conv)?
        };
        let prompt = Prompt { id: "passkey", style: "passkey", text: "Passkey", passkey: Some(passkey) };
        Ok(ChallengeReply { state: "challenge", conversation_id: id, prompts: vec![prompt] })
    }

    /// Count this start against `passkey.max_pending` (waiting conversations, starts
    /// in flight and live worker threads). Independent of the user name.
    fn reserve_passkey_slot(&self) -> Result<StartSlot<'_>, ApiError> {
        let now = self.now();
        let ttl = Duration::from_secs(self.cfg.limits.conversation_ttl_secs);
        let max = self.cfg.passkey.max_pending;
        let mut st = self.st.lock().unwrap();
        let pending = |st: &State| {
            st.passkey_starting
                + st.conversations
                    .values()
                    .filter(|c| c.method() == Method::Passkey && now.duration_since(c.created) < ttl)
                    .count()
        };
        if pending(&st) >= max || self.passkey_workers.load(Ordering::SeqCst) >= max {
            st.conversations.retain(|_, c| now.duration_since(c.created) < ttl);
            if pending(&st) >= max || self.passkey_workers.load(Ordering::SeqCst) >= max {
                warn!("passkey conversations at the limit ({max})");
                return Err(ApiError::RateLimited(10));
            }
        }
        st.passkey_starting += 1;
        Ok(StartSlot(&self.st))
    }

    /// Start the KDC exchange for `username` on a worker thread and wait for its
    /// challenge. `None` when the KDC offers none within the timeout.
    async fn spawn_passkey(&self, username: &str, opts: LoginOptions) -> Option<PasskeyWorker> {
        let (ch_tx, ch_rx) = tokio::sync::oneshot::channel::<Challenge>();
        let (ans_tx, ans_rx) = std::sync::mpsc::sync_channel::<Assertion>(1);
        let (res_tx, mut res_rx) = tokio::sync::oneshot::channel();
        let krb = self.d.krb.clone();
        let user = username.to_string();
        let wait = Duration::from_secs(self.cfg.limits.conversation_ttl_secs);
        let live = WorkerCount::new(&self.passkey_workers);
        let spawned = std::thread::Builder::new().name("plank-passkey".into()).spawn(move || {
            let _live = live;
            let mut ch_tx = Some(ch_tx);
            let mut ask = |c: &Challenge| -> Option<Assertion> {
                ch_tx.take()?.send(c.clone()).ok()?;
                // Blocks until respond delivers, the conversation is dropped, or the
                // conversation lifetime passes in real time (backstop).
                ans_rx.recv_timeout(wait).ok()
            };
            let r = krb.login_passkey(&user, &mut ask, opts);
            if let Err(Ok(t)) = res_tx.send(r) {
                krb.destroy(&t.ccache);
            }
        });
        if let Err(e) = spawned {
            error!("passkey worker thread: {e}");
            return None;
        }
        match tokio::time::timeout(Duration::from_secs(self.cfg.passkey.challenge_timeout_secs), ch_rx).await {
            Ok(Ok(challenge)) => Some(PasskeyWorker { challenge, answer: ans_tx, result: res_rx }),
            Ok(Err(_)) => {
                // The exchange ended without a challenge; its result is already sent.
                match res_rx.try_recv() {
                    Ok(Err(KrbError::Unavailable(m))) => error!("KDC unavailable (passkey start): {m}"),
                    Ok(Err(KrbError::Denied(m))) => debug!(user = %username, "no passkey challenge: {m}"),
                    _ => {}
                }
                None
            }
            Err(_) => {
                warn!(user = %username, "no passkey challenge from the KDC in time");
                None
            }
        }
    }

    /// Always takes at least `min_respond_ms` (constant-ish timing).
    pub async fn auth_respond(
        &self,
        ip: IpAddr,
        conversation_id: &str,
        responses: Vec<Zeroizing<String>>,
    ) -> Result<AuthenticatedReply, ApiError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.cfg.limits.min_respond_ms);
        let r = self.respond_inner(ip, conversation_id, responses).await;
        tokio::time::sleep_until(deadline).await;
        r
    }

    fn fail(&self, user: &str, ip: IpAddr, method: Method, reason: &str) {
        let burst = self.limiter.lock().unwrap().failure(user, ip, self.now());
        self.audit(
            "login_fail",
            json!({"user": user, "ip": ip.to_string(), "method": method.as_str(), "reason": reason}),
        );
        if burst {
            self.audit(
                "failure_burst",
                json!({"per_minute": self.cfg.limits.global_failure_burst_per_minute, "last_ip": ip.to_string()}),
            );
        }
    }

    /// Take the conversation and check it belongs to this address, is fresh, the
    /// (user, IP) is not blocked, and it was started for `method`.
    fn take_conversation(
        &self,
        ip: IpAddr,
        conversation_id: &str,
        method: Method,
    ) -> Result<(String, ConvAuth, Option<DeviceKey>), ApiError> {
        let now = self.now();
        let conv = self.st.lock().unwrap().conversations.remove(conversation_id);
        let Some(conv) = conv else { return Err(ApiError::Denied) };
        let conv_method = conv.method();
        let Conversation { username: user, ip: conv_ip, created, auth, device } = conv;
        if now.duration_since(created) >= Duration::from_secs(self.cfg.limits.conversation_ttl_secs) || conv_ip != ip {
            self.audit(
                "login_fail",
                json!({"user": user, "ip": ip.to_string(), "method": conv_method.as_str(), "reason": "conversation"}),
            );
            return Err(ApiError::Denied);
        }
        if let Some(r) = self.limiter.lock().unwrap().blocked(Some(&user), ip, now) {
            return Err(ApiError::RateLimited(r));
        }
        if conv_method != method {
            self.fail(&user, ip, conv_method, "malformed");
            return Err(ApiError::Denied);
        }
        Ok((user, auth, device))
    }

    /// Make room for one more session, or refuse.
    async fn ensure_session_room(&self) -> Result<(), ApiError> {
        if self.st.lock().unwrap().sessions.len() >= self.cfg.limits.max_sessions {
            self.reap().await;
            if self.st.lock().unwrap().sessions.len() >= self.cfg.limits.max_sessions {
                error!("session table full");
                return Err(ApiError::Denied);
            }
        }
        Ok(())
    }

    async fn respond_inner(
        &self,
        ip: IpAddr,
        conversation_id: &str,
        responses: Vec<Zeroizing<String>>,
    ) -> Result<AuthenticatedReply, ApiError> {
        let m = Method::PasswordOtp;
        let (user, _, device) = self.take_conversation(ip, conversation_id, m)?;
        let ad = self.ad_mode();
        let password_ok = !responses.is_empty()
            && !responses[0].is_empty()
            && responses[0].len() <= 1024
            && !responses[0].contains('\0');
        let well_formed = password_ok
            && if ad {
                responses.len() == 1
            } else {
                responses.len() == 2
                    && (6..=10).contains(&responses[1].len())
                    && responses[1].bytes().all(|b| b.is_ascii_digit())
            };
        if !valid_username(&user) || !well_formed {
            self.fail(&user, ip, m, if well_formed { "username" } else { "malformed" });
            return Err(ApiError::Denied);
        }
        self.ensure_session_room().await?;
        let mut responses = responses.into_iter();
        let password = responses.next().expect("validated password response");
        // FreeIPA: password followed by the OTP code. AD: the password alone.
        let mut secret = Zeroizing::new(String::with_capacity(password.len() + 10));
        secret.push_str(&password);
        if let Some(otp) = responses.next() {
            secret.push_str(&otp);
        }
        // Count the attempt before the KDC sees it (pessimistic) and allow one in flight per
        // user. If this future is dropped mid-call the attempt stays counted.
        // Active Directory: only a real, enabled sAMAccountName (exact match) ever reaches the
        // KDC. The KDC also accepts other spellings of an account (UPN prefix); each would get
        // its own count and together they could lock the account. An unknown name is denied
        // without a KDC call and without being tracked.
        if ad {
            match self.user(&user, false).await {
                Ok(Some(u)) if !u.disabled => {}
                Ok(_) => {
                    self.fail(&user, ip, m, "unknown_or_disabled");
                    return Err(ApiError::Denied);
                }
                Err(_) => {
                    self.audit(
                        "login_fail",
                        json!({"user": user, "ip": ip.to_string(), "method": m.as_str(), "reason": "directory_unavailable"}),
                    );
                    return Err(ApiError::Denied);
                }
            }
        }
        // A refusal by the per-user rule must look exactly like a wrong password (generic
        // denial after min_respond_ms, no 429): otherwise it would tell real names from unknown.
        let reserved = self.limiter.lock().unwrap().begin_attempt(&user, self.now());
        let reserved = match reserved {
            Ok(r) => r,
            Err(_) => {
                self.fail(&user, ip, m, "user_limited");
                return Err(ApiError::Denied);
            }
        };
        let guard = AttemptGuard {
            limiter: self.limiter.clone(),
            clock: self.d.clock.clone(),
            user: user.clone(),
            attempt: reserved,
            done: false,
        };
        let krb = self.d.krb.clone();
        let u = user.clone();
        let opts = self.login_options(&device);
        // The login runs to its end in its own task (which owns the attempt), so a slow KDC
        // cannot leave an uncounted request behind; the client waits at most login_timeout.
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let k = krb.clone();
            let res = tokio::task::spawn_blocking(move || k.login(&u, &secret, opts))
                .await
                .unwrap_or_else(|_| Err(KrbError::Unavailable("login task panicked".into())));
            guard.finish(counts_as_wrong_password(&res));
            if let Err(Ok(t)) = tx.send(res) {
                krb.destroy(&t.ccache); // nobody is waiting for this ticket any more
            }
        });
        let res = match tokio::time::timeout(Duration::from_secs(self.cfg.kerberos.login_timeout_secs), rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(KrbError::Unavailable("login task ended without a result".into())),
            Err(_) => Err(KrbError::Unavailable("login timed out".into())),
        };
        let mut reply = self.finish_login(user.clone(), ip, m, res, device)?;
        // Only a fresh OTP proof can open this short-lived enrollment window.
        // IPA still authorizes the mapping write as the user, not the broker.
        let allowed = !ad
            && self
                .d
                .dir
                .enrol_facts(&user)
                .await
                .ok()
                .flatten()
                .is_some_and(|f| !f.disabled && f.auth_types.iter().any(|t| t == "passkey"));
        if allowed && reply.device_bound {
            let key = sha256(reply.session_token.as_bytes());
            if let Some(session) = self.st.lock().unwrap().sessions.get_mut(&key) {
                session.passkey_setup =
                    Some(PendingPasskeySetup { created: self.now(), attempts: 0, in_flight: false });
                reply.passkey_setup_available = true;
            }
        }
        Ok(reply)
    }

    /// Passkey respond; `assertion` is `None` when the client's fields failed
    /// validation. Always takes at least `min_respond_ms`.
    pub async fn auth_respond_passkey(
        &self,
        ip: IpAddr,
        conversation_id: &str,
        assertion: Option<Assertion>,
    ) -> Result<AuthenticatedReply, ApiError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.cfg.limits.min_respond_ms);
        let r = self.respond_passkey_inner(ip, conversation_id, assertion).await;
        tokio::time::sleep_until(deadline).await;
        r
    }

    async fn respond_passkey_inner(
        &self,
        ip: IpAddr,
        conversation_id: &str,
        assertion: Option<Assertion>,
    ) -> Result<AuthenticatedReply, ApiError> {
        let m = Method::Passkey;
        let (user, auth, device) = self.take_conversation(ip, conversation_id, m)?;
        let ConvAuth::Passkey(worker) = auth else { return Err(ApiError::Denied) };
        let Some(a) = assertion else {
            self.fail(&user, ip, m, "malformed");
            return Err(ApiError::Denied);
        };
        let Some(w) = worker else {
            // Synthetic challenge: nothing can answer it.
            self.fail(&user, ip, m, if valid_username(&user) { "no_challenge" } else { "username" });
            return Err(ApiError::Denied);
        };
        if w.challenge.credential_id_for(&a.credential_id).is_none() {
            self.fail(&user, ip, m, "credential");
            return Err(ApiError::Denied);
        }
        self.ensure_session_room().await?;
        let PasskeyWorker { answer, result, .. } = w;
        if answer.try_send(a).is_err() {
            // The worker already gave up (real-time backstop or KDC error).
            self.audit(
                "login_fail",
                json!({"user": user, "ip": ip.to_string(), "method": m.as_str(), "reason": "conversation"}),
            );
            return Err(ApiError::Denied);
        }
        drop(answer);
        let res = match tokio::time::timeout(PASSKEY_VERIFY_TIMEOUT, result).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(KrbError::Unavailable("passkey worker ended without a result".into())),
            Err(_) => Err(KrbError::Unavailable("no KDC verdict on the passkey answer in time".into())),
        };
        self.finish_login(user, ip, m, res, device)
    }

    /// Turn a KDC result into a session (or a generic denial).
    fn finish_login(
        &self,
        user: String,
        ip: IpAddr,
        m: Method,
        res: Result<UserTicket, KrbError>,
        device: Option<DeviceKey>,
    ) -> Result<AuthenticatedReply, ApiError> {
        let ticket = match res {
            Ok(t) => t,
            Err(KrbError::Denied(msg)) => {
                debug!(user = %user, method = m.as_str(), "login denied: {msg}");
                self.fail(&user, ip, m, "credentials");
                return Err(ApiError::Denied);
            }
            Err(KrbError::Unavailable(msg)) => {
                error!("KDC unavailable: {msg}");
                // Not a wrong password, so never counted: tell the operator which problem it is.
                let reason = if msg.contains("TGT verification") {
                    "kdc_unverified"
                } else if msg.to_ascii_lowercase().contains("encryption type") {
                    "etype_unsupported"
                } else {
                    "kdc_unavailable"
                };
                self.audit(
                    "login_fail",
                    json!({"user": user, "ip": ip.to_string(), "method": m.as_str(), "reason": reason}),
                );
                return Err(ApiError::Denied);
            }
        };
        let unix = self.d.clock.unix();
        let tgt_left = ticket.end_unix.saturating_sub(unix);
        if tgt_left < 60 {
            self.d.krb.destroy(&ticket.ccache);
            self.fail(&user, ip, m, "ticket_lifetime");
            return Err(ApiError::Denied);
        }
        // A bound session lives as long as the TGT can be renewed (the KDC may grant
        // less than asked); without a renewable ticket it falls back to the TGT end.
        let life = match &device {
            Some(_) => ticket
                .renew_till_unix
                .max(ticket.end_unix)
                .saturating_sub(unix)
                .min(match self.cfg.limits.device_session_absolute_secs {
                    0 => i32::MAX as u64,
                    secs => secs,
                }),
            None => tgt_left.min(self.cfg.limits.session_absolute_secs),
        };
        let token = random_token();
        let key = sha256(token.as_bytes());
        let id = hex::encode(&key[..6]);
        self.limiter.lock().unwrap().success(&user, ip);
        let bound = device.is_some();
        let session = Session {
            id: id.clone(),
            username: user.clone(),
            ccache: ticket.ccache,
            created_unix: unix,
            last_used_unix: unix,
            ends_unix: unix + life,
            device,
            ticket_end_unix: ticket.end_unix,
            renew_till_unix: ticket.renew_till_unix,
            proofs: HashMap::new(),
            persisted_last_used: unix,
            ports_used: Vec::new(),
            hosts_used: Vec::new(),
            passkey_setup: None,
            completed_passkey_setup: None,
        };
        if let Some(rec) = session.record(&key) {
            if let Err(e) = self.d.sessions.save(&rec) {
                error!("session record: {e:#}");
            }
        }
        self.st.lock().unwrap().sessions.insert(key, session);
        self.audit(
            "login_ok",
            json!({"user": user, "ip": ip.to_string(), "method": m.as_str(), "session": id, "expires_in": life,
                   "device_bound": bound}),
        );
        Ok(AuthenticatedReply {
            state: "authenticated",
            session_token: token,
            expires_in: life,
            username: user,
            device_bound: bound,
            passkey_setup_available: false,
        })
    }

    fn session_expired(&self, s: &Session, now: u64) -> Option<&'static str> {
        let l = &self.cfg.limits;
        let (absolute, idle) = if s.device.is_some() {
            (l.device_session_absolute_secs, l.device_session_idle_secs)
        } else {
            (l.session_absolute_secs, l.session_idle_secs)
        };
        if now >= s.ends_unix
            || now >= s.ticket_end_unix
            || (absolute != 0 && now.saturating_sub(s.created_unix) >= absolute)
        {
            Some("expired")
        } else if idle != 0 && now.saturating_sub(s.last_used_unix) >= idle {
            Some("idle")
        } else {
            None
        }
    }

    /// A device-bound session needs a fresh, unreplayed proof over this request
    /// signed by its key (§14.2); unbound sessions ignore proofs.
    fn proof_ok(
        &self,
        s: &mut Session,
        token: &str,
        proof: Option<&DeviceProof>,
        expect: (&str, &str),
        now: u64,
    ) -> bool {
        let Some(device) = &s.device else { return true };
        let Some(p) = proof else { return false };
        // The proof must be for the operation being performed, not just any request.
        if !p.method.eq_ignore_ascii_case(expect.0) || p.path != expect.1 {
            return false;
        }
        let skew = self.cfg.limits.device_proof_skew_secs;
        if p.time.abs_diff(now) > skew {
            return false;
        }
        let tag = sha256(&p.signature);
        s.proofs.retain(|_, t| t.abs_diff(now) <= skew * 2);
        if s.proofs.contains_key(&tag) {
            return false;
        }
        if !device.verify(&proof_message(&p.method, &p.path, p.time, token, &p.body_sha256), &p.signature) {
            return false;
        }
        s.proofs.insert(tag, p.time);
        true
    }

    /// A remembered login never replaces the current directory account check.
    /// Directory outages preserve the login but deny the operation.
    pub(crate) async fn session<'a>(
        &self,
        bearer: impl Into<Bearer<'a>>,
        expect: (&str, &str),
    ) -> Result<([u8; 32], String, String), ApiError> {
        let out = self.session_proof(bearer, expect).await?;
        let user = self.user(&out.1, false).await?;
        if user.as_ref().is_none_or(|user| user.disabled) {
            self.end_session(out.0, "account_revoked").await;
            return Err(ApiError::Unauthorized);
        }
        if self.password_changed_since_login(&out.0, user.as_ref()) {
            self.end_session(out.0, "password_changed").await;
            return Err(ApiError::Unauthorized);
        }
        Ok(out)
    }

    /// The password was set after this session's sign-in (beyond clock skew between the
    /// directory and this host): the session belongs to the old password.
    fn password_changed_since_login(&self, key: &[u8; 32], user: Option<&UserView>) -> bool {
        const SKEW_SECS: u64 = 120;
        let Some(changed) = user.and_then(|u| u.pwd_last_set_unix) else { return false };
        self.st
            .lock()
            .unwrap()
            .sessions
            .get(key)
            .is_some_and(|s| changed > s.created_unix.saturating_add(SKEW_SECS))
    }

    /// Validate a bearer (and its device proof) and bump its idle timer.
    /// Returns (key, username, ccache).
    async fn session_proof<'a>(
        &self,
        bearer: impl Into<Bearer<'a>>,
        expect: (&str, &str),
    ) -> Result<([u8; 32], String, String), ApiError> {
        let bearer = bearer.into();
        let key = sha256(bearer.token.as_bytes());
        let now = self.d.clock.unix();
        let expired = {
            let mut st = self.st.lock().unwrap();
            match st.sessions.get_mut(&key) {
                None => return Err(ApiError::Unauthorized),
                Some(s) => {
                    if !self.proof_ok(s, bearer.token, bearer.proof.as_ref(), expect, now) {
                        // Refuse the request but keep the session: the proof, not the
                        // token, is what an attacker without the device key lacks.
                        debug!(session = %s.id, "device proof missing or invalid");
                        return Err(ApiError::Unauthorized);
                    }
                    match self.session_expired(s, now) {
                        None => {
                            s.last_used_unix = now;
                            // Keep the idle clock on disk coarse-grained (§14.3).
                            let record = if s.device.is_some() && now.saturating_sub(s.persisted_last_used) >= 300 {
                                s.persisted_last_used = now;
                                s.record(&key)
                            } else {
                                None
                            };
                            let out = (key, s.username.clone(), s.ccache.clone());
                            drop(st);
                            if let Some(rec) = record {
                                if let Err(e) = self.d.sessions.save(&rec) {
                                    error!("session record: {e:#}");
                                }
                            }
                            return Ok(out);
                        }
                        Some(r) => r,
                    }
                }
            }
        };
        self.end_session(key, expired).await;
        Err(ApiError::Unauthorized)
    }

    pub async fn logout<'a>(&self, bearer: impl Into<Bearer<'a>>) -> Result<(), ApiError> {
        let (key, _, _) = self.session(bearer, ("POST", "/v1/logout")).await?;
        self.end_session(key, "logout").await;
        Ok(())
    }

    /// Add a Secure Enclave public key after this session's fresh OTP login.
    /// The bearer and device proof authorize the request; IPA performs the
    /// actual write with the user's own Kerberos ticket. The broker's
    /// service principal never gains directory write rights.
    pub async fn setup_passkey<'a>(&self, bearer: impl Into<Bearer<'a>>, mapping: &str) -> Result<(), ApiError> {
        let mapping = valid_passkey_mapping(mapping).ok_or(ApiError::BadRequest)?;
        let (key, user, ccache) = self.session(bearer, ("POST", "/v1/passkeys/setup")).await?;
        let mapping_hash = sha256(mapping.as_bytes());
        {
            let mut st = self.st.lock().unwrap();
            let session = st.sessions.get_mut(&key).ok_or(ApiError::Unauthorized)?;
            if session.completed_passkey_setup == Some(mapping_hash) {
                return Ok(());
            }
            let setup = session.passkey_setup.as_mut().ok_or(ApiError::Denied)?;
            if self.now().duration_since(setup.created) >= PASSKEY_SETUP_TTL
                || setup.attempts >= PASSKEY_SETUP_ATTEMPTS
                || setup.in_flight
            {
                return Err(ApiError::Denied);
            }
            setup.attempts += 1;
            setup.in_flight = true;
        }
        let result = self.d.dir.add_passkey_with_ticket(&user, &ccache, &mapping).await;
        let mut st = self.st.lock().unwrap();
        if let Some(session) = st.sessions.get_mut(&key) {
            if result.is_ok() {
                session.passkey_setup = None;
                session.completed_passkey_setup = Some(mapping_hash);
            } else if let Some(setup) = session.passkey_setup.as_mut() {
                setup.in_flight = false;
                if setup.attempts >= PASSKEY_SETUP_ATTEMPTS {
                    session.passkey_setup = None;
                }
            }
        }
        drop(st);
        match result {
            Ok(()) => {
                self.audit("passkey_setup_added", json!({"user": user}));
                Ok(())
            }
            Err(DirError::Rejected(reason)) => {
                info!(user = %user, "passkey setup refused: {reason}");
                Err(ApiError::Denied)
            }
            Err(error) => {
                error!(user = %user, "passkey setup directory error: {error}");
                Err(ApiError::Internal("directory"))
            }
        }
    }

    /// Declining the optional offer discards the password immediately.
    pub async fn skip_passkey_setup<'a>(&self, bearer: impl Into<Bearer<'a>>) -> Result<(), ApiError> {
        let (key, _, _) = self.session(bearer, ("POST", "/v1/passkeys/setup/skip")).await?;
        if let Some(session) = self.st.lock().unwrap().sessions.get_mut(&key) {
            session.passkey_setup = None;
        }
        Ok(())
    }

    /// Destroy the TGT, close every lease and kill the session's flows.
    async fn end_session(&self, key: [u8; 32], reason: &str) {
        let (sess, leases) = {
            let mut st = self.st.lock().unwrap();
            let Some(sess) = st.sessions.remove(&key) else { return };
            if sess.device.is_some() {
                self.d.sessions.remove(&hex::encode(key));
            }
            let ports: Vec<u16> = st.leases.iter().filter(|(_, l)| l.session == key).map(|(p, _)| *p).collect();
            let leases: Vec<(u16, Lease)> =
                ports.into_iter().filter_map(|p| st.leases.remove(&p).map(|l| (p, l))).collect();
            st.direct.retain(|g| g.session != key);
            st.presence.retain(|(session, _), _| *session != key);
            (sess, leases)
        };
        let krb = self.d.krb.clone();
        let cc = sess.ccache.clone();
        let _ = tokio::task::spawn_blocking(move || krb.destroy(&cc)).await;
        for (port, l) in &leases {
            self.audit(
                "lease_end",
                json!({"user": sess.username, "ip": l.client.to_string(), "host": l.host, "port": port, "reason": reason}),
            );
        }
        let mut pairs = sess.ports_used.clone();
        pairs.sort();
        pairs.dedup();
        for (client, port) in pairs {
            // Never touch a port that another session now holds for the same client address.
            let reused = self.st.lock().unwrap().leases.get(&port).is_some_and(|l| l.client == client);
            if reused {
                continue;
            }
            if let Err(e) = self.d.relay.call(RelayRequest::Close { client, port, flush: true }).await {
                error!("relay close {client}:{port}: {e}");
            }
        }
        self.audit("session_end", json!({"user": sess.username, "session": sess.id, "reason": reason}));
    }

    // ------------------------------------------------------------ directory

    async fn view(&self, force: bool) -> Result<Arc<DirectoryView>, ApiError> {
        let ttl = Duration::from_secs(self.cfg.ldap.cache_ttl_secs);
        let mut cache = self.view.lock().await;
        let now = self.now();
        if let Some((t, v)) = cache.as_ref() {
            if !force && now.duration_since(*t) < ttl {
                return Ok(v.clone());
            }
        }
        match self.d.dir.view().await {
            Ok(v) => {
                let v = Arc::new(v);
                *cache = Some((now, v.clone()));
                Ok(v)
            }
            Err(e) => {
                error!("directory: {e}");
                // Never extend cached authorization through a directory outage.
                Err(ApiError::Internal("directory unavailable"))
            }
        }
    }

    async fn user(&self, uid: &str, force: bool) -> Result<Option<UserView>, ApiError> {
        let ttl = Duration::from_secs(self.cfg.ldap.cache_ttl_secs);
        let now = self.now();
        if let Some((t, u)) = self.users.lock().unwrap().get(uid) {
            if !force && now.duration_since(*t) < ttl {
                return Ok(u.clone());
            }
        }
        match self.d.dir.user(uid).await {
            Ok(u) => {
                let mut m = self.users.lock().unwrap();
                m.retain(|_, (t, _)| now.duration_since(*t) < ttl);
                m.insert(uid.to_string(), (now, u.clone()));
                Ok(u)
            }
            Err(e) => {
                if let DirError::InsufficientAccess(_) = e {
                    error!("directory: {e} (user entry)");
                } else {
                    error!("directory: {e}");
                }
                Err(ApiError::Internal("directory unavailable"))
            }
        }
    }

    /// (view, fqdns assigned to `user`).
    async fn assigned(&self, username: &str, force: bool) -> Result<(Arc<DirectoryView>, Vec<String>), ApiError> {
        let view = self.view(force).await?;
        let hosts = match self.user(username, force).await? {
            Some(u) if !u.disabled => assigned_hosts(&view, &u),
            Some(_) => Vec::new(),
            None => Vec::new(),
        };
        Ok((view, hosts))
    }

    // ------------------------------------------------------------ probes

    async fn probe_one(&self, fqdn: &str, ip: Ipv4Addr) -> HostStatus {
        let now = self.now();
        let r = self.d.prober.probe(fqdn, ip, self.cfg.hosts.port).await;
        let prev_mismatch = self.status.read().unwrap().get(fqdn).map(|s| s.pin_mismatch).unwrap_or(false);
        let st = match r {
            Err(e) => {
                debug!(host = %fqdn, "probe: {e}");
                HostStatus { online: false, busy: None, cert_sha256: None, pin_mismatch: prev_mismatch, checked: now }
            }
            Ok(h) => {
                let hexh = hex::encode(h);
                let static_pin = self.cfg.hosts.static_pins.get(fqdn);
                let checked = match static_pin {
                    // Administrator-supplied pin: compared directly, never TOFU-stored.
                    Some(pin) if *pin == hexh => Ok(PinCheck::Match),
                    Some(_) => Ok(PinCheck::Mismatch),
                    None => self.d.pins.check(fqdn, &hexh),
                };
                let mismatch = match checked {
                    Ok(PinCheck::Pinned) => {
                        self.audit("pin_new", json!({"host": fqdn, "sha256": hexh}));
                        false
                    }
                    Ok(PinCheck::Match) => false,
                    Ok(PinCheck::Mismatch) => {
                        if !prev_mismatch {
                            self.audit(
                                "pin_mismatch",
                                json!({"host": fqdn, "presented": hexh, "pinned": static_pin.cloned().or_else(|| self.d.pins.get(fqdn))}),
                            );
                        }
                        true
                    }
                    Err(e) => {
                        error!("pin store: {e:#}");
                        true
                    }
                };
                let busy = if mismatch { None } else { self.d.prober.busy(fqdn, ip, self.cfg.hosts.port, h).await };
                HostStatus { online: true, busy, cert_sha256: Some(h), pin_mismatch: mismatch, checked: now }
            }
        };
        self.status.write().unwrap().insert(fqdn.to_string(), st.clone());
        st
    }

    /// Probe every remote host (periodic task).
    pub async fn probe_all(self: &Arc<Self>) {
        let view = match self.view(false).await {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut set = tokio::task::JoinSet::new();
        for h in view.remote_hosts.iter() {
            if let Some(ip) = h.ipv4 {
                let me = self.clone();
                let fqdn = h.fqdn.clone();
                set.spawn(async move {
                    me.probe_one(&fqdn, ip).await;
                });
            }
        }
        while set.join_next().await.is_some() {}
    }

    fn entry(&self, fqdn: &str, ipv4: Option<Ipv4Addr>, st: Option<&HostStatus>) -> HostEntry {
        let name = fqdn.split('.').next().unwrap_or(fqdn).to_string();
        let online = st.map(|s| s.online).unwrap_or(false);
        let reason = if ipv4.is_none() {
            Some("no address")
        } else if st.is_some_and(|s| s.pin_mismatch) {
            Some("certificate changed")
        } else if !online {
            Some("offline")
        } else {
            None
        };
        HostEntry {
            id: fqdn.to_string(),
            name,
            online,
            busy: st.and_then(|s| s.busy),
            in_use_by: None,
            connected_users: if reason.is_none() { self.connected_users(fqdn) } else { Vec::new() },
            connectable: reason.is_none(),
            shared_desktop: self.cfg.mac_admission.as_ref()
                .filter(|cfg| cfg.hosts.contains_key(fqdn)).map(|_| true),
            reason: reason.map(str::to_string),
            image_sha256: self.thumbs.as_ref().and_then(|t| t.image(fqdn)).map(|i| i.sha256.clone()),
        }
    }

    fn status_fresh(&self, fqdn: &str) -> Option<HostStatus> {
        let max_age = Duration::from_secs(self.cfg.hosts.probe_interval_secs * 2 + self.cfg.hosts.probe_timeout_secs);
        let now = self.now();
        self.status.read().unwrap().get(fqdn).filter(|s| now.duration_since(s.checked) < max_age).cloned()
    }

    fn connected_users(&self, host: &str) -> Vec<String> {
        let now = self.now();
        let st = self.st.lock().unwrap();
        st.presence
            .iter()
            .filter(|(_, p)| p.host == host && p.connected && p.expires > now)
            .filter_map(|((key, _), _)| st.sessions.get(key).map(|s| s.username.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Names come only from authenticated sessions. The client supplies a random
    /// per-stream ID and monotonic sequence, never a username. Keep stopped
    /// records briefly so a delayed heartbeat cannot resurrect a disconnected stream.
    pub async fn presence<'a>(
        &self,
        ip: IpAddr,
        bearer: impl Into<Bearer<'a>>,
        host: &str,
        connection_id: &str,
        sequence: u64,
        connected: bool,
    ) -> Result<(), ApiError> {
        let path = format!("/v1/hosts/{host}/presence");
        let (key, user, _) = self.session(bearer, ("POST", &path)).await?;
        if connection_id.len() != 32 || !connection_id.bytes().all(|c| c.is_ascii_hexdigit()) || sequence == 0 {
            return Err(ApiError::BadRequest);
        }
        let (_, hosts) = self.assigned(&user, false).await?;
        if !hosts.iter().any(|h| h == host) {
            return Err(ApiError::Denied);
        }
        let client = v4(ip).ok_or(ApiError::NoLease)?;
        let now = self.now();
        let mut st = self.st.lock().unwrap();
        if !st.sessions.contains_key(&key) {
            return Err(ApiError::Unauthorized);
        }
        if connected
            && !st.direct.iter().any(|g| g.session == key && g.host == host && g.client == client && g.expires > now)
            && !st.leases.values().any(|l| l.session == key && l.host == host && l.client == client && l.expires > now)
        {
            return Err(ApiError::NoLease);
        }
        st.presence.retain(|_, p| p.expires > now);
        let id = (key, connection_id.to_string());
        if let Some(previous) = st.presence.get(&id) {
            if previous.host != host {
                return Err(ApiError::Denied);
            }
            if sequence <= previous.sequence || !previous.connected {
                return Ok(());
            }
        } else if st.presence.keys().filter(|(session, _)| *session == key).count() >= MAX_PRESENCES_PER_SESSION {
            return Err(ApiError::Exhausted);
        }
        st.presence.insert(id, Presence { host: host.to_string(), sequence, connected, expires: now + PRESENCE_TTL });
        Ok(())
    }

    // ------------------------------------------------------------ hosts / connect

    pub async fn list_hosts<'a>(&self, ip: IpAddr, bearer: impl Into<Bearer<'a>>) -> Result<HostsReply, ApiError> {
        let (key, user, _) = self.session(bearer, ("GET", "/v1/hosts")).await?;
        let (view, fqdns) = self.assigned(&user, false).await?;
        let mut hosts = Vec::new();
        for fqdn in &fqdns {
            let ipv4 = view.remote_hosts.iter().find(|h| &h.fqdn == fqdn).and_then(|h| h.ipv4);
            let st = match (self.status_fresh(fqdn), ipv4) {
                (Some(s), _) => Some(s),
                (None, Some(a)) => Some(self.probe_one(fqdn, a).await),
                (None, None) => None,
            };
            hosts.push(self.entry(fqdn, ipv4, st.as_ref()));
        }
        // Listing is a keepalive for every lease of this session from this address.
        if let Some(c) = v4(ip) {
            self.refresh_direct(key, c, None);
            self.refresh_leases(key, c, None).await;
        }
        Ok(HostsReply { hosts })
    }

    /// The caller's own host image. 404 unless the host is in the caller's
    /// assigned list and has a valid image (same visibility rule as `list_hosts`).
    pub async fn host_image<'a>(&self, bearer: impl Into<Bearer<'a>>, host: &str) -> Result<ImageReply, ApiError> {
        let path = format!("/v1/hosts/{host}/image");
        let (_, user, _) = self.session(bearer, ("GET", &path)).await?;
        let (_, hosts) = self.assigned(&user, false).await?;
        if !hosts.iter().any(|h| h == host) {
            return Err(ApiError::NotFound);
        }
        let img = self.thumbs.as_ref().and_then(|t| t.image(host)).ok_or(ApiError::NotFound)?;
        Ok(ImageReply { kind: "image/png", sha256: img.sha256.clone(), data: STANDARD.encode(&img.bytes) })
    }

    async fn refresh_leases(&self, key: [u8; 32], client: Ipv4Addr, host: Option<&str>) -> usize {
        let now = self.now();
        let ttl = self.cfg.relay.lease_keepalive_secs;
        let mine: Vec<(u16, Lease)> = self
            .st
            .lock()
            .unwrap()
            .leases
            .iter()
            .filter(|(_, l)| {
                l.session == key && l.client == client && l.expires > now && host.is_none_or(|h| h == l.host)
            })
            .map(|(p, l)| (*p, l.clone()))
            .collect();
        let mut n = 0;
        for (port, l) in mine {
            let req = RelayRequest::Refresh { client, port, target: l.target, ttl_secs: ttl };
            match self.d.relay.call(req).await {
                Ok(()) => {
                    if let Some(x) = self.st.lock().unwrap().leases.get_mut(&port) {
                        x.expires = now + Duration::from_secs(ttl);
                    }
                    n += 1;
                }
                Err(e) => {
                    warn!("relay refresh {client}:{port}: {e}");
                    self.st.lock().unwrap().leases.remove(&port);
                }
            }
        }
        n
    }

    /// Extend this session's direct grants from `client` (to `host`, or all). Returns how many.
    fn refresh_direct(&self, key: [u8; 32], client: Ipv4Addr, host: Option<&str>) -> usize {
        let now = self.now();
        let until = now + Duration::from_secs(self.cfg.relay.lease_keepalive_secs);
        let mut st = self.st.lock().unwrap();
        let mut n = 0;
        for g in st.direct.iter_mut() {
            if g.session == key && g.client == client && g.expires > now && host.is_none_or(|h| h == g.host) {
                g.expires = until;
                n += 1;
            }
        }
        n
    }

    fn is_direct_client(&self, client: Ipv4Addr) -> bool {
        self.direct_nets.iter().any(|n| n.contains(&client))
    }

    pub async fn keepalive<'a>(
        &self,
        ip: IpAddr,
        bearer: impl Into<Bearer<'a>>,
        host: &str,
    ) -> Result<KeepaliveReply, ApiError> {
        let path = format!("/v1/hosts/{host}/keepalive");
        let (key, user, _) = self.session(bearer, ("POST", &path)).await?;
        let (_, hosts) = self.assigned(&user, false).await?;
        if !hosts.iter().any(|assigned| assigned == host) {
            self.end_session(key, "access_revoked").await;
            return Err(ApiError::Unauthorized);
        }
        let client = v4(ip).ok_or(ApiError::NoLease)?;
        let direct = self.refresh_direct(key, client, Some(host));
        if direct == 0 && self.refresh_leases(key, client, Some(host)).await == 0 {
            return Err(ApiError::NoLease);
        }
        Ok(KeepaliveReply { state: "ok", expires_in: self.cfg.relay.lease_keepalive_secs })
    }

    fn allocate_port(&self, st: &mut State, now: Instant) -> Option<u16> {
        let (min, max) = (self.cfg.relay.port_min, self.cfg.relay.port_max);
        let n = (max - min) as u32 + 1;
        for i in 0..n {
            let p = min + ((st.next_port.saturating_sub(min) as u32 + i) % n) as u16;
            let free = match st.leases.get(&p) {
                None => true,
                Some(l) => l.expires <= now,
            };
            if free {
                st.leases.remove(&p);
                st.next_port = if p == max { min } else { p + 1 };
                return Some(p);
            }
        }
        None
    }

    /// Clients inside `routing.direct_client_cidrs` get the host's own address and
    /// port (route `direct`, no lease); everyone else gets a relay lease.
    pub async fn connect<'a>(
        &self,
        ip: IpAddr,
        bearer: impl Into<Bearer<'a>>,
        host: &str,
        endpoint: &str,
    ) -> Result<ConnectReply, ApiError> {
        let path = format!("/v1/hosts/{host}/connect");
        let (key, user, ccache) = self.session(bearer, ("POST", &path)).await?;
        let Some(client) = v4(ip) else { return Err(ApiError::Unavailable("IPv6 clients are not supported")) };
        let (view, fqdns) = self.assigned(&user, false).await?;
        if !fqdns.iter().any(|f| f == host) {
            self.audit(
                "connect_denied",
                json!({"user": user, "ip": ip.to_string(), "host": host, "reason": "not_assigned"}),
            );
            return Err(ApiError::Denied);
        }
        let Some(target) = view.remote_hosts.iter().find(|h| h.fqdn == host).and_then(|h| h.ipv4) else {
            return Err(ApiError::Unavailable("no address"));
        };
        // The periodic status cache is suitable for listing workstations, but
        // a desktop handoff briefly takes the host listener offline. Recheck a
        // cached offline result on an explicit connection request so a newly
        // started desktop worker is not rejected for the cache's full lifetime.
        // Preserve a recorded pin mismatch until the administrator resets it.
        let st = match self.status_fresh(host) {
            Some(s) if s.online || s.pin_mismatch => s,
            _ => self.probe_one(host, target).await,
        };
        if st.pin_mismatch {
            return Err(ApiError::Unavailable("certificate changed"));
        }
        let Some(cert) = st.cert_sha256.filter(|_| st.online) else {
            return Err(ApiError::Unavailable("offline"));
        };

        // Configuration, never discovery metadata, selects this trust boundary.
        // The same authenticated session, HBAC assignment and pinned Host gates
        // above apply to both methods. Shared Mac users never receive an OS password.
        let mac = self.cfg.mac_admission.as_ref()
            .and_then(|cfg| cfg.hosts.get(host).map(|local| (cfg.clone(), local.clone())));
        let host_login = mac.is_none() && self.cfg.hosts.admission_for(host) == crate::config::Admission::None;
        let (gssapi_token, broker_token, local_username) = if let Some((cfg, local)) = mac {
            let issued = self.d.clock.unix();
            let host = host.to_string();
            let subject = user.clone();
            let local_for_signing = local.clone();
            let token = tokio::task::spawn_blocking(move || {
                cfg.issue(&host, &cert, &subject, &local_for_signing, issued)
            })
            .await
            .map_err(|_| ApiError::Internal("Mac admission unavailable"))?
            .map_err(|_| ApiError::Internal("Mac admission unavailable"))?;
            (String::new(), Some(token), Some(local))
        } else if host_login {
            // Admission `none`: the Host authenticates the client itself (its own
            // sign-in); no ticket is requested and none is returned.
            (String::new(), None, None)
        } else {
            let krb = self.d.krb.clone();
            let fq = host.to_string();
            let tok = tokio::task::spawn_blocking(move || krb.ap_req(&ccache, &fq, &cert))
                .await
                .unwrap_or_else(|_| Err(KrbError::Unavailable("ap_req task panicked".into())));
            let tok = match tok {
                Ok(t) => t,
                Err(KrbError::Denied(m)) => {
                    info!(user = %user, host = %host, "service ticket refused: {m}");
                    self.audit(
                        "connect_denied",
                        json!({"user": user, "ip": ip.to_string(), "host": host, "reason": "kdc"}),
                    );
                    return Err(ApiError::Denied);
                }
                Err(KrbError::Unavailable(m)) => {
                    error!("KDC unavailable: {m}");
                    return Err(ApiError::Internal("kdc unavailable"));
                }
            };
            (STANDARD.encode(tok), None, None)
        };
        let auth_method = if broker_token.is_some() {
            Some("broker_capability")
        } else if host_login {
            Some("host_login")
        } else {
            None
        };

        let now = self.now();
        let initial = self.cfg.relay.lease_initial_secs;

        if self.is_direct_client(client) {
            let still_logged_in = {
                let mut st = self.st.lock().unwrap();
                if let Some(session) = st.sessions.get_mut(&key) {
                    if !session.hosts_used.iter().any(|used| used == host) {
                        session.hosts_used.push(host.to_string());
                    }
                    st.direct.retain(|g| !(g.session == key && g.host == host && g.client == client));
                    st.direct.push(DirectGrant {
                        session: key,
                        host: host.to_string(),
                        client,
                        expires: now + Duration::from_secs(initial),
                    });
                    true
                } else {
                    false
                }
            };
            if !still_logged_in {
                return Err(ApiError::Unauthorized);
            }
            self.audit(
                "connect",
                json!({"user": user, "ip": ip.to_string(), "host": host, "route": "direct", "target": target.to_string()}),
            );
            return Ok(ConnectReply {
                route: "direct",
                endpoint: target.to_string(),
                port: self.cfg.hosts.port,
                host_cert_sha256: hex::encode(cert),
                username: user,
                gssapi_token,
                auth_method,
                broker_token,
                local_username,
                expires_in: initial,
            });
        }

        // Reuse this session's lease to the same host from the same address.
        let port = {
            let mut st = self.st.lock().unwrap();
            let existing = st
                .leases
                .iter()
                .find(|(_, l)| l.session == key && l.host == host && l.client == client && l.expires > now)
                .map(|(p, _)| *p);
            let port = existing.or_else(|| self.allocate_port(&mut st, now));
            if let Some(port) = port {
                st.leases.insert(
                    port,
                    Lease {
                        session: key,
                        host: host.to_string(),
                        client,
                        target,
                        expires: now + Duration::from_secs(initial),
                    },
                );
            }
            port
        };
        let Some(port) = port else {
            self.audit(
                "connect_denied",
                json!({"user": user, "ip": ip.to_string(), "host": host, "reason": "ports_exhausted"}),
            );
            return Err(ApiError::Exhausted);
        };
        if let Err(e) = self.d.relay.call(RelayRequest::Open { client, port, target, ttl_secs: initial }).await {
            error!("relay open {client}:{port}: {e}");
            self.st.lock().unwrap().leases.remove(&port);
            return Err(ApiError::Internal("relay unavailable"));
        }
        let still_logged_in = {
            let mut st = self.st.lock().unwrap();
            match st.sessions.get_mut(&key) {
                Some(s) => {
                    s.ports_used.push((client, port));
                    if !s.hosts_used.iter().any(|used| used == host) {
                        s.hosts_used.push(host.to_string());
                    }
                    true
                }
                None => {
                    st.leases.remove(&port);
                    false
                }
            }
        };
        if !still_logged_in {
            // Logged out concurrently: undo.
            let _ = self.d.relay.call(RelayRequest::Close { client, port, flush: true }).await;
            return Err(ApiError::Unauthorized);
        }
        self.audit(
            "connect",
            json!({"user": user, "ip": ip.to_string(), "host": host, "route": "relay", "port": port, "target": target.to_string()}),
        );
        Ok(ConnectReply {
            route: "relay",
            endpoint: endpoint.to_string(),
            port,
            host_cert_sha256: hex::encode(cert),
            username: user,
            gssapi_token,
            auth_method,
            broker_token,
            local_username,
            expires_in: initial,
        })
    }

    // ------------------------------------------------------------ housekeeping

    /// Expire conversations, sessions and lapsed leases.
    pub async fn reap(&self) {
        let now = self.now();
        let unix = self.d.clock.unix();
        let conv_ttl = Duration::from_secs(self.cfg.limits.conversation_ttl_secs);
        let (expired, lapsed, renew) = {
            let mut st = self.st.lock().unwrap();
            st.conversations.retain(|_, c| now.duration_since(c.created) < conv_ttl);
            for session in st.sessions.values_mut() {
                if session.passkey_setup.as_ref().is_some_and(|p| now.duration_since(p.created) >= PASSKEY_SETUP_TTL) {
                    session.passkey_setup = None;
                }
            }
            let expired: Vec<([u8; 32], &'static str)> =
                st.sessions.iter().filter_map(|(k, s)| self.session_expired(s, unix).map(|r| (*k, r))).collect();
            let renew: Vec<([u8; 32], String)> = st
                .sessions
                .iter()
                .filter(|(k, s)| {
                    s.device.is_some()
                        && s.ticket_end_unix.saturating_sub(unix) < self.cfg.limits.renew_before_secs
                        && s.ticket_end_unix < s.ends_unix
                        && !expired.iter().any(|(e, _)| e == *k)
                })
                .map(|(k, s)| (*k, s.ccache.clone()))
                .collect();
            // Direct grants hold nothing open: they simply stop keeping the session alive.
            st.direct.retain(|g| g.expires > now);
            st.presence.retain(|_, p| p.expires > now);
            let ports: Vec<u16> = st.leases.iter().filter(|(_, l)| l.expires <= now).map(|(p, _)| *p).collect();
            let lapsed: Vec<(u16, Lease, String)> = ports
                .into_iter()
                .filter_map(|p| {
                    let l = st.leases.remove(&p)?;
                    let u = st.sessions.get(&l.session).map(|s| s.username.clone()).unwrap_or_default();
                    Some((p, l, u))
                })
                .collect();
            (expired, lapsed, renew)
        };
        for (port, l, user) in lapsed {
            // Keepalive stopped: no new flows; established flows keep running via conntrack
            // until the session itself ends.
            let _ = self.d.relay.call(RelayRequest::Close { client: l.client, port, flush: false }).await;
            self.audit(
                "lease_end",
                json!({"user": user, "ip": l.client.to_string(), "host": l.host, "port": port, "reason": "keepalive_timeout"}),
            );
        }
        for (k, reason) in expired {
            self.end_session(k, reason).await;
        }
        // Check every remembered login, including closed clients, against current
        // account/HBAC policy. The directory cache bounds revocation latency;
        // this check never bumps the user's idle timer.
        let sessions: Vec<_> = self
            .st
            .lock()
            .unwrap()
            .sessions
            .iter()
            .map(|(key, session)| (*key, session.username.clone()))
            .collect();
        for (key, user) in sessions {
            if let Ok(Some(u)) = self.user(&user, false).await {
                if self.password_changed_since_login(&key, Some(&u)) {
                    self.end_session(key, "password_changed").await;
                    continue;
                }
            }
            let Ok((_, assigned)) = self.assigned(&user, false).await else { continue };
            let revoked = {
                let st = self.st.lock().unwrap();
                assigned.is_empty()
                    || st.sessions.get(&key).is_some_and(|session| {
                        session.hosts_used.iter().any(|host| !assigned.contains(host))
                    })
            };
            if revoked {
                // A new grant can be newer than the shared snapshot (especially
                // just after enrolment). Confirm a negative decision with fresh
                // account and rule reads before destroying a remembered login.
                let Ok((_, fresh)) = self.assigned(&user, true).await else { continue };
                let confirmed = {
                    let st = self.st.lock().unwrap();
                    fresh.is_empty()
                        || st.sessions.get(&key).is_some_and(|session| {
                            session.hosts_used.iter().any(|host| !fresh.contains(host))
                        })
                };
                if confirmed {
                    self.end_session(key, "access_revoked").await;
                }
            }
        }
        for (k, ccache) in renew {
            let active = self.st.lock().unwrap().sessions.contains_key(&k);
            if active {
                self.renew_session(k, ccache).await;
            }
        }
        self.reap_enrol(now);
        self.limiter.lock().unwrap().gc(now);
    }

    /// Renew a bound session's TGT (§14.3). A refusal ends the session; an
    /// unreachable KDC is retried on the next reap until the ticket runs out.
    async fn renew_session(&self, key: [u8; 32], ccache: String) {
        let krb = self.d.krb.clone();
        let res = tokio::task::spawn_blocking(move || krb.renew(&ccache))
            .await
            .unwrap_or_else(|_| Err(KrbError::Unavailable("renew task panicked".into())));
        match res {
            Ok(t) => {
                let record = {
                    let mut st = self.st.lock().unwrap();
                    let Some(s) = st.sessions.get_mut(&key) else { return };
                    s.ticket_end_unix = t.end_unix;
                    if t.renew_till_unix != 0 {
                        s.renew_till_unix = t.renew_till_unix;
                        s.ends_unix = s.ends_unix.min(t.renew_till_unix.max(t.end_unix));
                    }
                    info!(session = %s.id, user = %s.username, "TGT renewed until {}", t.end_unix);
                    s.record(&key)
                };
                if let Some(rec) = record {
                    if let Err(e) = self.d.sessions.save(&rec) {
                        error!("session record: {e:#}");
                    }
                }
            }
            Err(KrbError::Denied(m)) => {
                let user = self.st.lock().unwrap().sessions.get(&key).map(|s| s.username.clone());
                info!(user = ?user, "TGT renewal refused: {m}");
                self.end_session(key, "renewal_refused").await;
            }
            Err(KrbError::Unavailable(m)) => warn!("TGT renewal postponed (KDC unavailable): {m}"),
        }
    }

    /// Load device-bound sessions persisted by a previous run (§14.3). Call once
    /// at start, after the relay reset.
    pub fn restore_sessions(&self) -> usize {
        let unix = self.d.clock.unix();
        let mut restored = 0;
        let mut live = Vec::new();
        for rec in self.d.sessions.load_all() {
            let (Some(key), Some(device)) = (rec.key_bytes(), rec.device()) else { continue };
            let session = Session {
                id: rec.id.clone(),
                username: rec.username.clone(),
                ccache: rec.ccache.clone(),
                created_unix: rec.created_unix,
                last_used_unix: rec.last_used_unix,
                ends_unix: rec.ends_unix,
                device: Some(device),
                ticket_end_unix: rec.ticket_end_unix,
                renew_till_unix: rec.renew_till_unix,
                proofs: HashMap::new(),
                persisted_last_used: rec.last_used_unix,
                ports_used: Vec::new(),
                hosts_used: Vec::new(),
                passkey_setup: None,
                completed_passkey_setup: None,
            };
            if self.session_expired(&session, unix).is_some() {
                self.d.krb.destroy(&session.ccache);
                self.d.sessions.remove(&rec.key);
                continue;
            }
            live.push(session.ccache.clone());
            self.st.lock().unwrap().sessions.insert(key, session);
            restored += 1;
        }
        self.d.sessions.sweep_ccaches(&live);
        if restored > 0 {
            self.audit("sessions_restored", json!({"count": restored}));
        }
        restored
    }

    pub fn audit_start(&self) {
        self.audit(
            "service_start",
            json!({"version": env!("CARGO_PKG_VERSION"), "ports": format!("{}-{}", self.cfg.relay.port_min, self.cfg.relay.port_max)}),
        );
    }

    /// Clear relay state left over from a previous run (leases never survive a restart).
    pub async fn reset_relay(&self) -> Result<(), String> {
        self.d.relay.call(RelayRequest::Reset).await
    }

    /// End every unbound session (shutdown). Device-bound sessions stay on disk
    /// with their ccache and are restored by the next start (§14.3).
    pub async fn shutdown(&self) {
        let keys: Vec<[u8; 32]> =
            self.st.lock().unwrap().sessions.iter().filter(|(_, s)| s.device.is_none()).map(|(k, _)| *k).collect();
        for k in keys {
            self.end_session(k, "shutdown").await;
        }
        let bound: Vec<SessionRecord> =
            self.st.lock().unwrap().sessions.iter().filter_map(|(k, s)| s.record(k)).collect();
        for rec in bound {
            if let Err(e) = self.d.sessions.save(&rec) {
                error!("session record: {e:#}");
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn lease_count(&self) -> usize {
        self.st.lock().unwrap().leases.len()
    }

    #[cfg(test)]
    pub(crate) fn passkey_worker_count(&self) -> usize {
        self.passkey_workers.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn direct_count(&self) -> usize {
        self.st.lock().unwrap().direct.len()
    }
}

/// A reserved passkey start; releases the reservation if the start is abandoned
/// (e.g. the client disconnects while the KDC is asked).
struct StartSlot<'a>(&'a Mutex<State>);
impl Drop for StartSlot<'_> {
    fn drop(&mut self) {
        self.0.lock().unwrap().passkey_starting -= 1;
    }
}
