//! HTTP layer: contracts v1 §10.1 over TLS 1.3 / HTTP/1.1.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::broker::{ApiError, Bearer, Broker, Method};
use crate::device::{DeviceKey, DeviceProof};
use crate::passkey::Assertion;
use crate::util::sha256;
use crate::util::valid_hostname;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, body) = match self {
            ApiError::Denied => (StatusCode::FORBIDDEN, json!({"state": "denied"})),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, json!({"state": "denied"})),
            ApiError::RateLimited(s) => (StatusCode::TOO_MANY_REQUESTS, json!({"state": "denied", "retry_after": s})),
            ApiError::Unavailable(r) => (StatusCode::CONFLICT, json!({"state": "unavailable", "reason": r})),
            ApiError::NoLease => (StatusCode::NOT_FOUND, json!({"state": "no_lease"})),
            ApiError::NotFound => (StatusCode::NOT_FOUND, json!({"state": "not_found"})),
            ApiError::Exhausted => {
                (StatusCode::SERVICE_UNAVAILABLE, json!({"state": "unavailable", "reason": "no free session port"}))
            }
            ApiError::BadRequest => (StatusCode::BAD_REQUEST, json!({"state": "denied"})),
            ApiError::Internal(r) => (StatusCode::SERVICE_UNAVAILABLE, json!({"state": "unavailable", "reason": r})),
        };
        let mut resp = (code, Json(body)).into_response();
        if let ApiError::RateLimited(s) = self {
            if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

/// Auth endpoints answer denial with HTTP 200 `{"state":"denied"}` (contract).
fn auth_error(e: ApiError) -> Response {
    match e {
        ApiError::Denied | ApiError::BadRequest | ApiError::Unauthorized => {
            (StatusCode::OK, Json(json!({"state": "denied"}))).into_response()
        }
        other => other.into_response(),
    }
}

fn bearer(h: &HeaderMap) -> Result<&str, ApiError> {
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= 128)
        .ok_or(ApiError::Unauthorized)
}

/// Bearer plus the optional device proof (§14.2) of this request. Malformed
/// proof headers count as absent: a bound session then refuses the request.
pub(crate) fn device_bearer<'a>(
    h: &'a HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Bearer<'a>, ApiError> {
    let token = bearer(h)?;
    let header = |name: &str| h.get(name).and_then(|v| v.to_str().ok()).map(str::trim);
    let proof = match (header("x-plank-device-time"), header("x-plank-device-proof")) {
        (Some(t), Some(sig)) if t.len() <= 20 && sig.len() <= 200 => match (t.parse::<u64>(), STANDARD.decode(sig)) {
            (Ok(time), Ok(signature)) => Some(DeviceProof {
                method: method.to_string(),
                path: path.to_string(),
                time,
                signature,
                body_sha256: sha256(body),
            }),
            _ => None,
        },
        _ => None,
    };
    Ok(Bearer { token, proof })
}

/// The host name the client used (Host header without port), else the configured name.
fn endpoint(h: &HeaderMap, fallback: &str) -> String {
    h.get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|v| match v.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
            _ => v,
        })
        .map(|v| v.trim_end_matches('.').to_ascii_lowercase())
        .filter(|v| valid_hostname(v))
        .unwrap_or_else(|| fallback.to_string())
}

fn client_ip(ci: &SocketAddr) -> IpAddr {
    match ci.ip() {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        a => a,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartReq {
    username: String,
    /// Absent or `"password_otp"`: password + OTP; `"passkey"`: passkey (contract §13.3).
    #[serde(default)]
    method: Option<String>,
    /// Base64 P-256 SPKI of the client's device key: binds the session (§14.2).
    #[serde(default)]
    device_key: Option<String>,
}

/// Exactly one of `responses` (password + OTP) and `passkey`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RespondReq {
    conversation_id: String,
    #[serde(default)]
    responses: Option<Vec<String>>,
    #[serde(default)]
    passkey: Option<PasskeyResp>,
}

/// Base64 fields; decoded and size-checked by [`Assertion::from_b64`]. Never logged.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyResp {
    credential_id: String,
    authenticator_data: String,
    signature: String,
}

async fn auth_start(State(b): State<Arc<Broker>>, ConnectInfo(ci): ConnectInfo<SocketAddr>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<StartReq>(&body) else { return auth_error(ApiError::BadRequest) };
    let Some(method) = Method::parse(req.method.as_deref()) else { return auth_error(ApiError::BadRequest) };
    let device = match req.device_key.as_deref() {
        None => None,
        Some(k) if k.len() <= 200 => match STANDARD.decode(k).ok().and_then(|der| DeviceKey::from_spki(&der)) {
            Some(d) => Some(d),
            None => return auth_error(ApiError::BadRequest),
        },
        Some(_) => return auth_error(ApiError::BadRequest),
    };
    match b.auth_start_method(client_ip(&ci), &req.username, method, device).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => auth_error(e),
    }
}

async fn auth_respond(State(b): State<Arc<Broker>>, ConnectInfo(ci): ConnectInfo<SocketAddr>, body: Bytes) -> Response {
    // Parse into a buffer we can wipe; the request body itself is dropped right after.
    let mut raw = Zeroizing::new(body.to_vec());
    drop(body);
    let parsed = serde_json::from_slice::<RespondReq>(&raw);
    zeroize::Zeroize::zeroize(&mut *raw);
    let Ok(req) = parsed else { return auth_error(ApiError::BadRequest) };
    let ip = client_ip(&ci);
    let r = match (req.responses, req.passkey) {
        (Some(responses), None) => {
            let responses: Vec<Zeroizing<String>> = responses.into_iter().map(Zeroizing::new).collect();
            b.auth_respond(ip, &req.conversation_id, responses).await
        }
        (None, Some(p)) => {
            let a = Assertion::from_b64(&p.credential_id, &p.authenticator_data, &p.signature);
            b.auth_respond_passkey(ip, &req.conversation_id, a).await
        }
        _ => Err(ApiError::BadRequest),
    };
    match r {
        Ok(r) => Json(r).into_response(),
        Err(e) => auth_error(e),
    }
}

// ---------------------------------------------------------------- enrolment (§16)

/// Enrolment answers: 200 JSON except 429 (rate limit) and 400 (malformed body).
/// Every other failure is the generic 200 `{"state":"denied"}`.
fn enrol_error(e: ApiError) -> Response {
    match e {
        ApiError::RateLimited(_) => e.into_response(),
        ApiError::BadRequest => (StatusCode::BAD_REQUEST, Json(json!({"state": "denied"}))).into_response(),
        _ => (StatusCode::OK, Json(json!({"state": "denied"}))).into_response(),
    }
}

fn enrol_result<T: serde::Serialize>(r: Result<T, ApiError>) -> Response {
    match r {
        Ok(v) => Json(v).into_response(),
        Err(e) => enrol_error(e),
    }
}

/// Parse a body that may carry secrets from a buffer that is wiped right after.
fn parse_secret<T: serde::de::DeserializeOwned>(body: Bytes) -> Option<T> {
    let mut raw = Zeroizing::new(body.to_vec());
    drop(body);
    let parsed = serde_json::from_slice::<T>(&raw).ok();
    zeroize::Zeroize::zeroize(&mut *raw);
    parsed
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolStartReq {
    username: String,
    #[serde(default)]
    device_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolRespondReq {
    conversation_id: String,
    responses: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolPasswordReq {
    conversation_id: String,
    new_password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolTotpReq {
    conversation_id: String,
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolPasskeyReq {
    conversation_id: String,
    mapping: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolFinishReq {
    conversation_id: String,
}

async fn enroll_start(State(b): State<Arc<Broker>>, ConnectInfo(ci): ConnectInfo<SocketAddr>, body: Bytes) -> Response {
    if !b.cfg.enrol.enabled {
        return not_found().await;
    }
    let Ok(req) = serde_json::from_slice::<EnrolStartReq>(&body) else { return enrol_error(ApiError::BadRequest) };
    let device = match req.device_key.as_deref() {
        None => None,
        Some(k) if k.len() <= 200 => match STANDARD.decode(k).ok().and_then(|der| DeviceKey::from_spki(&der)) {
            Some(d) => Some(d),
            None => return enrol_error(ApiError::BadRequest),
        },
        Some(_) => return enrol_error(ApiError::BadRequest),
    };
    enrol_result(b.enroll_start(client_ip(&ci), &req.username, device).await)
}

async fn enroll_respond(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if !b.cfg.enrol.enabled {
        return not_found().await;
    }
    let Some(req) = parse_secret::<EnrolRespondReq>(body) else { return enrol_error(ApiError::BadRequest) };
    let responses: Vec<Zeroizing<String>> = req.responses.into_iter().map(Zeroizing::new).collect();
    enrol_result(b.enroll_respond(client_ip(&ci), &req.conversation_id, responses).await)
}

async fn enroll_password(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if !b.cfg.enrol.enabled {
        return not_found().await;
    }
    let Some(req) = parse_secret::<EnrolPasswordReq>(body) else { return enrol_error(ApiError::BadRequest) };
    let new = Zeroizing::new(req.new_password);
    enrol_result(b.enroll_password(client_ip(&ci), &req.conversation_id, new).await)
}

async fn enroll_totp(State(b): State<Arc<Broker>>, ConnectInfo(ci): ConnectInfo<SocketAddr>, body: Bytes) -> Response {
    if !b.cfg.enrol.enabled {
        return not_found().await;
    }
    let Some(req) = parse_secret::<EnrolTotpReq>(body) else { return enrol_error(ApiError::BadRequest) };
    let code = Zeroizing::new(req.code);
    enrol_result(b.enroll_totp(client_ip(&ci), &req.conversation_id, &code).await)
}

async fn enroll_passkey(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if !b.cfg.enrol.enabled {
        return not_found().await;
    }
    let Ok(req) = serde_json::from_slice::<EnrolPasskeyReq>(&body) else { return enrol_error(ApiError::BadRequest) };
    enrol_result(b.enroll_passkey(client_ip(&ci), &req.conversation_id, &req.mapping).await)
}

async fn enroll_finish(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if !b.cfg.enrol.enabled {
        return not_found().await;
    }
    let Ok(req) = serde_json::from_slice::<EnrolFinishReq>(&body) else { return enrol_error(ApiError::BadRequest) };
    Json(b.enroll_finish(client_ip(&ci), &req.conversation_id)).into_response()
}

async fn hosts(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let r = async { b.list_hosts(client_ip(&ci), device_bearer(&h, "GET", uri.path(), &body)?).await }.await;
    match r {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn host_image(
    State(b): State<Arc<Broker>>,
    Path(id): Path<String>,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let r = async {
        let t = device_bearer(&h, "GET", uri.path(), &body)?;
        if !valid_hostname(&id) {
            return Err(ApiError::NotFound);
        }
        b.host_image(t, &id).await
    }
    .await;
    match r {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn connect(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let ep = endpoint(&h, &b.cfg.public_endpoint);
    let r = async {
        let t = device_bearer(&h, "POST", uri.path(), &body)?;
        if !valid_hostname(&id) {
            return Err(ApiError::Denied);
        }
        b.connect(client_ip(&ci), t, &id, &ep).await
    }
    .await;
    match r {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn keepalive(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let r = async { b.keepalive(client_ip(&ci), device_bearer(&h, "POST", uri.path(), &body)?, &id).await }.await;
    match r {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceReq {
    connection_id: String,
    sequence: u64,
    connected: bool,
}

async fn presence(
    State(b): State<Arc<Broker>>,
    ConnectInfo(ci): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let r = async {
        let bearer = device_bearer(&h, "POST", uri.path(), &body)?;
        let req: PresenceReq = serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest)?;
        b.presence(client_ip(&ci), bearer, &id, &req.connection_id, req.sequence, req.connected).await
    }
    .await;
    match r {
        Ok(()) => Json(json!({"state": "ok"})).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn logout(State(b): State<Arc<Broker>>, uri: Uri, h: HeaderMap, body: Bytes) -> Response {
    let r = async { b.logout(device_bearer(&h, "POST", uri.path(), &body)?).await }.await;
    match r {
        Ok(()) => Json(json!({"state": "logged_out"})).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeySetupReq {
    mapping: String,
}

async fn passkey_setup(State(b): State<Arc<Broker>>, uri: Uri, h: HeaderMap, body: Bytes) -> Response {
    let result = async {
        let credential = device_bearer(&h, "POST", uri.path(), &body)?;
        let request: PasskeySetupReq = serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest)?;
        b.setup_passkey(credential, &request.mapping).await
    }
    .await;
    match result {
        Ok(()) => Json(json!({"state": "passkey_added"})).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn passkey_setup_skip(State(b): State<Arc<Broker>>, uri: Uri, h: HeaderMap, body: Bytes) -> Response {
    let result = async {
        if !body.is_empty() {
            return Err(ApiError::BadRequest);
        }
        b.skip_passkey_setup(device_bearer(&h, "POST", uri.path(), &body)?).await
    }
    .await;
    match result {
        Ok(()) => Json(json!({"state": "done"})).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"state": "not_found"}))).into_response()
}

async fn no_store(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    r
}

pub fn router(b: Arc<Broker>) -> Router {
    Router::new()
        .route("/v1/client-updates/macos-arm64", get(crate::updates::manifest))
        .route("/v1/diagnostics/support-request", get(crate::support_diagnostics::poll))
        .route("/v1/diagnostics/support", post(crate::support_diagnostics::submit)
            .layer(DefaultBodyLimit::max(crate::support_diagnostics::MAX_BODY)))
        .route("/v1/client-updates/macos-arm64/{filename}", get(crate::updates::download))
        .route("/v1/client-updates/windows-x64", get(crate::updates::windows_manifest))
        .route("/v1/client-updates/windows-x64/{filename}", get(crate::updates::windows_download))
        .route("/v1/auth/start", post(auth_start))
        .route("/v1/auth/respond", post(auth_respond))
        .route(
            "/v1/diagnostics",
            post(crate::diagnostics::submit).layer(DefaultBodyLimit::max(crate::diagnostics::MAX_BODY)),
        )
        .route("/v1/hosts", get(hosts))
        .route("/v1/hosts/{id}/image", get(host_image))
        .route("/v1/hosts/{id}/connect", post(connect))
        .route("/v1/hosts/{id}/keepalive", post(keepalive))
        .route("/v1/hosts/{id}/presence", post(presence))
        .route("/v1/logout", post(logout))
        .route("/v1/passkeys/setup", post(passkey_setup))
        .route("/v1/passkeys/setup/skip", post(passkey_setup_skip))
        .route("/v1/enroll/start", post(enroll_start))
        .route("/v1/enroll/respond", post(enroll_respond))
        .route("/v1/enroll/password", post(enroll_password))
        .route("/v1/enroll/totp", post(enroll_totp))
        .route("/v1/enroll/passkey", post(enroll_passkey))
        .route("/v1/enroll/finish", post(enroll_finish))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(axum::middleware::map_response(no_store))
        .with_state(b)
}

pub fn tls_acceptor(cert: &std::path::Path, key: &std::path::Path) -> anyhow::Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", cert.display()))?
        .collect::<Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("{}: no certificate", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| anyhow::anyhow!("reading {}: {e}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.max_early_data_size = 0;
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Accept loop. Returns when `shutdown` resolves.
pub async fn serve(
    b: Arc<Broker>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    let app = router(b.clone());
    let slots = Arc::new(tokio::sync::Semaphore::new(b.cfg.limits.max_connections));
    info!("listening on {}", listener.local_addr()?);
    tokio::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => { warn!("accept: {e}"); tokio::time::sleep(Duration::from_millis(100)).await; continue; }
            },
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!("connection limit reached; dropping {peer}");
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                app.clone().oneshot(req.map(axum::body::Body::new))
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .keep_alive(true)
                .max_buf_size(64 * 1024)
                .serve_connection(TokioIo::new(tls), svc);
            let _ = tokio::time::timeout(Duration::from_secs(300), conn).await;
        });
    }
}
