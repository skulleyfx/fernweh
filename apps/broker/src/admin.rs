//! Local admin status API on a Unix socket (`[admin]` in broker.toml).
//!
//! Read-only apart from `refresh`, which only drops the directory caches. The
//! socket is never bound to TCP; every connection must come from the uid of
//! `admin.api_user`, checked with `SO_PEERCRED` before a byte is read. Absent
//! `[admin]` = the feature does not exist.
//!
//! * `GET  /v1/admin/status`      every directory host with probe, presence and grants
//! * `GET  /v1/admin/users/{sam}` what the broker would list for that user
//! * `POST /v1/admin/refresh`     drop the view and user caches

use std::ffi::CString;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use tokio::net::{UnixListener, UnixStream};
use tower::ServiceExt;
use tracing::{debug, info, warn};

use crate::broker::Broker;
use crate::config::AdminConfig;

async fn status(State(b): State<Arc<Broker>>) -> Response {
    match b.admin_status().await {
        Ok(s) => Json(s).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn user(State(b): State<Arc<Broker>>, Path(sam): Path<String>) -> Response {
    match b.admin_user(&sam).await {
        Ok(u) => Json(u).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn refresh(State(b): State<Arc<Broker>>) -> Response {
    b.invalidate_caches().await;
    Json(json!({"state": "ok"})).into_response()
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"state": "not_found"}))).into_response()
}

async fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

pub fn router(b: Arc<Broker>) -> Router {
    Router::new()
        .route("/v1/admin/status", get(status))
        .route("/v1/admin/users/{sam}", get(user))
        .route("/v1/admin/refresh", post(refresh))
        .fallback(not_found)
        .layer(axum::extract::DefaultBodyLimit::max(1024))
        .layer(axum::middleware::map_response(no_store))
        .with_state(b)
}

/// The peer-credential rule: only the API user's uid is served.
pub fn peer_allowed(peer_uid: u32, api_uid: u32) -> bool {
    peer_uid == api_uid
}

fn passwd_uid(user: &str) -> Result<u32> {
    let name = CString::new(user)?;
    let mut buf = vec![0u8; 16 * 1024];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc =
        unsafe { libc::getpwnam_r(name.as_ptr(), &mut pw, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        bail!("admin.api_user {user}: no such user");
    }
    Ok(pw.pw_uid)
}

fn group_gid(group: &str) -> Result<u32> {
    let name = CString::new(group)?;
    let mut buf = vec![0u8; 16 * 1024];
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::group = std::ptr::null_mut();
    let rc =
        unsafe { libc::getgrnam_r(name.as_ptr(), &mut gr, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        bail!("admin.socket_group {group}: no such group");
    }
    Ok(gr.gr_gid)
}

/// A bound, permission-set admin socket and the uid it serves.
pub struct AdminSocket {
    listener: UnixListener,
    api_uid: u32,
}

/// Bind the socket (replacing a stale socket file, never any other file type).
/// Failing here is a startup error: an `[admin]` section that does not work
/// must not be silently ignored.
pub fn bind(cfg: &AdminConfig) -> Result<AdminSocket> {
    let api_uid = passwd_uid(&cfg.api_user)?;
    let path = &cfg.socket;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if let Some(g) = &cfg.socket_group {
        let gid = group_gid(g)?;
        // Only a directory this broker owns (the RuntimeDirectory dedicated to the
        // socket) may be re-grouped; never a shared one.
        let dir = path.parent().with_context(|| format!("{} has no parent directory", path.display()))?;
        let owner = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?.uid();
        let me = unsafe { libc::geteuid() };
        if owner != me {
            let _ = std::fs::remove_file(path);
            bail!(
                "admin.socket_group: {} is owned by uid {owner}, not the broker (uid {me}); \
                 put the socket in a directory dedicated to it",
                dir.display()
            );
        }
        chgrp(path, gid)?;
        chgrp(dir, gid)?;
    }
    info!("admin socket on {} for uid {api_uid}", path.display());
    Ok(AdminSocket { listener, api_uid })
}

fn chgrp(path: &FsPath, gid: u32) -> Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())?;
    // uid (u32)-1 = leave unchanged.
    if unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("chgrp {}", path.display()));
    }
    Ok(())
}

/// Accept loop: refuse any peer that is not the API user, serve the rest.
pub async fn serve(b: Arc<Broker>, sock: AdminSocket, shutdown: impl std::future::Future<Output = ()>) {
    serve_listener(b, sock.listener, sock.api_uid, shutdown).await
}

pub(crate) async fn serve_listener(
    b: Arc<Broker>,
    listener: UnixListener,
    api_uid: u32,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let app = router(b);
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    tokio::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            _ = &mut shutdown => return,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => { warn!("admin accept: {e}"); tokio::time::sleep(Duration::from_millis(100)).await; continue; }
            },
        };
        match stream.peer_cred() {
            Ok(c) if peer_allowed(c.uid(), api_uid) => {}
            Ok(c) => {
                warn!("refusing admin client uid {}", c.uid());
                continue;
            }
            Err(_) => continue,
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!("admin connection limit reached");
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle(stream, app).await;
        });
    }
}

async fn handle(stream: UnixStream, app: Router) {
    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        app.clone().oneshot(req.map(axum::body::Body::new))
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .keep_alive(true)
        .max_buf_size(16 * 1024)
        .serve_connection(TokioIo::new(stream), svc);
    let _ = tokio::time::timeout(Duration::from_secs(60), conn).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_api_uid_passes() {
        assert!(peer_allowed(996, 996));
        assert!(!peer_allowed(0, 996), "not even root");
        assert!(!peer_allowed(997, 996));
    }
}
