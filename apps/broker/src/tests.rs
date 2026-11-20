//! Broker flow tests against fakes (Kerberos, directory, relay, prober, clock).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::broker::{ApiError, Broker, Deps};
use crate::config::{test_config, ClientUpdatesConfig, Config};

#[tokio::test]
async fn public_client_update_feed_streams_only_the_published_release() {
    let directory = std::env::temp_dir().join(format!("fernweh-update-test-{}", rand::random::<u64>()));
    std::fs::create_dir(&directory).unwrap();
    let dmg = b"signed-dmg-test-bytes";
    std::fs::write(directory.join("1.0.139.dmg"), dmg).unwrap();
    let digest = hex::encode(crate::util::sha256(dmg));
    std::fs::write(
        directory.join("current.json"),
        serde_json::json!({
            "version": "1.0.139", "sha256": digest, "size": dmg.len()
        })
        .to_string(),
    )
    .unwrap();
    let h = harness_cfg(FakeKerberos::new(&[]), |cfg| {
        cfg.client_updates = Some(ClientUpdatesConfig { directory: directory.clone(), windows_directory: None });
    });
    let app = crate::api::router(h.b);
    let manifest = app
        .clone()
        .oneshot(Request::builder().uri("/v1/client-updates/macos-arm64").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(manifest.status(), StatusCode::OK);
    let body = axum::body::to_bytes(manifest.into_body(), 4096).await.unwrap();
    let feed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(feed["version"], "1.0.139");
    assert_eq!(feed["sha256"], digest);
    assert_eq!(feed["size"], dmg.len());
    let route = feed["url"].as_str().unwrap();
    let response = app.clone().oneshot(Request::builder().uri(route).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(axum::body::to_bytes(response.into_body(), 4096).await.unwrap().as_ref(), dmg);
    let old = app
        .oneshot(Request::builder().uri("/v1/client-updates/macos-arm64/1.0.138.dmg").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::NOT_FOUND);
    std::fs::remove_dir_all(directory).unwrap();
}
#[tokio::test]
async fn windows_updates_are_independent_and_require_complete_published_artifacts() {
    let root = std::env::temp_dir().join(format!("fernweh-platform-test-{}", rand::random::<u64>()));
    let mac = root.join("mac");
    let win = root.join("windows");
    std::fs::create_dir_all(&mac).unwrap();
    std::fs::create_dir_all(&win).unwrap();
    let bytes = b"unsigned-alpha-msi-fixture";
    let h = harness_cfg(FakeKerberos::new(&[]), |cfg| {
        cfg.client_updates = Some(ClientUpdatesConfig { directory: mac.clone(), windows_directory: Some(win.clone()) });
    });
    let app = crate::api::router(h.b);
    let get = |url: &str| Request::builder().uri(url).body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(get("/v1/client-updates/windows-x64")).await.unwrap().status(), StatusCode::NOT_FOUND);
    std::fs::write(win.join("current.json"), serde_json::json!({
        "version":"1.1.040", "sha256":hex::encode(crate::util::sha256(bytes)), "size":bytes.len()
    }).to_string()).unwrap();
    assert_eq!(app.clone().oneshot(get("/v1/client-updates/windows-x64")).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
    std::fs::write(win.join("1.1.040.msi"), b"partial").unwrap();
    assert_eq!(app.clone().oneshot(get("/v1/client-updates/windows-x64")).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
    std::fs::write(win.join("1.1.040.msi"), bytes).unwrap();
    let response = app.clone().oneshot(get("/v1/client-updates/windows-x64")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let feed: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(),4096).await.unwrap()).unwrap();
    assert_eq!(feed["platform"], "windows-x64");
    assert_eq!(feed["product_name"], "BDE fernweh");
    assert_eq!(feed["upgrade_code"], "{F598C7E9-ECA2-432F-B0C0-41F9E1201F8F}");
    assert_eq!(feed["url"], "/v1/client-updates/windows-x64/1.1.040.msi");
    let response = app.clone().oneshot(get(feed["url"].as_str().unwrap())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/x-msi");
    assert_eq!(axum::body::to_bytes(response.into_body(),4096).await.unwrap().as_ref(), bytes);
    for url in ["/v1/client-updates/windows-x64/1.1.039.msi", "/v1/client-updates/windows-x64/1.1.040.dmg", "/v1/client-updates/macos-arm64", "/v1/client-updates/macos-arm64/1.1.040.msi"] {
        assert_eq!(app.clone().oneshot(get(url)).await.unwrap().status(), StatusCode::NOT_FOUND, "{url}");
    }
    std::fs::write(win.join("current.json"), r#"{"version":"../secret","sha256":"bad","size":0}"#).unwrap();
    assert_eq!(app.oneshot(get("/v1/client-updates/windows-x64")).await.unwrap().status(), StatusCode::NOT_FOUND);
    std::fs::remove_dir_all(root).unwrap();
}

use crate::directory::FakeDirectory;
use crate::hbac::fixtures::*;
use crate::hbac::UserView;
use crate::kerberos::FakeKerberos;
use crate::pins::PinStore;
use crate::probe::FakeProber;
use crate::relay::{FakeRelay, RelayRequest};
use crate::sessions::SessionStore;
use crate::util::FakeClock;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const IP2: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
const IP3: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
/// Office LAN client (inside `routing.direct_client_cidrs` in `harness_direct`).
const LAN: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 50));
const WS1: &str = "ws1.example.org";
const WS2: &str = "ws2.example.org";

struct H {
    b: Arc<Broker>,
    krb: Arc<FakeKerberos>,
    relay: Arc<FakeRelay>,
    prober: Arc<FakeProber>,
    pins: Arc<PinStore>,
    audit: Arc<Audit>,
    clock: Arc<FakeClock>,
    sessions: Arc<SessionStore>,
    dir: Arc<FakeDirectory>,
    cfg: Config,
}

fn harness_with(krb: FakeKerberos) -> H {
    harness_cfg(krb, |_| {})
}

fn harness_cfg(krb: FakeKerberos, tweak: impl FnOnce(&mut Config)) -> H {
    let mut cfg = test_config();
    cfg.limits.min_respond_ms = 0;
    tweak(&mut cfg);
    let v = view(vec![
        rule("plank_remote_anna", &[user("anna")], &[host("ws1"), hostgroup("remote-nested")], &[svc("plank-remote")]),
        rule("plank_remote_bob", &[user("bob")], &[host("ws1")], &[svc("plank-remote")]),
    ]);
    let dir =
        Arc::new(FakeDirectory::new(v, vec![("anna", anna()), ("bob", UserView { disabled: false, dn: user("bob"), groups: vec![], ..Default::default() })]));
    let krb = Arc::new(krb);
    let relay = Arc::new(FakeRelay::default());
    let prober = Arc::new(FakeProber {
        certs: Mutex::new(HashMap::from([(WS1.to_string(), Some([1u8; 32])), (WS2.to_string(), Some([2u8; 32]))])),
        busy: Mutex::new(HashMap::new()),
    });
    let pins = Arc::new(PinStore::memory());
    let audit = Arc::new(Audit::memory());
    let clock = FakeClock::new();
    let sessions = Arc::new(SessionStore::memory());
    let b = Broker::new(
        cfg.clone(),
        Deps {
            krb: krb.clone(),
            dir: dir.clone(),
            relay: relay.clone(),
            prober: prober.clone(),
            pins: pins.clone(),
            audit: audit.clone(),
            clock: clock.clone(),
            sessions: sessions.clone(),
        },
    );
    H { b, krb, relay, prober, pins, audit, clock, sessions, dir, cfg }
}

impl H {
    /// A new broker process on the same disk state (session store), KDC and clock.
    fn restart(&self) -> Arc<Broker> {
        Broker::new(
            self.cfg.clone(),
            Deps {
                krb: self.krb.clone(),
                dir: self.dir.clone(),
                relay: self.relay.clone(),
                prober: self.prober.clone(),
                pins: self.pins.clone(),
                audit: self.audit.clone(),
                clock: self.clock.clone(),
                sessions: self.sessions.clone(),
            },
        )
    }
}

fn harness() -> H {
    harness_with(FakeKerberos::new(&[("anna", "secret123456"), ("bob", "hunter2654321")]))
}

fn direct_lan(cfg: &mut Config) {
    cfg.routing.direct_client_cidrs = vec!["10.1.0.0/24".into()];
}

fn harness_direct() -> H {
    harness_cfg(FakeKerberos::new(&[("anna", "secret123456"), ("bob", "hunter2654321")]), direct_lan)
}

fn z(v: &[&str]) -> Vec<Zeroizing<String>> {
    v.iter().map(|s| Zeroizing::new(s.to_string())).collect()
}

fn test_passkey_mapping() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let mut point = [0u8; 65];
    point.copy_from_slice(key.public_key().as_ref());
    format!("passkey:{},{}", STANDARD.encode([7u8; 32]), STANDARD.encode(crate::device::DeviceKey(point).to_spki()))
}

fn setup_bearer<'a>(
    device: &crate::device::testkey::TestDevice,
    token: &'a str,
    time: u64,
    path: &str,
) -> crate::broker::Bearer<'a> {
    use crate::device::{proof_message, DeviceProof};
    let digest = crate::util::sha256(b"");
    crate::broker::Bearer {
        token,
        proof: Some(DeviceProof {
            method: "POST".into(),
            path: path.into(),
            time,
            signature: device.sign(&proof_message("POST", path, time, token, &digest)),
            body_sha256: digest,
        }),
    }
}

#[tokio::test]
async fn fresh_otp_session_can_add_one_passkey_without_admin_rights() {
    let h = harness();
    h.dir.passwords.lock().unwrap().insert("anna".into(), "secret".into());
    h.dir.enrol.lock().unwrap().insert(
        "anna".into(),
        crate::enrol::EnrolFacts {
            auth_types: vec!["password".into(), "otp".into(), "passkey".into()],
            ..Default::default()
        },
    );
    let device = crate::device::testkey::TestDevice::new();
    let device_key = crate::device::DeviceKey::from_spki(&device.spki()).unwrap();
    let c = h.b.auth_start_method(IP, "anna", crate::broker::Method::PasswordOtp, Some(device_key)).await.unwrap();
    let reply = h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap();
    assert!(reply.passkey_setup_available);
    let mapping = test_passkey_mapping();
    let app = crate::api::router(h.b.clone());
    let body = serde_json::json!({"mapping": mapping}).to_string();
    assert_eq!(call(&app, "POST", "/v1/passkeys/setup", None, &body).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&app, "POST", "/v1/passkeys/setup", Some(&reply.session_token), &body).await.0,
        StatusCode::UNAUTHORIZED
    );
    let now = crate::util::Clock::unix(&*h.clock);
    h.b.setup_passkey(setup_bearer(&device, &reply.session_token, now, "/v1/passkeys/setup"), &mapping).await.unwrap();
    assert_eq!(h.dir.passkeys.lock().unwrap().as_slice(), &[("anna".to_string(), mapping.clone())]);
    h.b.setup_passkey(setup_bearer(&device, &reply.session_token, now + 1, "/v1/passkeys/setup"), &mapping)
        .await
        .unwrap();
    assert_eq!(
        h.b.setup_passkey(
            setup_bearer(&device, &reply.session_token, now + 2, "/v1/passkeys/setup"),
            &test_passkey_mapping()
        )
        .await,
        Err(ApiError::Denied)
    );
    assert_eq!(h.audit.count("passkey_setup_added"), 1);
    let events = serde_json::to_string(&h.audit.events()).unwrap();
    assert!(!events.contains("secret"));
}

#[tokio::test]
async fn passkey_setup_requires_fresh_otp_and_enabled_ipa_type() {
    let h = harness();
    h.dir.passwords.lock().unwrap().insert("anna".into(), "secret".into());
    let device = crate::device::testkey::TestDevice::new();
    let device_key = crate::device::DeviceKey::from_spki(&device.spki()).unwrap();
    let c =
        h.b.auth_start_method(IP, "anna", crate::broker::Method::PasswordOtp, Some(device_key.clone())).await.unwrap();
    let first = h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap();
    assert!(!first.passkey_setup_available);
    let now = crate::util::Clock::unix(&*h.clock);
    assert_eq!(
        h.b.setup_passkey(
            setup_bearer(&device, &first.session_token, now, "/v1/passkeys/setup"),
            &test_passkey_mapping()
        )
        .await,
        Err(ApiError::Denied)
    );
    h.dir.enrol.lock().unwrap().insert(
        "anna".into(),
        crate::enrol::EnrolFacts {
            auth_types: vec!["password".into(), "otp".into(), "passkey".into()],
            ..Default::default()
        },
    );
    let unbound = h.b.auth_start(IP, "anna").unwrap();
    let unbound = h.b.auth_respond(IP, &unbound.conversation_id, z(&["secret", "123456"])).await.unwrap();
    assert!(!unbound.passkey_setup_available, "a bearer alone cannot enroll a new key");
    let c =
        h.b.auth_start_method(IP, "anna", crate::broker::Method::PasswordOtp, Some(device_key.clone())).await.unwrap();
    let second = h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap();
    assert!(second.passkey_setup_available);
    h.clock.advance(Duration::from_secs(300));
    let now = crate::util::Clock::unix(&*h.clock);
    assert_eq!(
        h.b.setup_passkey(
            setup_bearer(&device, &second.session_token, now, "/v1/passkeys/setup"),
            &test_passkey_mapping()
        )
        .await,
        Err(ApiError::Denied)
    );
    let c = h.b.auth_start_method(IP, "anna", crate::broker::Method::PasswordOtp, Some(device_key)).await.unwrap();
    let third = h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap();
    h.b.skip_passkey_setup(setup_bearer(&device, &third.session_token, now + 1, "/v1/passkeys/setup/skip"))
        .await
        .unwrap();
    assert_eq!(
        h.b.setup_passkey(
            setup_bearer(&device, &third.session_token, now + 2, "/v1/passkeys/setup"),
            &test_passkey_mapping()
        )
        .await,
        Err(ApiError::Denied)
    );
    h.b.logout(setup_bearer(&device, &third.session_token, now + 3, "/v1/logout")).await.unwrap();
    assert_eq!(
        h.b.setup_passkey(
            setup_bearer(&device, &third.session_token, now + 4, "/v1/passkeys/setup"),
            &test_passkey_mapping()
        )
        .await,
        Err(ApiError::Unauthorized)
    );
}

impl H {
    async fn login_from(&self, ip: IpAddr, user: &str, pw: &str, otp: &str) -> Result<String, ApiError> {
        let c = self.b.auth_start(ip, user)?;
        self.b.auth_respond(ip, &c.conversation_id, z(&[pw, otp])).await.map(|r| r.session_token)
    }
    async fn login(&self) -> String {
        self.login_from(IP, "anna", "secret", "123456").await.unwrap()
    }
    fn relay_calls(&self) -> Vec<RelayRequest> {
        self.relay.calls.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn auth_flow_and_reply_shapes() {
    let h = harness();
    let c = h.b.auth_start(IP, "Anna").unwrap();
    let j = serde_json::to_value(&c).unwrap();
    assert_eq!(j["state"], "challenge");
    assert_eq!(
        j["prompts"],
        serde_json::json!([
            {"id":"password","style":"secret","text":"Password"},
            {"id":"otp","style":"otp","text":"Authenticator code"}
        ])
    );
    let r = h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap();
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["state"], "authenticated");
    assert_eq!(j["username"], "anna");
    assert_eq!(j["expires_in"], 36000);
    assert_eq!(r.session_token.len(), 43, "256-bit base64url");
    assert_eq!(h.audit.count("login_ok"), 1);

    let hosts = h.b.list_hosts(IP, &r.session_token).await.unwrap();
    let j = serde_json::to_value(&hosts).unwrap();
    assert_eq!(
        j,
        serde_json::json!({"hosts":[
            {"id":WS1,"name":"ws1","online":true,"busy":null,"in_use_by":null,"connected_users":[],"connectable":true,"reason":null},
            {"id":WS2,"name":"ws2","online":true,"busy":null,"in_use_by":null,"connected_users":[],"connectable":true,"reason":null}
        ]})
    );

    let cr = h.b.connect(IP, &r.session_token, WS1, "remote.example.org").await.unwrap();
    let j = serde_json::to_value(&cr).unwrap();
    let keys: Vec<&str> = j.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys.len(), 7);
    assert_eq!(j["route"], "relay");
    for k in ["route", "endpoint", "port", "host_cert_sha256", "username", "gssapi_token", "expires_in"] {
        assert!(keys.contains(&k), "{k}");
    }
    assert_eq!(j["endpoint"], "remote.example.org");
    assert_eq!(j["port"], 29001);
    assert_eq!(j["host_cert_sha256"], hex::encode([1u8; 32]));
    assert_eq!(j["username"], "anna");
    assert_eq!(j["expires_in"], 30);
    use base64::Engine;
    let tok = base64::engine::general_purpose::STANDARD.decode(cr.gssapi_token).unwrap();
    let mut cb = b"tls-server-end-point:".to_vec();
    cb.extend([1u8; 32]);
    assert!(tok.ends_with(&cb), "channel bindings over the pinned leaf hash");
    assert_eq!(
        h.relay_calls(),
        vec![RelayRequest::Open {
            client: Ipv4Addr::new(203, 0, 113, 7),
            port: 29001,
            target: Ipv4Addr::new(192, 0, 2, 11),
            ttl_secs: 30
        }]
    );
    let conn = h.audit.events().into_iter().find(|e| e["event"] == "connect").unwrap();
    assert_eq!(conn["ip"], "203.0.113.7");
    assert_eq!(conn["host"], WS1);
    assert_eq!(conn["port"], 29001);
}

#[tokio::test]
async fn denied_paths_are_generic_and_skip_kdc_when_possible() {
    let h = harness();
    // Wrong credentials.
    assert_eq!(h.login_from(IP, "anna", "wrong", "123456").await, Err(ApiError::Denied));
    assert_eq!(h.krb.logins(), 1);
    // Unknown conversation / reuse.
    let c = h.b.auth_start(IP, "anna").unwrap();
    assert!(h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.is_ok());
    assert_eq!(h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.b.auth_respond(IP, "nope", z(&["secret", "123456"])).await.unwrap_err(), ApiError::Denied);
    // Other source address than the one that started the conversation.
    let c = h.b.auth_start(IP, "anna").unwrap();
    assert_eq!(
        h.b.auth_respond(IP2, &c.conversation_id, z(&["secret", "123456"])).await.unwrap_err(),
        ApiError::Denied
    );
    // Expired conversation.
    let c = h.b.auth_start(IP, "anna").unwrap();
    h.clock.advance(Duration::from_secs(121));
    assert_eq!(h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap_err(), ApiError::Denied);
    // Malformed responses and invalid user names never reach the KDC.
    let before = h.krb.logins();
    for (i, resp) in
        [vec!["secret"], vec!["secret", "12ab56"], vec!["", "123456"], vec!["secret", "123456", "x"]].iter().enumerate()
    {
        // Malformed attempts count as failures, so spread them over addresses.
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 100 + i as u8));
        let c = h.b.auth_start(ip, "anna").unwrap();
        assert_eq!(h.b.auth_respond(ip, &c.conversation_id, z(resp)).await.unwrap_err(), ApiError::Denied);
    }
    let c = h.b.auth_start(IP2, "host/evil@EXAMPLE.ORG").unwrap();
    assert_eq!(c.state, "challenge", "no user enumeration at start");
    assert_eq!(h.b.auth_respond(IP2, &c.conversation_id, z(&["x", "123456"])).await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.krb.logins(), before);
    // Unknown user goes to the KDC and gets the same answer.
    assert_eq!(h.login_from(IP2, "nobody", "x", "123456").await, Err(ApiError::Denied));
    // KDC down: still generic, not counted as a failure.
    let mut k = FakeKerberos::new(&[("anna", "secret123456")]);
    k.unavailable = true;
    let h2 = harness_with(k);
    for _ in 0..4 {
        assert_eq!(h2.login_from(IP, "anna", "secret", "123456").await, Err(ApiError::Denied));
        h2.clock.advance(Duration::from_secs(20));
    }
    assert!(h2.b.auth_start(IP, "anna").is_ok(), "KDC outages do not lock users out");
}

#[tokio::test]
async fn start_rate_limit_per_ip() {
    let h = harness();
    for _ in 0..5 {
        h.b.auth_start(IP, "anna").unwrap();
    }
    assert!(matches!(h.b.auth_start(IP, "anna"), Err(ApiError::RateLimited(60))));
    assert!(h.b.auth_start(IP2, "anna").is_ok());
    h.clock.advance(Duration::from_secs(60));
    assert!(h.b.auth_start(IP, "anna").is_ok());
}

#[tokio::test]
async fn three_failures_block_user_ip_before_the_kdc() {
    let h = harness();
    for _ in 0..3 {
        assert_eq!(h.login_from(IP, "anna", "wrong", "000000").await, Err(ApiError::Denied));
        h.clock.advance(Duration::from_secs(20));
    }
    assert_eq!(h.krb.logins(), 3);
    assert_eq!(
        h.b.auth_start(IP, "anna").unwrap_err(),
        ApiError::RateLimited(900 - 20),
        "blocked from the 3rd failure on"
    );
    // Right password is not even tried while blocked.
    assert!(h.login_from(IP, "anna", "secret", "123456").await.is_err());
    assert_eq!(h.krb.logins(), 3);
    // Other user from the same IP and same user from another IP are unaffected.
    assert!(h.login_from(IP, "bob", "hunter2", "654321").await.is_ok());
    assert!(h.login_from(IP2, "anna", "secret", "123456").await.is_ok());
    h.clock.advance(Duration::from_secs(900));
    assert!(h.login_from(IP, "anna", "secret", "123456").await.is_ok());
    assert_eq!(h.audit.count("login_fail"), 3);
}

#[tokio::test]
async fn session_idle_absolute_and_ticket_expiry() {
    // Idle.
    let h = harness();
    let t = h.login().await;
    h.clock.advance(Duration::from_secs(3599));
    assert!(h.b.list_hosts(IP, &t).await.is_ok());
    h.clock.advance(Duration::from_secs(3600));
    assert_eq!(h.b.list_hosts(IP, &t).await.unwrap_err(), ApiError::Unauthorized);
    assert_eq!(h.krb.destroyed.lock().unwrap().len(), 1, "TGT destroyed");
    // Absolute 10 h even while active.
    let t = h.login().await;
    for _ in 0..20 {
        h.clock.advance(Duration::from_secs(1800));
        let _ = h.b.list_hosts(IP, &t).await;
    }
    assert_eq!(h.b.list_hosts(IP, &t).await.unwrap_err(), ApiError::Unauthorized);
    // Bounded by the TGT lifetime.
    let clock_now = FakeClock::new();
    let mut k = FakeKerberos::new(&[("anna", "secret123456")]);
    k.end_unix = crate::util::Clock::unix(&*clock_now) + 600;
    let h = harness_with(k);
    let c = h.b.auth_start(IP, "anna").unwrap();
    let r = h.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap();
    assert_eq!(r.expires_in, 600);
    h.clock.advance(Duration::from_secs(601));
    assert_eq!(h.b.list_hosts(IP, &r.session_token).await.unwrap_err(), ApiError::Unauthorized);
    assert_eq!(h.audit.count("session_end"), 1);
    // Reaper ends expired sessions without a request.
    let h = harness();
    let _t = h.login().await;
    h.clock.advance(Duration::from_secs(3601));
    h.b.reap().await;
    assert_eq!(h.audit.count("session_end"), 1);
    assert_eq!(h.krb.destroyed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn logout_closes_leases_and_destroys_tgt() {
    let h = harness();
    let t = h.login().await;
    h.b.connect(IP, &t, WS1, "remote.example.org").await.unwrap();
    h.b.connect(IP, &t, WS2, "remote.example.org").await.unwrap();
    h.b.logout(&t).await.unwrap();
    let calls = h.relay_calls();
    let c = Ipv4Addr::new(203, 0, 113, 7);
    assert!(calls.contains(&RelayRequest::Close { client: c, port: 29001, flush: true }));
    assert!(calls.contains(&RelayRequest::Close { client: c, port: 29002, flush: true }));
    assert_eq!(h.b.lease_count(), 0);
    assert_eq!(h.krb.destroyed.lock().unwrap().len(), 1);
    assert_eq!(h.b.list_hosts(IP, &t).await.unwrap_err(), ApiError::Unauthorized);
    assert_eq!(h.audit.count("lease_end"), 2);
}

#[tokio::test]
async fn lease_allocation_reuse_exhaustion_and_release() {
    let h = harness(); // ports 29001-29003
    let t = h.login().await;
    let p1 = h.b.connect(IP, &t, WS1, "e").await.unwrap().port;
    let p1b = h.b.connect(IP, &t, WS1, "e").await.unwrap().port;
    assert_eq!(p1, p1b, "same session, host and address reuse the lease");
    let p2 = h.b.connect(IP, &t, WS2, "e").await.unwrap().port;
    let p3 = h.b.connect(IP2, &t, WS1, "e").await.unwrap().port;
    assert_eq!((p1, p2, p3), (29001, 29002, 29003));
    assert_eq!(h.b.connect(IP3, &t, WS1, "e").await.unwrap_err(), ApiError::Exhausted);
    // Keepalive keeps two of them; the third lapses and its port is reused.
    h.clock.advance(Duration::from_secs(20));
    assert_eq!(h.b.keepalive(IP, &t, WS1).await.unwrap().expires_in, 90);
    assert_eq!(h.b.keepalive(IP, &t, WS2).await.unwrap().expires_in, 90);
    h.clock.advance(Duration::from_secs(11));
    h.b.reap().await;
    assert!(h.relay_calls().contains(&RelayRequest::Close {
        client: Ipv4Addr::new(198, 51, 100, 20),
        port: 29003,
        flush: false
    }));
    assert_eq!(h.b.keepalive(IP2, &t, WS1).await.unwrap_err(), ApiError::NoLease);
    assert_eq!(h.b.connect(IP3, &t, WS1, "e").await.unwrap().port, 29003);
    // Relay failure frees the port again.
    *h.relay.fail.lock().unwrap() = true;
    h.b.logout(&t).await.unwrap();
    *h.relay.fail.lock().unwrap() = false;
    assert_eq!(h.b.lease_count(), 0);
    let t2 = h.login_from(IP, "bob", "hunter2", "654321").await.unwrap();
    *h.relay.fail.lock().unwrap() = true;
    assert_eq!(h.b.connect(IP, &t2, WS1, "e").await.unwrap_err(), ApiError::Internal("relay unavailable"));
    assert_eq!(h.b.lease_count(), 0);
}

#[tokio::test]
async fn host_list_is_a_keepalive() {
    let h = harness();
    let t = h.login().await;
    h.b.connect(IP, &t, WS1, "e").await.unwrap();
    h.b.list_hosts(IP, &t).await.unwrap();
    assert!(matches!(h.relay_calls().last(), Some(RelayRequest::Refresh { ttl_secs: 90, port: 29001, .. })));
    // A listing from another address does not refresh this address's lease.
    let n = h.relay_calls().len();
    h.b.list_hosts(IP2, &t).await.unwrap();
    assert_eq!(h.relay_calls().len(), n);
}

#[tokio::test]
async fn pin_tofu_mismatch_and_reset() {
    let h = harness();
    let t = h.login().await;
    h.b.list_hosts(IP, &t).await.unwrap();
    assert_eq!(h.pins.get(WS1), Some(hex::encode([1u8; 32])));
    assert_eq!(h.audit.count("pin_new"), 2);
    // Host presents a new certificate.
    h.prober.certs.lock().unwrap().insert(WS1.into(), Some([9u8; 32]));
    h.clock.advance(Duration::from_secs(40));
    let hosts = h.b.list_hosts(IP, &t).await.unwrap().hosts;
    let ws1 = hosts.iter().find(|x| x.id == WS1).unwrap();
    assert!(ws1.online);
    assert!(!ws1.connectable);
    assert_eq!(ws1.reason.as_deref(), Some("certificate changed"));
    assert_eq!(h.b.connect(IP, &t, WS1, "e").await.unwrap_err(), ApiError::Unavailable("certificate changed"));
    assert_eq!(h.audit.count("pin_mismatch"), 1);
    // Mismatch is sticky across probes until reset.
    h.clock.advance(Duration::from_secs(40));
    h.b.probe_all().await;
    assert_eq!(h.b.connect(IP, &t, WS1, "e").await.unwrap_err(), ApiError::Unavailable("certificate changed"));
    assert_eq!(h.audit.count("pin_mismatch"), 1, "reported once");
    assert!(h.pins.reset(WS1).unwrap());
    h.b.probe_all().await;
    let cr = h.b.connect(IP, &t, WS1, "e").await.unwrap();
    assert_eq!(cr.host_cert_sha256, hex::encode([9u8; 32]));
}

#[tokio::test]
async fn host_occupancy_is_advisory_and_never_bypasses_pinning() {
    let h = harness();
    let t = h.login().await;
    h.prober.busy.lock().unwrap().insert(WS1.into(), Some(true));
    let hosts = h.b.list_hosts(IP, &t).await.unwrap().hosts;
    let ws1 = hosts.iter().find(|host| host.id == WS1).unwrap();
    assert_eq!(ws1.busy, Some(true));
    assert!(ws1.connectable, "occupancy must not change desktop handoff admission");
    assert_eq!(ws1.in_use_by, None, "the host list must not reveal an owner");

    h.prober.certs.lock().unwrap().insert(WS1.into(), Some([9u8; 32]));
    h.clock.advance(Duration::from_secs(40));
    let hosts = h.b.list_hosts(IP, &t).await.unwrap().hosts;
    let ws1 = hosts.iter().find(|host| host.id == WS1).unwrap();
    assert_eq!(ws1.busy, None);
    assert!(!ws1.connectable);
}

#[tokio::test]
async fn collaboration_users_keep_independent_relay_leases_on_a_busy_host() {
    let h = harness();
    h.prober.busy.lock().unwrap().insert(WS1.into(), Some(true));
    // Both users may be behind the same NAT. A host's coarse busy status is
    // advisory: only the authenticated Host can ask its desktop owner for consent.
    let owner = h.login().await;
    let guest = h.login_from(IP, "bob", "hunter2", "654321").await.unwrap();
    let owner_route = h.b.connect(IP, &owner, WS1, "remote.example.org").await.unwrap();
    let guest_route = h.b.connect(IP, &guest, WS1, "remote.example.org").await.unwrap();
    assert_ne!(owner_route.port, guest_route.port);
    assert_eq!(owner_route.host_cert_sha256, guest_route.host_cert_sha256);
    assert_eq!(owner_route.username, "anna");
    assert_eq!(guest_route.username, "bob");
    assert_eq!(h.b.lease_count(), 2);

    // Transport reachability never extends the guest's HBAC assignment.
    assert_eq!(h.b.connect(IP, &guest, WS2, "remote.example.org").await.unwrap_err(), ApiError::Denied);
    h.b.logout(&guest).await.unwrap();
    assert_eq!(h.b.lease_count(), 1);
    assert!(h.relay_calls().contains(&RelayRequest::Close {
        client: Ipv4Addr::new(203, 0, 113, 7), port: guest_route.port, flush: true,
    }));
    assert!(!h.relay_calls().contains(&RelayRequest::Close {
        client: Ipv4Addr::new(203, 0, 113, 7), port: owner_route.port, flush: true,
    }));
    assert!(h.b.keepalive(IP, &owner, WS1).await.is_ok());
    assert_eq!(h.b.keepalive(IP, &guest, WS1).await.unwrap_err(), ApiError::Unauthorized);
}

#[tokio::test]
async fn collaboration_users_keep_independent_direct_grants() {
    let h = harness_direct();
    h.prober.busy.lock().unwrap().insert(WS1.into(), Some(true));
    let owner = h.login_from(LAN, "anna", "secret", "123456").await.unwrap();
    let guest = h.login_from(LAN, "bob", "hunter2", "654321").await.unwrap();
    for token in [&owner, &guest] {
        let route = h.b.connect(LAN, token, WS1, "remote.example.org").await.unwrap();
        assert_eq!(route.route, "direct");
        assert_eq!(route.port, 28989);
    }
    assert_eq!(h.b.direct_count(), 2);
    h.b.logout(&guest).await.unwrap();
    assert_eq!(h.b.direct_count(), 1);
    assert!(h.b.keepalive(LAN, &owner, WS1).await.is_ok());
    assert_eq!(h.b.keepalive(LAN, &guest, WS1).await.unwrap_err(), ApiError::Unauthorized);
    assert!(h.relay_calls().is_empty());
}

const CONNECTION_A: &str = "11111111111111111111111111111111";
const CONNECTION_B: &str = "22222222222222222222222222222222";

#[tokio::test]
async fn presence_tracks_streams_not_grants_and_deduplicates_people() {
    for direct in [false, true] {
        let h = if direct { harness_direct() } else { harness() };
        let ip = if direct { LAN } else { IP };
        let owner = h.login_from(ip, "anna", "secret", "123456").await.unwrap();
        let guest = h.login_from(ip, "bob", "hunter2", "654321").await.unwrap();
        let users = || async { h.b.list_hosts(ip, &owner).await.unwrap().hosts[0].connected_users.clone() };
        assert_eq!(h.b.presence(ip, &owner, WS1, CONNECTION_A, 1, true).await, Err(ApiError::NoLease));
        for token in [&owner, &guest] {
            h.b.connect(ip, token, WS1, "remote.example.org").await.unwrap();
        }
        assert!(users().await.is_empty(), "a prepared transport is not a connected person");
        h.b.presence(ip, &owner, WS1, CONNECTION_A, 1, true).await.unwrap();
        h.b.presence(ip, &owner, WS1, CONNECTION_B, 1, true).await.unwrap();
        h.b.presence(ip, &guest, WS1, CONNECTION_A, 1, true).await.unwrap();
        assert_eq!(users().await, vec!["anna", "bob"]);
        assert_eq!(h.b.list_hosts(ip, &guest).await.unwrap().hosts.len(), 1, "names do not extend host access");
        assert_eq!(h.b.presence(ip, &guest, WS2, CONNECTION_B, 1, true).await, Err(ApiError::Denied));
        assert_eq!(
            h.b.presence(IP3, &owner, WS1, "33333333333333333333333333333333", 1, true).await,
            Err(ApiError::NoLease)
        );
        h.b.presence(ip, &owner, WS1, CONNECTION_A, 3, false).await.unwrap();
        h.b.presence(ip, &owner, WS1, CONNECTION_A, 2, true).await.unwrap();
        assert_eq!(users().await, vec!["anna", "bob"], "the owner's other stream remains connected");
        h.b.presence(ip, &owner, WS1, CONNECTION_B, 2, false).await.unwrap();
        assert_eq!(users().await, vec!["bob"]);
        h.b.logout(&guest).await.unwrap();
        assert!(users().await.is_empty());
    }
}

#[tokio::test]
async fn presence_expires_without_heartbeats_even_when_dashboard_refreshes() {
    let h = harness();
    let token = h.login().await;
    h.b.connect(IP, &token, WS1, "remote.example.org").await.unwrap();
    h.b.presence(IP, &token, WS1, CONNECTION_A, 1, true).await.unwrap();
    for _ in 0..3 {
        h.clock.advance(Duration::from_secs(19));
        assert_eq!(h.b.list_hosts(IP, &token).await.unwrap().hosts[0].connected_users, vec!["anna"]);
    }
    h.clock.advance(Duration::from_secs(3));
    assert!(h.b.list_hosts(IP, &token).await.unwrap().hosts[0].connected_users.is_empty());
    // Stop may arrive before the first heartbeat. Later packets never revive it.
    h.b.presence(IP, &token, WS1, CONNECTION_B, 2, false).await.unwrap();
    h.b.presence(IP, &token, WS1, CONNECTION_B, 1, true).await.unwrap();
    h.b.presence(IP, &token, WS1, CONNECTION_B, 3, true).await.unwrap();
    assert!(h.b.list_hosts(IP, &token).await.unwrap().hosts[0].connected_users.is_empty());
    assert_eq!(h.b.presence(IP, &token, WS1, "bad", 1, true).await, Err(ApiError::BadRequest));
    assert_eq!(h.b.presence(IP, &token, WS1, CONNECTION_A, 0, true).await, Err(ApiError::BadRequest));
}

#[tokio::test]
async fn presence_heartbeat_extends_only_its_stream_and_hides_untrusted_hosts() {
    let h = harness();
    let token = h.login().await;
    let guest = h.login_from(IP, "bob", "hunter2", "654321").await.unwrap();
    for t in [&token, &guest] {
        h.b.connect(IP, t, WS1, "remote.example.org").await.unwrap();
        h.b.presence(IP, t, WS1, CONNECTION_A, 1, true).await.unwrap();
    }
    for sequence in 2..=5 {
        h.clock.advance(Duration::from_secs(20));
        h.b.list_hosts(IP, &token).await.unwrap(); // Refreshes the owner's grant, not presence.
        h.b.presence(IP, &token, WS1, CONNECTION_A, sequence, true).await.unwrap();
    }
    assert_eq!(h.b.list_hosts(IP, &token).await.unwrap().hosts[0].connected_users, vec!["anna"]);
    h.prober.certs.lock().unwrap().insert(WS1.into(), None);
    h.b.probe_all().await;
    assert!(h.b.list_hosts(IP, &token).await.unwrap().hosts[0].connected_users.is_empty());
    h.prober.certs.lock().unwrap().insert(WS1.into(), Some([9u8; 32]));
    h.b.probe_all().await;
    let host = &h.b.list_hosts(IP, &token).await.unwrap().hosts[0];
    assert_eq!(host.reason.as_deref(), Some("certificate changed"));
    assert!(host.connected_users.is_empty());
}

#[tokio::test]
async fn presence_http_requires_authentication_and_rejects_client_supplied_names() {
    let h = harness();
    let token = h.login().await;
    h.b.connect(IP, &token, WS1, "remote.example.org").await.unwrap();
    let app = crate::api::router(h.b.clone());
    for (auth, body, status) in [
        (
            "garbage",
            serde_json::json!({"connection_id": CONNECTION_A, "sequence":1, "connected":true}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            token.as_str(),
            serde_json::json!({"connection_id": CONNECTION_A, "sequence":1, "connected":true, "username":"someone"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            token.as_str(),
            serde_json::json!({"connection_id": CONNECTION_A, "sequence":1, "connected":true}),
            StatusCode::OK,
        ),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/hosts/{WS1}/presence"))
            .header("authorization", format!("Bearer {auth}"))
            .extension(ConnectInfo(SocketAddr::new(IP, 12345)))
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(app.clone().oneshot(request).await.unwrap().status(), status);
    }
    assert_eq!(h.b.list_hosts(IP, &token).await.unwrap().hosts[0].connected_users, vec!["anna"]);
}

#[tokio::test]
async fn offline_policy_denied_and_unassigned_hosts() {
    let mut k = FakeKerberos::new(&[("anna", "secret123456")]);
    k.policy_denied_hosts = vec![WS2.into()];
    let h = harness_with(k);
    let t = h.login().await;
    h.prober.certs.lock().unwrap().insert(WS1.into(), None);
    let hosts = h.b.list_hosts(IP, &t).await.unwrap().hosts;
    assert_eq!(hosts[0].reason.as_deref(), Some("offline"));
    assert!(!hosts[0].online && !hosts[0].connectable);
    assert_eq!(h.b.connect(IP, &t, WS1, "e").await.unwrap_err(), ApiError::Unavailable("offline"));
    // KDC refuses the service ticket (e.g. password-only TGT, auth-ind=otp).
    assert_eq!(h.b.connect(IP, &t, WS2, "e").await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.b.lease_count(), 0);
    assert!(h.relay_calls().is_empty());
    // Not assigned / not a remote host.
    assert_eq!(h.b.connect(IP, &t, "ws3.example.org", "e").await.unwrap_err(), ApiError::Denied);
    let tb = h.login_from(IP2, "bob", "x", "000000").await;
    assert!(tb.is_err());
    assert_eq!(h.audit.count("connect_denied"), 2);
}

#[tokio::test]
async fn connect_reprobes_cached_offline_host_after_desktop_handoff() {
    let h = harness_cfg(FakeKerberos::new(&[("anna", "secret123456")]), direct_lan);
    let token = h.login_from(LAN, "anna", "secret", "123456").await.unwrap();
    h.b.probe_all().await; // Pin the original host certificate.
    h.prober.certs.lock().unwrap().insert(WS1.into(), None);
    h.b.probe_all().await; // Cache the brief handoff outage.
    h.prober.certs.lock().unwrap().insert(WS1.into(), Some([1u8; 32]));

    let reply = h.b.connect(LAN, &token, WS1, "e").await.unwrap();
    assert_eq!(reply.route, "direct");
    assert_eq!(reply.host_cert_sha256, hex::encode([1u8; 32]));
    assert_eq!(h.pins.get(WS1), Some(hex::encode([1u8; 32])));
    assert_eq!(h.b.direct_count(), 1);
}

#[tokio::test]
async fn bearer_is_required_and_hashed() {
    let h = harness();
    let t = h.login().await;
    assert_eq!(h.b.list_hosts(IP, "garbage").await.unwrap_err(), ApiError::Unauthorized);
    assert!(h.b.list_hosts(IP2, &t).await.is_ok(), "sessions roam; leases do not");
    let events = serde_json::to_string(&h.audit.events()).unwrap();
    assert!(!events.contains(&t), "token never logged");
    assert!(!events.contains("secret"), "password never logged");
}

// ------------------------------------------------------------------ direct route

#[tokio::test]
async fn lan_client_gets_the_host_directly_without_a_lease() {
    let h = harness_direct();
    let t = h.login_from(LAN, "anna", "secret", "123456").await.unwrap();
    let cr = h.b.connect(LAN, &t, WS1, "remote.example.org").await.unwrap();
    let j = serde_json::to_value(&cr).unwrap();
    assert_eq!(j["route"], "direct");
    assert_eq!(j["endpoint"], "192.0.2.11", "the host's own address, not the broker name");
    assert_eq!(j["port"], 28989);
    assert_eq!(j["host_cert_sha256"], hex::encode([1u8; 32]));
    assert_eq!(j["expires_in"], 30);
    assert!(!cr.gssapi_token.is_empty(), "single sign-on still goes through the KDC");
    assert!(h.relay_calls().is_empty(), "nothing is opened on the relay");
    assert_eq!(h.b.lease_count(), 0);
    assert_eq!(h.b.direct_count(), 1);
    let ev = h.audit.events();
    let c = ev.iter().find(|e| e["event"] == "connect").unwrap();
    assert_eq!(c["route"], "direct");
    assert_eq!(c["target"], "192.0.2.11");

    // Reconnecting replaces the grant rather than piling them up.
    h.b.connect(LAN, &t, WS1, "remote.example.org").await.unwrap();
    assert_eq!(h.b.direct_count(), 1);

    // The same session from outside is relayed as before.
    let cr = h.b.connect(IP, &t, WS1, "remote.example.org").await.unwrap();
    assert_eq!((cr.route, cr.endpoint.as_str(), cr.port), ("relay", "remote.example.org", 29001));
    assert_eq!(h.b.lease_count(), 1);
}

#[tokio::test]
async fn direct_route_is_off_by_default() {
    let h = harness();
    let t = h.login_from(LAN, "anna", "secret", "123456").await.unwrap();
    let cr = h.b.connect(LAN, &t, WS1, "remote.example.org").await.unwrap();
    assert_eq!((cr.route, cr.port), ("relay", 29001));
    assert_eq!(h.b.direct_count(), 0);
}

#[tokio::test]
async fn direct_grant_keepalive_reap_and_logout() {
    let h = harness_direct();
    let t = h.login_from(LAN, "anna", "secret", "123456").await.unwrap();
    assert_eq!(h.b.keepalive(LAN, &t, WS1).await.unwrap_err(), ApiError::NoLease, "no grant yet");
    h.b.connect(LAN, &t, WS1, "e").await.unwrap();
    // Like a relay lease, the grant starts at 30 s: the first keepalive comes early.
    h.clock.advance(Duration::from_secs(20));
    assert_eq!(h.b.keepalive(LAN, &t, WS1).await.unwrap().expires_in, 90);
    // A long stream: keepalives every 60 s keep the grant and the broker session going
    // well past the 1 h idle limit.
    for _ in 0..70 {
        h.clock.advance(Duration::from_secs(60));
        assert_eq!(h.b.keepalive(LAN, &t, WS1).await.unwrap().expires_in, 90);
        h.b.reap().await;
    }
    assert_eq!(h.b.direct_count(), 1);
    assert!(h.relay_calls().is_empty());
    // Other hosts, other addresses: no grant.
    assert_eq!(h.b.keepalive(LAN, &t, WS2).await.unwrap_err(), ApiError::NoLease);
    assert_eq!(h.b.keepalive(IP, &t, WS1).await.unwrap_err(), ApiError::NoLease);
    // Listing refreshes the grant too.
    h.clock.advance(Duration::from_secs(80));
    h.b.list_hosts(LAN, &t).await.unwrap();
    h.clock.advance(Duration::from_secs(80));
    h.b.reap().await;
    assert_eq!(h.b.direct_count(), 1);
    // Keepalive stops: the grant lapses (nothing to close on the relay).
    h.clock.advance(Duration::from_secs(91));
    h.b.reap().await;
    assert_eq!(h.b.direct_count(), 0);
    assert_eq!(h.b.keepalive(LAN, &t, WS1).await.unwrap_err(), ApiError::NoLease);
    assert!(h.relay_calls().is_empty());
    // Logout drops grants.
    h.b.connect(LAN, &t, WS1, "e").await.unwrap();
    h.b.logout(&t).await.unwrap();
    assert_eq!(h.b.direct_count(), 0);
    assert_eq!(h.b.keepalive(LAN, &t, WS1).await.unwrap_err(), ApiError::Unauthorized);
}

#[tokio::test]
async fn direct_route_keeps_every_admission_check() {
    let mut k = FakeKerberos::new(&[("anna", "secret123456")]);
    k.policy_denied_hosts = vec![WS2.into()];
    let h = harness_cfg(k, direct_lan);
    let t = h.login_from(LAN, "anna", "secret", "123456").await.unwrap();
    h.b.probe_all().await; // TOFU-pin ws1/ws2
                           // KDC refuses the service ticket (password-only TGT): no direct answer either.
    assert_eq!(h.b.connect(LAN, &t, WS2, "e").await.unwrap_err(), ApiError::Denied);
    // Not assigned / not a remote host.
    assert_eq!(h.b.connect(LAN, &t, "ws3.example.org", "e").await.unwrap_err(), ApiError::Denied);
    // Offline.
    h.prober.certs.lock().unwrap().insert(WS1.into(), None);
    h.b.probe_all().await;
    assert_eq!(h.b.connect(LAN, &t, WS1, "e").await.unwrap_err(), ApiError::Unavailable("offline"));
    // Certificate changed.
    h.prober.certs.lock().unwrap().insert(WS1.into(), Some([9u8; 32]));
    h.b.probe_all().await;
    assert_eq!(h.b.connect(LAN, &t, WS1, "e").await.unwrap_err(), ApiError::Unavailable("certificate changed"));
    assert_eq!(h.b.direct_count(), 0);
    assert!(h.relay_calls().is_empty());
}

// ------------------------------------------------------------------ HTTP layer

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: &str,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(uri).header("host", "remote.example.org:29000");
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let mut req = req.body(Body::from(body.to_string())).unwrap();
    req.extensions_mut().insert(ConnectInfo(std::net::SocketAddr::from(([203, 0, 113, 7], 50000))));
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn http_contract() {
    let h = harness();
    let app = crate::api::router(h.b.clone());
    let (s, hd, j) = call(&app, "POST", "/v1/auth/start", None, r#"{"username":"anna"}"#).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hd["cache-control"], "no-store");
    let conv = j["conversation_id"].as_str().unwrap().to_string();
    let (s, _, j) = call(
        &app,
        "POST",
        "/v1/auth/respond",
        None,
        &format!(r#"{{"conversation_id":"{conv}","responses":["bad","123456"]}}"#),
    )
    .await;
    assert_eq!((s, j), (StatusCode::OK, serde_json::json!({"state":"denied"})));
    let (s, _, j) = call(&app, "POST", "/v1/auth/respond", None, "not json").await;
    assert_eq!((s, j), (StatusCode::OK, serde_json::json!({"state":"denied"})));

    let (_, _, j) = call(&app, "POST", "/v1/auth/start", None, r#"{"username":"anna"}"#).await;
    let conv = j["conversation_id"].as_str().unwrap().to_string();
    let (s, _, j) = call(
        &app,
        "POST",
        "/v1/auth/respond",
        None,
        &format!(r#"{{"conversation_id":"{conv}","responses":["secret","123456"]}}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let tok = j["session_token"].as_str().unwrap().to_string();

    let (s, hd, j) = call(&app, "GET", "/v1/hosts", None, "").await;
    assert_eq!((s, j), (StatusCode::UNAUTHORIZED, serde_json::json!({"state":"denied"})));
    assert_eq!(hd["cache-control"], "no-store");
    let (s, _, j) = call(&app, "GET", "/v1/hosts", Some(&tok), "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["hosts"].as_array().unwrap().len(), 2);
    let (s, _, j) = call(&app, "POST", &format!("/v1/hosts/{WS1}/connect"), Some(&tok), "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["endpoint"], "remote.example.org", "Host header without port");
    assert_eq!(j["route"], "relay");
    let (s, _, j) = call(&app, "POST", &format!("/v1/hosts/{WS1}/keepalive"), Some(&tok), "").await;
    assert_eq!((s, j["state"].clone()), (StatusCode::OK, "ok".into()));
    let (s, _, j) = call(&app, "POST", "/v1/logout", Some(&tok), "").await;
    assert_eq!((s, j), (StatusCode::OK, serde_json::json!({"state":"logged_out"})));

    // Rate limit shape (start budget: 2 used above + 3).
    for _ in 0..3 {
        call(&app, "POST", "/v1/auth/start", None, r#"{"username":"anna"}"#).await;
    }
    let (s, hd, j) = call(&app, "POST", "/v1/auth/start", None, r#"{"username":"anna"}"#).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(j["state"], "denied");
    assert!(j["retry_after"].as_u64().unwrap() > 0);
    assert!(hd.contains_key("retry-after"));
    let (s, _, _) = call(&app, "GET", "/nope", None, "").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[test]
fn spki_hash_of_pem() {
    // Self-signed P-256 test certificate (reserved example name).
    let pem = include_bytes!("../testdata/broker-test.pem");
    let h = crate::spki_sha256_hex(pem).unwrap();
    assert_eq!(h.len(), 64);
    assert_eq!(h, include_str!("../testdata/broker-test.spki").trim());
}

// ------------------------------------------------------------------ passkeys

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::broker::Method;
use crate::kerberos::fake_passkey_signature;
use crate::passkey::Assertion;

const CRED: [u8; 32] = [0xc5; 32];
const RP: &str = "ipa.example.org";

/// anna has a passkey (no OTP), bob has password + OTP.
fn harness_passkey(tweak: impl FnOnce(&mut Config)) -> H {
    let k = FakeKerberos::new(&[("bob", "hunter2654321")]).with_passkey("anna", &CRED);
    harness_cfg(k, |c| {
        c.passkey.rp_id = Some(RP.into());
        tweak(c)
    })
}

/// What the Mac helper does: authData = SHA-256(rp) ‖ UP|UV ‖ counter, signature over
/// authData ‖ raw challenge (fake signature scheme of `FakeKerberos`).
fn sign(prompt: &serde_json::Value) -> Assertion {
    let p = &prompt["passkey"];
    let mut ad = crate::util::sha256(p["rp_id"].as_str().unwrap().as_bytes()).to_vec();
    ad.extend([0x05, 0, 0, 0, 1]);
    let ch = B64.decode(p["challenge"].as_str().unwrap()).unwrap();
    Assertion {
        credential_id: B64.decode(p["credential_ids"][0].as_str().unwrap()).unwrap(),
        signature: fake_passkey_signature(&ad, &ch),
        authenticator_data: ad,
    }
}

impl H {
    async fn passkey_start(&self, ip: IpAddr, user: &str) -> (String, serde_json::Value) {
        let c = self.b.auth_start_passkey(ip, user).await.unwrap();
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["state"], "challenge");
        (c.conversation_id, j["prompts"][0].clone())
    }

    async fn passkey_login(&self, ip: IpAddr, user: &str) -> Result<String, ApiError> {
        let (id, prompt) = self.passkey_start(ip, user).await;
        self.b.auth_respond_passkey(ip, &id, Some(sign(&prompt))).await.map(|r| r.session_token)
    }

    /// Worker threads exit asynchronously; wait until `n` are left.
    async fn workers_settle(&self, n: usize) {
        for _ in 0..400 {
            if self.b.passkey_worker_count() == n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("{} passkey workers left, expected {n}", self.b.passkey_worker_count());
    }

    fn fails(&self) -> Vec<serde_json::Value> {
        self.audit.events().into_iter().filter(|e| e["event"] == "login_fail").collect()
    }
}

#[tokio::test]
async fn passkey_happy_path() {
    let h = harness_passkey(|_| {});
    let (id, prompt) = h.passkey_start(IP, "Anna").await;
    assert_eq!(prompt["id"], "passkey");
    assert_eq!(prompt["style"], "passkey");
    assert_eq!(prompt["text"], "Passkey");
    let p = &prompt["passkey"];
    assert_eq!(p["rp_id"], RP);
    assert_eq!(p["credential_ids"], serde_json::json!([B64.encode(CRED)]));
    assert_eq!(p["user_verification"], true);
    assert_eq!(B64.decode(p["challenge"].as_str().unwrap()).unwrap().len(), 32);
    assert_eq!(h.b.passkey_worker_count(), 1, "exchange parked in the responder");

    let a = sign(&prompt);
    let r = h.b.auth_respond_passkey(IP, &id, Some(a.clone())).await.unwrap();
    assert_eq!(r.username, "anna");
    assert_eq!(r.expires_in, 36000);
    assert_eq!(h.krb.passkey_logins(), 1);
    assert_eq!(h.krb.logins(), 0, "no password exchange");
    let ok = h.audit.events().into_iter().find(|e| e["event"] == "login_ok").unwrap();
    assert_eq!(ok["method"], "passkey");
    h.workers_settle(0).await;

    // The session is a normal one.
    assert_eq!(h.b.list_hosts(IP, &r.session_token).await.unwrap().hosts.len(), 2);
    assert!(h.b.connect(IP, &r.session_token, WS1, "e").await.is_ok());

    // A conversation is single-use.
    assert_eq!(h.b.auth_respond_passkey(IP, &id, Some(a.clone())).await.unwrap_err(), ApiError::Denied);

    // Assertion material never reaches the audit trail.
    let events = serde_json::to_string(&h.audit.events()).unwrap();
    for secret in [B64.encode(&a.signature), B64.encode(&a.authenticator_data), p["challenge"].to_string()] {
        assert!(!events.contains(secret.trim_matches('"')), "assertion material logged");
    }
}

#[tokio::test]
async fn passkey_wrong_and_missing_fields() {
    let h = harness_passkey(|_| {});
    let ip = |n: u8| IpAddr::V4(Ipv4Addr::new(198, 51, 100, n));

    // Bad signature: the KDC refuses.
    let (id, prompt) = h.passkey_start(ip(1), "anna").await;
    let mut a = sign(&prompt);
    a.signature[0] ^= 1;
    assert_eq!(h.b.auth_respond_passkey(ip(1), &id, Some(a)).await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.fails().last().unwrap()["reason"], "credentials");
    assert_eq!(h.fails().last().unwrap()["method"], "passkey");

    // Assertion for another challenge (stale signature).
    let (_, old) = h.passkey_start(ip(2), "anna").await;
    let (id, _) = h.passkey_start(ip(2), "anna").await;
    assert_eq!(h.b.auth_respond_passkey(ip(2), &id, Some(sign(&old))).await.unwrap_err(), ApiError::Denied);

    // Credential the KDC did not offer: refused before the KDC is answered.
    let (id, prompt) = h.passkey_start(ip(3), "anna").await;
    let a = Assertion { credential_id: vec![1u8; 32], ..sign(&prompt) };
    assert_eq!(h.b.auth_respond_passkey(ip(3), &id, Some(a)).await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.fails().last().unwrap()["reason"], "credential");

    // Fields that failed validation.
    let (id, _) = h.passkey_start(ip(4), "anna").await;
    assert_eq!(h.b.auth_respond_passkey(ip(4), &id, None).await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.fails().last().unwrap()["reason"], "malformed");

    // Wrong source address.
    let (id, prompt) = h.passkey_start(ip(5), "anna").await;
    assert_eq!(h.b.auth_respond_passkey(ip(6), &id, Some(sign(&prompt))).await.unwrap_err(), ApiError::Denied);

    // Method mismatch in both directions consumes the conversation.
    let (id, prompt) = h.passkey_start(ip(7), "anna").await;
    assert_eq!(h.b.auth_respond(ip(7), &id, z(&["secret", "123456"])).await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.b.auth_respond_passkey(ip(7), &id, Some(sign(&prompt))).await.unwrap_err(), ApiError::Denied);
    let c = h.b.auth_start(ip(8), "anna").unwrap();
    assert_eq!(
        h.b.auth_respond_passkey(ip(8), &c.conversation_id, Some(sign(&prompt))).await.unwrap_err(),
        ApiError::Denied
    );
    assert_eq!(h.b.auth_respond_passkey(ip(8), "nope", Some(sign(&prompt))).await.unwrap_err(), ApiError::Denied);

    h.workers_settle(1).await; // `old` is still waiting for its answer
    assert_eq!(h.krb.passkey_logins(), 7);
    assert_eq!(h.audit.count("login_ok"), 0);
}

#[tokio::test]
async fn passkey_http_contract_and_validation() {
    let h = harness_passkey(|c| c.limits.starts_per_minute_per_ip = 100);
    let app = crate::api::router(h.b.clone());
    let start = |m: &str| format!(r#"{{"username":"anna","method":"{m}"}}"#);
    let (s, hd, j) = call(&app, "POST", "/v1/auth/start", None, &start("passkey")).await;
    assert_eq!((s, &hd["cache-control"]), (StatusCode::OK, &"no-store".parse::<axum::http::HeaderValue>().unwrap()));
    let keys: Vec<&str> = j["prompts"][0]["passkey"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["challenge", "credential_ids", "rp_id", "user_verification"]);
    let conv = j["conversation_id"].as_str().unwrap().to_string();
    let a = sign(&j["prompts"][0]);
    let body = |conv: &str, cred: &str, ad: &str, sig: &str| {
        format!(
            r#"{{"conversation_id":"{conv}","passkey":{{"credential_id":"{cred}","authenticator_data":"{ad}","signature":"{sig}"}}}}"#
        )
    };
    let (cred, ad, sig) = (B64.encode(&a.credential_id), B64.encode(&a.authenticator_data), B64.encode(&a.signature));
    let denied = serde_json::json!({"state":"denied"});

    // Shapes that never reach a conversation.
    for bad in [
        format!(r#"{{"conversation_id":"{conv}"}}"#),
        format!(
            r#"{{"conversation_id":"{conv}","responses":["x","123456"],"passkey":{{"credential_id":"{cred}","authenticator_data":"{ad}","signature":"{sig}"}}}}"#
        ),
        format!(r#"{{"conversation_id":"{conv}","passkey":{{"credential_id":"{cred}","authenticator_data":"{ad}"}}}}"#),
        format!(
            r#"{{"conversation_id":"{conv}","passkey":{{"credential_id":"{cred}","authenticator_data":"{ad}","signature":"{sig}","extra":1}}}}"#
        ),
    ] {
        let (s, _, j) = call(&app, "POST", "/v1/auth/respond", None, &bad).await;
        assert_eq!((s, &j), (StatusCode::OK, &denied));
    }
    // Field validation (each consumes a fresh conversation).
    let long = B64.encode([1u8; 1025]);
    let short_ad = B64.encode([1u8; 36]);
    let long_sig = B64.encode([1u8; 257]);
    for (c, a2, s2) in [
        ("not base64!", ad.as_str(), sig.as_str()),
        (long.as_str(), ad.as_str(), sig.as_str()),
        (cred.as_str(), short_ad.as_str(), sig.as_str()),
        (cred.as_str(), long.as_str(), sig.as_str()),
        (cred.as_str(), ad.as_str(), long_sig.as_str()),
        (cred.as_str(), ad.as_str(), ""),
    ] {
        h.clock.advance(Duration::from_secs(1000)); // clear the per-user failure block
        let (_, _, j) = call(&app, "POST", "/v1/auth/start", None, &start("passkey")).await;
        let conv = j["conversation_id"].as_str().unwrap();
        let (s, _, j) = call(&app, "POST", "/v1/auth/respond", None, &body(conv, c, a2, s2)).await;
        assert_eq!((s, &j), (StatusCode::OK, &denied));
        assert_eq!(h.fails().last().unwrap()["reason"], "malformed");
    }
    // Unknown method.
    let (s, _, j) = call(&app, "POST", "/v1/auth/start", None, &start("webauthn")).await;
    assert_eq!((s, &j), (StatusCode::OK, &denied));

    // The real thing over HTTP.
    h.clock.advance(Duration::from_secs(1000));
    let (_, _, j) = call(&app, "POST", "/v1/auth/start", None, &start("passkey")).await;
    let conv = j["conversation_id"].as_str().unwrap().to_string();
    let a = sign(&j["prompts"][0]);
    let unpadded = |b: &[u8]| B64.encode(b).trim_end_matches('=').to_string();
    let (s, _, j) = call(
        &app,
        "POST",
        "/v1/auth/respond",
        None,
        &body(&conv, &unpadded(&a.credential_id), &unpadded(&a.authenticator_data), &unpadded(&a.signature)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["state"], "authenticated");
    assert_eq!(j["username"], "anna");
    h.workers_settle(1).await; // the first conversation was never answered
}

#[tokio::test]
async fn passkey_conversation_expiry_releases_the_worker() {
    let h = harness_passkey(|_| {});
    let (id, prompt) = h.passkey_start(IP, "anna").await;
    assert_eq!(h.b.passkey_worker_count(), 1);
    h.clock.advance(Duration::from_secs(121));
    assert_eq!(h.b.auth_respond_passkey(IP, &id, Some(sign(&prompt))).await.unwrap_err(), ApiError::Denied);
    h.workers_settle(0).await;
    assert_eq!(h.fails().last().unwrap()["reason"], "conversation");
    assert_eq!(h.audit.count("login_ok"), 0);

    // The reaper drops expired conversations without a request.
    let (_id, _) = h.passkey_start(IP2, "anna").await;
    assert_eq!(h.b.passkey_worker_count(), 1);
    h.clock.advance(Duration::from_secs(121));
    h.b.reap().await;
    h.workers_settle(0).await;
}

#[tokio::test]
async fn passkey_pending_cap_is_user_independent() {
    let h = harness_passkey(|c| c.passkey.max_pending = 2);
    let (id, prompt) = h.passkey_start(IP, "anna").await;
    let _ = h.passkey_start(IP2, "nobody").await;
    // Full: a real passkey user and an unknown user get the same 429.
    for user in ["anna", "nobody", "bob"] {
        assert_eq!(h.b.auth_start_passkey(IP3, user).await.unwrap_err(), ApiError::RateLimited(10));
    }
    // Password logins are not affected by the passkey cap.
    assert!(h.login_from(IP3, "bob", "hunter2", "654321").await.is_ok());
    // HTTP shape.
    let app = crate::api::router(h.b.clone());
    let (s, hd, j) = call(&app, "POST", "/v1/auth/start", None, r#"{"username":"anna","method":"passkey"}"#).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(j, serde_json::json!({"state":"denied","retry_after":10}));
    assert!(hd.contains_key("retry-after"));
    // Finishing one frees a slot.
    h.b.auth_respond_passkey(IP, &id, Some(sign(&prompt))).await.unwrap();
    assert!(h.b.auth_start_passkey(LAN, "anna").await.is_ok());
    // Expiry frees them all.
    h.clock.advance(Duration::from_secs(121));
    assert!(h.b.auth_start_passkey(IP2, "anna").await.is_ok());
}

#[tokio::test]
async fn synthetic_challenge_has_the_real_shape() {
    let mut k = FakeKerberos::new(&[("bob", "hunter2654321")]).with_passkey("anna", &CRED);
    k.passkey_domain = RP.into();
    let h = harness_cfg(k, |c| {
        c.passkey.rp_id = Some(RP.into());
        c.limits.starts_per_minute_per_ip = 100;
    });
    let (_, real) = h.passkey_start(IP, "anna").await;
    // Shape: key set, types, lengths.
    fn shape(p: &serde_json::Value) -> serde_json::Value {
        let pk = &p["passkey"];
        let lens: Vec<usize> = pk["credential_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| B64.decode(c.as_str().unwrap()).unwrap().len())
            .collect();
        serde_json::json!({
            "keys": p.as_object().unwrap().keys().collect::<Vec<_>>(),
            "pk_keys": pk.as_object().unwrap().keys().collect::<Vec<_>>(),
            "id": p["id"], "style": p["style"], "text": p["text"],
            "rp_id": pk["rp_id"], "uv": pk["user_verification"],
            "cred_lens": lens,
            "cred_b64_len": pk["credential_ids"][0].as_str().unwrap().len(),
            "challenge_len": B64.decode(pk["challenge"].as_str().unwrap()).unwrap().len(),
            "challenge_b64_len": pk["challenge"].as_str().unwrap().len(),
        })
    }
    let want = shape(&real);
    // Unknown user, password+OTP user, name the KDC never sees.
    for (i, user) in ["nobody", "bob", "host/evil@EXAMPLE.ORG"].iter().enumerate() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40 + i as u8));
        let (id, p) = h.passkey_start(ip, user).await;
        assert_eq!(shape(&p), want, "{user}");
        assert_ne!(p["passkey"]["challenge"], real["passkey"]["challenge"]);
        // Answering it (even "correctly") is denied like a wrong signature.
        assert_eq!(h.b.auth_respond_passkey(ip, &id, Some(sign(&p))).await.unwrap_err(), ApiError::Denied);
    }
    assert_eq!(h.krb.passkey_logins(), 3, "invalid names never reach the KDC");
    let reasons: Vec<_> = h.fails().iter().map(|e| e["reason"].clone()).collect();
    assert_eq!(reasons, ["no_challenge", "no_challenge", "username"]);
    // A KDC outage is not visible either.
    let mut k = FakeKerberos::new(&[]).with_passkey("anna", &CRED);
    k.unavailable = true;
    let h2 = harness_cfg(k, |c| c.passkey.rp_id = Some(RP.into()));
    let (_, p) = h2.passkey_start(IP, "anna").await;
    assert_eq!(shape(&p), want);
    h.workers_settle(1).await; // only the real conversation holds a worker
}

#[tokio::test]
async fn otp_method_unaffected_by_passkeys() {
    let h = harness_passkey(|_| {});
    // Absent method and explicit password_otp are the same flow and prompts.
    let app = crate::api::router(h.b.clone());
    for body in [r#"{"username":"bob"}"#, r#"{"username":"bob","method":"password_otp"}"#] {
        let (s, _, j) = call(&app, "POST", "/v1/auth/start", None, body).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            j["prompts"],
            serde_json::json!([
                {"id":"password","style":"secret","text":"Password"},
                {"id":"otp","style":"otp","text":"Authenticator code"}
            ])
        );
        let conv = j["conversation_id"].as_str().unwrap();
        let (_, _, j) = call(
            &app,
            "POST",
            "/v1/auth/respond",
            None,
            &format!(r#"{{"conversation_id":"{conv}","responses":["hunter2","654321"]}}"#),
        )
        .await;
        assert_eq!(j["state"], "authenticated");
    }
    assert_eq!(h.krb.logins(), 2);
    assert_eq!(h.krb.passkey_logins(), 0, "the password path never runs a passkey exchange");
    let ok: Vec<_> = h.audit.events().into_iter().filter(|e| e["event"] == "login_ok").collect();
    assert!(ok.iter().all(|e| e["method"] == "password_otp"));
    // A passkey user on the password path is simply denied.
    assert_eq!(h.login_from(IP2, "anna", "secret", "123456").await, Err(ApiError::Denied));
    assert_eq!(h.fails().last().unwrap()["method"], "password_otp");
    // ...and gets in with the passkey.
    assert!(h.passkey_login(IP3, "anna").await.is_ok());
    assert_eq!(Method::parse(None), Some(Method::PasswordOtp));
    assert_eq!(Method::parse(Some("passkey")), Some(Method::Passkey));
    assert_eq!(Method::parse(Some("PASSKEY")), None);
}

// ------------------------------------------------------------------ device-bound sessions (§14)

mod device_sessions {
    use super::*;
    use crate::device::testkey::TestDevice;
    use crate::device::{proof_message, DeviceKey, DeviceProof};
    use crate::kerberos::LoginOptions;

    const T0: u64 = 1_800_000_000; // FakeClock::unix() at start
    const DAY: u64 = 86_400;

    /// KDC issuing 24 h tickets renewable for 90 days (the §14.4 IPA policy).
    fn kdc() -> FakeKerberos {
        let mut k = FakeKerberos::new(&[("anna", "secret123456"), ("bob", "hunter2654321")]);
        k.end_unix = T0 + DAY;
        k.renew_till_unix = T0 + 90 * DAY;
        k
    }

    fn device_key(d: &TestDevice) -> DeviceKey {
        DeviceKey::from_spki(&d.spki()).unwrap()
    }

    fn proof(d: &TestDevice, method: &str, path: &str, time: u64, token: &str, body: &[u8]) -> DeviceProof {
        let body_sha256 = crate::util::sha256(body);
        DeviceProof {
            method: method.into(),
            path: path.into(),
            time,
            signature: d.sign(&proof_message(method, path, time, token, &body_sha256)),
            body_sha256,
        }
    }

    fn hosts_bearer<'a>(d: &TestDevice, token: &'a str, time: u64) -> Bearer<'a> {
        Bearer { token, proof: Some(proof(d, "GET", "/v1/hosts", time, token, b"")) }
    }

    impl H {
        async fn bound_login(&self, d: &TestDevice) -> crate::broker::AuthenticatedReply {
            let c = self.b.auth_start_method(IP, "anna", Method::PasswordOtp, Some(device_key(d))).await.unwrap();
            self.b.auth_respond(IP, &c.conversation_id, z(&["secret", "123456"])).await.unwrap()
        }
        fn now(&self) -> u64 {
            crate::util::Clock::unix(&*self.clock)
        }
    }

    use crate::broker::Bearer;

    #[tokio::test]
    async fn diagnostics_require_a_valid_device_signature_over_the_actual_body() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("plank-bound-diagnostics-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let h = harness_cfg(kdc(), |cfg| {
            cfg.diagnostics = Some(crate::diagnostics::Config { directory: dir.clone(), enabled_until_unix: u64::MAX })
        });
        let d = TestDevice::new();
        let token = h.bound_login(&d).await.session_token;
        let body = diagnostic_report(1).to_string();
        let app = crate::api::router(h.b.clone());
        let request = |proof_body: &[u8], signed: bool| {
            let p = proof(&d, "POST", "/v1/diagnostics", h.now(), &token, proof_body);
            let mut r = Request::builder()
                .method("POST")
                .uri("/v1/diagnostics")
                .header("authorization", format!("Bearer {token}"));
            if signed {
                r = r
                    .header("x-plank-device-time", h.now().to_string())
                    .header("x-plank-device-proof", base64::engine::general_purpose::STANDARD.encode(p.signature));
            }
            r.body(Body::from(body.clone())).unwrap()
        };
        assert_eq!(
            app.clone().oneshot(request(body.as_bytes(), false)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(app.clone().oneshot(request(b"tampered", true)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(app.oneshot(request(body.as_bytes(), true)).await.unwrap().status(), StatusCode::ACCEPTED);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn support_diagnostics_keep_device_proofs_bound_to_method_path_and_body() {
        use std::os::unix::fs::PermissionsExt;
        let dir=std::env::temp_dir().join(format!("plank-bound-support-{}",rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
        let h=harness_cfg(kdc(),|cfg| cfg.diagnostics=Some(crate::diagnostics::Config{
            directory:dir.clone(),enabled_until_unix:u64::MAX}));
        let d=TestDevice::new(); let token=h.bound_login(&d).await.session_token;
        let app=crate::api::router(h.b.clone());
        for (method,path,body,expected) in [
            ("GET","/v1/diagnostics/support-request",String::new(),StatusCode::NO_CONTENT),
            ("POST","/v1/diagnostics/support",serde_json::json!({"schema":1,
                "request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","report":diagnostic_report(1),"log_tail":"renderer reset\n"}).to_string(),StatusCode::FORBIDDEN),
        ] {
            for correct in [false,true] {
                let signed_body=if correct {body.as_bytes()} else {b"wrong-body"};
                let signature=proof(&d,method,path,h.now(),&token,signed_body);
                let request=Request::builder().method(method).uri(path)
                    .header("authorization",format!("Bearer {token}"))
                    .header("x-plank-device-time",h.now().to_string())
                    .header("x-plank-device-proof",base64::engine::general_purpose::STANDARD.encode(signature.signature))
                    .body(Body::from(body.clone())).unwrap();
                assert_eq!(app.clone().oneshot(request).await.unwrap().status(),
                    if correct {expected} else {StatusCode::UNAUTHORIZED});
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn bound_login_is_renewable_persistent_and_long() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        let r = h.bound_login(&d).await;
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["device_bound"], true);
        assert_eq!(r.expires_in, 90 * DAY);
        let want = LoginOptions { renew_life_secs: Some(i32::MAX as u32), persistent: true };
        assert!(h.krb.log.lock().unwrap().iter().any(|l| l == &format!("login anna {want:?}")));
        let recs = h.sessions.load_all();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].username, "anna");
        assert!(recs[0].ccache.starts_with("FILE:"));
        assert_eq!(recs[0].device().unwrap(), device_key(&d));
        assert_eq!(recs[0].key, hex::encode(crate::util::sha256(r.session_token.as_bytes())));
        assert!(!serde_json::to_string(&recs[0]).unwrap().contains(&r.session_token), "token never stored");

        // Unbound logins are unchanged: 10 h, in-memory ticket, no record, no flag.
        let t = h.login_from(IP2, "bob", "hunter2", "654321").await.unwrap();
        let bob = h.krb.log.lock().unwrap().iter().any(|l| l == &format!("login bob {:?}", LoginOptions::default()));
        assert!(bob);
        assert_eq!(h.sessions.load_all().len(), 1);
        assert!(h.b.list_hosts(IP2, &t).await.is_ok(), "unbound sessions need no proof");
    }

    #[tokio::test]
    async fn bound_session_needs_a_fresh_unreplayed_proof() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        let t = h.bound_login(&d).await.session_token;
        let now = h.now();
        // The token alone is useless.
        assert_eq!(h.b.list_hosts(IP, &t).await.unwrap_err(), ApiError::Unauthorized);
        let good = hosts_bearer(&d, &t, now);
        assert!(h.b.list_hosts(IP, good.clone()).await.is_ok());
        assert_eq!(h.b.list_hosts(IP, good).await.unwrap_err(), ApiError::Unauthorized, "replay");
        // Stale / future times, a proof for another path, another key, another token.
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &t, now - 61)).await.is_err());
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &t, now + 61)).await.is_err());
        let other_path = Bearer { token: &t, proof: Some(proof(&d, "POST", "/v1/logout", now, &t, b"{}")) };
        assert!(h.b.list_hosts(IP, other_path).await.is_err(), "path/method are signed (GET /v1/hosts expected)");
        assert!(h.b.list_hosts(IP, hosts_bearer(&TestDevice::new(), &t, now)).await.is_err());
        let mut wrong_token = hosts_bearer(&d, "another-token", now);
        wrong_token.token = &t;
        assert!(h.b.list_hosts(IP, wrong_token).await.is_err());
        // Failed proofs never end the session.
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &t, now + 1)).await.is_ok());
        // connect / keepalive / logout carry proofs over their own path and body.
        let path = format!("/v1/hosts/{WS1}/connect");
        let b = Bearer { token: &t, proof: Some(proof(&d, "POST", &path, now, &t, b"{}")) };
        assert!(h.b.connect(IP, b, WS1, "e").await.is_ok());
        let path = format!("/v1/hosts/{WS1}/keepalive");
        let b = Bearer { token: &t, proof: Some(proof(&d, "POST", &path, now, &t, b"{}")) };
        assert!(h.b.keepalive(IP, b, WS1).await.is_ok());
        let b = Bearer { token: &t, proof: Some(proof(&d, "POST", "/v1/logout", now, &t, b"{}")) };
        h.b.logout(b).await.unwrap();
        assert!(h.sessions.load_all().is_empty(), "logout removes the record");
    }

    #[tokio::test]
    async fn tgt_is_renewed_and_the_session_lives_ninety_days() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        let t = h.bound_login(&d).await.session_token;
        // The reaper renews an hour before each ticket end (renew_before 2 h); the KDC
        // extends by 24 h, capped at renew_till. Leave the client closed for over two months before resuming.
        let mut ticket_end = T0 + DAY;
        let mut last_use = T0;
        while ticket_end < T0 + 90 * DAY {
            h.clock.advance(Duration::from_secs(ticket_end - 3600 - h.now()));
            let next = (h.now() + DAY).min(T0 + 90 * DAY);
            *h.krb.renewed_end_unix.lock().unwrap() = next;
            h.b.reap().await;
            ticket_end = next;
            if h.now() - last_use >= 65 * DAY {
                let r = h.b.list_hosts(IP, hosts_bearer(&d, &t, h.now())).await;
                assert!(r.is_ok(), "{}: {:?}", (h.now() - T0) / DAY, r.err());
                last_use = h.now();
            }
        }
        assert!(h.krb.renewals() >= 88, "{} renewals", h.krb.renewals());
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &t, h.now())).await.is_ok(), "still alive before day 90");
        h.clock.advance(Duration::from_secs(DAY + 10));
        h.b.reap().await;
        assert_eq!(h.b.list_hosts(IP, hosts_bearer(&d, &t, h.now())).await.unwrap_err(), ApiError::Unauthorized);
        assert!(h.sessions.load_all().is_empty());
    }

    #[tokio::test]
    async fn configured_shorter_idle_limit_still_ends_the_session() {
        let h = harness_cfg(kdc(), |c| c.limits.device_session_idle_secs = 7 * DAY);
        let d = TestDevice::new();
        // Idle: renewed in the background, but nobody uses it for 7 days.
        let t = h.bound_login(&d).await.session_token;
        let mut ticket_end = T0 + DAY;
        while h.now() < T0 + 7 * DAY {
            h.clock.advance(Duration::from_secs(ticket_end - 3600 - h.now()));
            ticket_end = h.now() + DAY;
            *h.krb.renewed_end_unix.lock().unwrap() = ticket_end;
            h.b.reap().await;
        }
        h.b.reap().await;
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &t, h.now())).await.is_err());
        assert!(h.audit.events().iter().any(|e| e["event"] == "session_end" && e["reason"] == "idle"));
    }

    #[tokio::test]
    async fn refused_renewal_ends_the_session() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        let t = h.bound_login(&d).await.session_token;
        // Account disabled: the KDC refuses the renewal an hour before the ticket ends.
        *h.krb.renew_fails.lock().unwrap() = true;
        h.clock.advance(Duration::from_secs(DAY - 3600));
        h.b.reap().await;
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &t, h.now())).await.is_err());
        assert!(h.audit.events().iter().any(|e| e["event"] == "session_end" && e["reason"] == "renewal_refused"));
        assert!(h.sessions.load_all().is_empty());
        // An unreachable KDC only postpones renewal; the ticket end is the backstop.
        let h2 = harness_with(kdc());
        let t2 = h2.bound_login(&d).await.session_token;
        *h2.krb.renew_unavailable.lock().unwrap() = true;
        h2.clock.advance(Duration::from_secs(DAY - 3600));
        h2.b.reap().await;
        assert_eq!(h2.krb.renewals(), 1);
        assert!(h2.b.list_hosts(IP, hosts_bearer(&d, &t2, h2.now())).await.is_ok(), "postponed, still valid");
        h2.clock.advance(Duration::from_secs(3600));
        h2.b.reap().await;
        assert!(h2.b.list_hosts(IP, hosts_bearer(&d, &t2, h2.now())).await.is_err(), "ticket ran out");
    }

    #[tokio::test]
    async fn bound_sessions_survive_a_restart() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        let bound = h.bound_login(&d).await.session_token;
        let unbound = h.login_from(IP2, "bob", "hunter2", "654321").await.unwrap();
        h.b.shutdown().await;
        let destroyed = h.krb.destroyed.lock().unwrap().clone();
        assert_eq!(destroyed.len(), 1, "only the unbound ticket is destroyed: {destroyed:?}");
        assert!(destroyed[0].starts_with("MEMORY:"));

        h.clock.advance(Duration::from_secs(600));
        let b2 = h.restart();
        assert_eq!(b2.restore_sessions(), 1);
        assert!(b2.list_hosts(IP, hosts_bearer(&d, &bound, h.now())).await.is_ok());
        assert_eq!(b2.list_hosts(IP2, &unbound).await.unwrap_err(), ApiError::Unauthorized);
        // A record that expired while the broker was down is dropped on restore.
        b2.shutdown().await;
        h.clock.advance(Duration::from_secs(8 * DAY));
        let b3 = h.restart();
        assert_eq!(b3.restore_sessions(), 0);
        assert!(h.sessions.load_all().is_empty());
    }

    #[tokio::test]
    async fn passkey_login_binds_too() {
        let mut k = FakeKerberos::new(&[]).with_passkey("anna", &CRED);
        k.end_unix = T0 + DAY;
        k.renew_till_unix = T0 + 90 * DAY;
        let h = harness_cfg(k, |c| c.passkey.rp_id = Some(RP.into()));
        let d = TestDevice::new();
        let c = h.b.auth_start_method(IP, "anna", Method::Passkey, Some(device_key(&d))).await.unwrap();
        let prompt = serde_json::to_value(&c).unwrap()["prompts"][0].clone();
        let r = h.b.auth_respond_passkey(IP, &c.conversation_id, Some(sign(&prompt))).await.unwrap();
        assert!(r.device_bound);
        assert_eq!(r.expires_in, 90 * DAY);
        let want = LoginOptions { renew_life_secs: Some(i32::MAX as u32), persistent: true };
        assert!(h.krb.log.lock().unwrap().iter().any(|l| l == &format!("login_passkey anna {want:?}")));
        assert!(h.b.list_hosts(IP, &r.session_token).await.is_err());
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &r.session_token, h.now())).await.is_ok());
        h.workers_settle(0).await;
    }

    #[tokio::test]
    async fn newly_granted_user_is_not_signed_out_by_a_stale_directory_snapshot() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        h.dir.view.lock().unwrap().rules[0].enabled = false;
        h.b.probe_all().await; // Warm the shared snapshot before this user has access.
        h.dir.view.lock().unwrap().rules[0].enabled = true;
        let token = h.bound_login(&d).await.session_token;
        h.b.reap().await;
        assert_eq!(h.sessions.load_all().len(), 1, "a fresh grant must survive the first reaper");
        assert!(!h.b.list_hosts(IP, hosts_bearer(&d, &token, h.now())).await.unwrap().hosts.is_empty());
    }

    #[tokio::test]
    async fn never_expiry_survives_a_year_of_inactivity_and_restart() {
        let mut k = kdc();
        k.renew_till_unix = T0 + i32::MAX as u64;
        let h = harness_with(k);
        let d = TestDevice::new();
        let reply = h.bound_login(&d).await;
        assert_eq!(reply.expires_in, i32::MAX as u64, "only the credential horizon, no application timeout");
        let token = reply.session_token;
        let mut ticket_end = T0 + DAY;
        while h.now() < T0 + 366 * DAY {
            h.clock.advance(Duration::from_secs(ticket_end - 3600 - h.now()));
            ticket_end = h.now() + DAY;
            *h.krb.renewed_end_unix.lock().unwrap() = ticket_end;
            h.b.reap().await;
        }
        // No client request, app activity, or idle-clock bump for the whole year.
        h.b.shutdown().await;
        let restarted = h.restart();
        assert_eq!(restarted.restore_sessions(), 1);
        assert!(restarted.list_hosts(IP, hosts_bearer(&d, &token, h.now())).await.is_ok());
    }

    #[tokio::test]
    async fn a_finite_expiry_can_be_reenabled_later() {
        let mut k = kdc();
        k.renew_till_unix = T0 + i32::MAX as u64;
        let h = harness_cfg(k, |cfg| cfg.limits.device_session_absolute_secs = 90 * DAY);
        let reply = h.bound_login(&TestDevice::new()).await;
        assert_eq!(reply.expires_in, 90 * DAY);
        let want = LoginOptions { renew_life_secs: Some((90 * DAY) as u32), persistent: true };
        assert!(h.krb.log.lock().unwrap().iter().any(|entry| entry == &format!("login anna {want:?}")));
    }

    #[tokio::test]
    async fn kdc_can_grant_less_than_the_requested_maximum() {
        let mut k = kdc();
        k.renew_till_unix = T0 + 30 * DAY;
        let h = harness_with(k);
        assert_eq!(h.bound_login(&TestDevice::new()).await.expires_in, 30 * DAY);
    }

    #[tokio::test]
    async fn account_disable_or_delete_revokes_a_remembered_session() {
        for delete in [false, true] {
            let h = harness_with(kdc());
            let d = TestDevice::new();
            let token = h.bound_login(&d).await.session_token;
            assert!(h.b.list_hosts(IP, hosts_bearer(&d, &token, h.now())).await.is_ok());
            if delete {
                h.dir.users.lock().unwrap().remove("anna");
            } else {
                h.dir.users.lock().unwrap().get_mut("anna").unwrap().disabled = true;
            }
            h.clock.advance(Duration::from_secs(h.cfg.ldap.cache_ttl_secs));
            assert_eq!(h.b.list_hosts(IP, hosts_bearer(&d, &token, h.now())).await.unwrap_err(), ApiError::Unauthorized);
            assert!(h.sessions.load_all().is_empty());
            assert!(!h.krb.destroyed.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn removed_host_permission_ends_relay_and_direct_sessions() {
        for direct in [false, true] {
            let h = harness_cfg(kdc(), |cfg| { if direct { direct_lan(cfg); } });
            let d = TestDevice::new();
            let token = h.bound_login(&d).await.session_token;
            let ip = if direct { LAN } else { IP };
            let path = format!("/v1/hosts/{WS1}/connect");
            let bearer = Bearer { token: &token, proof: Some(proof(&d, "POST", &path, h.now(), &token, b"{}")) };
            h.b.connect(ip, bearer, WS1, "e").await.unwrap();
            // Keep the second host assigned: revoking one active host must still
            // remove its flows, even when the account has other permissions.
            h.dir.view.lock().unwrap().rules[0].member_hosts = vec![hostgroup("remote-nested")];
            h.clock.advance(Duration::from_secs(h.cfg.ldap.cache_ttl_secs));
            h.b.reap().await;
            assert!(h.sessions.load_all().is_empty());
            assert_eq!(h.b.list_hosts(ip, hosts_bearer(&d, &token, h.now())).await.unwrap_err(), ApiError::Unauthorized);
            if !direct {
                assert!(h.relay.calls.lock().unwrap().iter().any(|call| matches!(call, RelayRequest::Close { flush: true, .. })));
            }
        }
    }

    #[tokio::test]
    async fn keepalive_rechecks_permission_without_waiting_for_reaper() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        let token = h.bound_login(&d).await.session_token;
        h.dir.view.lock().unwrap().rules[0].enabled = false;
        let path = format!("/v1/hosts/{WS1}/keepalive");
        let bearer = Bearer { token: &token, proof: Some(proof(&d, "POST", &path, h.now(), &token, b"{}")) };
        assert_eq!(h.b.keepalive(IP, bearer, WS1).await.unwrap_err(), ApiError::Unauthorized);
        assert!(h.sessions.load_all().is_empty());
    }

    #[tokio::test]
    async fn directory_outage_denies_access_but_preserves_remembered_login() {
        let h = harness_with(kdc());
        let d = TestDevice::new();
        let token = h.bound_login(&d).await.session_token;
        h.b.list_hosts(IP, hosts_bearer(&d, &token, h.now())).await.unwrap();
        h.clock.advance(Duration::from_secs(h.cfg.ldap.cache_ttl_secs));
        *h.dir.unavailable.lock().unwrap() = true;
        h.b.reap().await;
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &token, h.now())).await.is_err());
        assert_eq!(h.sessions.load_all().len(), 1);
        *h.dir.unavailable.lock().unwrap() = false;
        assert!(h.b.list_hosts(IP, hosts_bearer(&d, &token, h.now())).await.is_ok());
    }

    #[tokio::test]
    async fn mac_admission_requires_mfa_and_fresh_device_proof() {
        let key = crate::mac_admission::tests::TestKey::new(WS1);
        let h = harness_cfg(kdc(), |cfg| { cfg.mac_admission = Some(key.config.clone()); });
        assert!(h.login_from(IP, "anna", "secret", "wrong").await.is_err());
        let d = TestDevice::new();
        let token = h.bound_login(&d).await.session_token;
        assert_eq!(h.b.connect(IP, &token, WS1, "e").await.unwrap_err(), ApiError::Unauthorized);
        let path = format!("/v1/hosts/{WS1}/connect");
        let bearer = Bearer { token: &token, proof: Some(proof(&d, "POST", &path, h.now(), &token, b"{}")) };
        let reply = h.b.connect(IP, bearer.clone(), WS1, "e").await.unwrap();
        assert_eq!(key.verify(reply.broker_token.as_ref().unwrap()).subject, "anna");
        assert_eq!(h.b.connect(IP, bearer, WS1, "e").await.unwrap_err(), ApiError::Unauthorized);
    }

    #[tokio::test]
    async fn http_device_key_and_proof_headers() {
        let h = harness_with(kdc());
        let app = crate::api::router(h.b.clone());
        let d = TestDevice::new();
        let spki = B64.encode(d.spki());
        // A malformed key is a generic denial.
        let (s, _, j) = call(&app, "POST", "/v1/auth/start", None, r#"{"username":"anna","device_key":"AAAA"}"#).await;
        assert_eq!((s, j), (StatusCode::OK, serde_json::json!({"state":"denied"})));
        let body = format!(r#"{{"username":"anna","device_key":"{spki}"}}"#);
        let (_, _, j) = call(&app, "POST", "/v1/auth/start", None, &body).await;
        let conv = j["conversation_id"].as_str().unwrap().to_string();
        let body = format!(r#"{{"conversation_id":"{conv}","responses":["secret","123456"]}}"#);
        let (_, _, j) = call(&app, "POST", "/v1/auth/respond", None, &body).await;
        assert_eq!(j["device_bound"], true);
        let tok = j["session_token"].as_str().unwrap().to_string();
        // No proof → 401; proof headers → 200.
        let (s, _, _) = call(&app, "GET", "/v1/hosts", Some(&tok), "").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let now = h.now();
        let sig = B64.encode(proof(&d, "GET", "/v1/hosts", now, &tok, b"").signature);
        let mut req = Request::builder()
            .method("GET")
            .uri("/v1/hosts")
            .header("host", "remote.example.org:29000")
            .header("authorization", format!("Bearer {tok}"))
            .header("x-plank-device-time", now.to_string())
            .header("x-plank-device-proof", sig)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(std::net::SocketAddr::from(([203, 0, 113, 7], 50000))));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Password-only clients keep the old shape: no device_bound field.
        let (_, _, j) = call(&app, "POST", "/v1/auth/start", None, r#"{"username":"bob"}"#).await;
        let conv = j["conversation_id"].as_str().unwrap().to_string();
        let body = format!(r#"{{"conversation_id":"{conv}","responses":["hunter2","654321"]}}"#);
        let (_, _, j) = call(&app, "POST", "/v1/auth/respond", None, &body).await;
        assert!(j.get("device_bound").is_none());
    }
}

pub(crate) fn diagnostic_report(id: usize) -> serde_json::Value {
    serde_json::json!({"schema":1,"report_id":format!("{id:032x}"),"version":"1.2.20-beta","platform":"windows","os_version":"11",
        "started_unix":1794211200u64,"duration_ms":1000,"outcome":"completed",
        "displays_end":[],"displays":[{"width":3840,"height":2160,"refresh_millihz":120000,"hdr_supported":null,"hdr_enabled":true,"bits_per_color":10}],
        "samples":[{"elapsed_ms":10,"fps_x100":6000,"video_kbps":150000,"rtt_ms":12,"received_age_ms":2,"statistics_age_ms":3}],
        "events":[{"elapsed_ms":0,"kind":"prepared","code":0}]})
}

#[tokio::test]
async fn support_diagnostics_require_an_operator_request_and_scope_it_to_the_account() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("plank-support-{}",rand::random::<u64>()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
    let requests=dir.join(crate::support_diagnostics::REQUESTS);
    std::fs::create_dir(&requests).unwrap();
    std::fs::set_permissions(&requests,std::fs::Permissions::from_mode(0o700)).unwrap();
    let h=harness_cfg(FakeKerberos::new(&[("anna","secret123456")]),|cfg| {
        cfg.diagnostics=Some(crate::diagnostics::Config{directory:dir.clone(),enabled_until_unix:u64::MAX});
    });
    let token=h.login().await;
    let app=crate::api::router(h.b.clone());
    let get=|token:&str| Request::builder().uri("/v1/diagnostics/support-request")
        .header("authorization",format!("Bearer {token}")).body(Body::empty()).unwrap();
    let post=|body:serde_json::Value| Request::builder().method("POST").uri("/v1/diagnostics/support")
        .header("authorization",format!("Bearer {token}")).header("content-type","application/json")
        .body(Body::from(body.to_string())).unwrap();
    let body=serde_json::json!({"schema":1,"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "report":diagnostic_report(1),"log_tail":"DXGI reset 0x887a0005\n"});
    assert_eq!(app.clone().oneshot(get("bogus")).await.unwrap().status(),StatusCode::UNAUTHORIZED);
    assert_eq!(app.clone().oneshot(get(&token)).await.unwrap().status(),StatusCode::NO_CONTENT);
    assert_eq!(app.clone().oneshot(post(body.clone())).await.unwrap().status(),StatusCode::FORBIDDEN);
    let time=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let request=serde_json::json!({"schema":1,"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "issued_unix":time,"expires_unix":time+600});
    let write=|user:&str,value:&serde_json::Value| {
        let path=requests.join(format!("{}.json",hex::encode(crate::util::sha256(user.as_bytes()))));
        std::fs::write(&path,value.to_string()).unwrap();
        std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    write("bob",&request);
    assert_eq!(app.clone().oneshot(get(&token)).await.unwrap().status(),StatusCode::NO_CONTENT);
    assert_eq!(app.clone().oneshot(post(body.clone())).await.unwrap().status(),StatusCode::FORBIDDEN);
    write("anna",&request);
    let response=app.clone().oneshot(get(&token)).await.unwrap();
    assert_eq!(response.status(),StatusCode::OK);
    assert_eq!(response.headers()["cache-control"],"no-store");
    assert_eq!(app.clone().oneshot(post(body.clone())).await.unwrap().status(),StatusCode::ACCEPTED);
    assert_eq!(app.clone().oneshot(post(body.clone())).await.unwrap().status(),StatusCode::ACCEPTED);
    let reports=dir.join(crate::support_diagnostics::REPORTS);
    assert_eq!(std::fs::read_dir(&reports).unwrap().count(),1);
    let path=std::fs::read_dir(&reports).unwrap().next().unwrap().unwrap().path();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode()&0o777,0o600);
    let saved:serde_json::Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["username"],"anna");
    let mut expected=body.clone(); expected["report"]["stream"]=serde_json::Value::Null;
    assert_eq!(saved["bundle"],expected);
    assert!(!std::fs::read_to_string(path).unwrap().contains(&token));
    let mut expired=request.clone(); expired["expires_unix"]=serde_json::json!(time);
    write("anna",&expired);
    assert_eq!(app.clone().oneshot(get(&token)).await.unwrap().status(),StatusCode::NO_CONTENT);
    assert_eq!(app.clone().oneshot(post(body.clone())).await.unwrap().status(),StatusCode::FORBIDDEN);
    write("anna",&request);
    let mut large=body.clone(); large["log_tail"]=serde_json::json!("x".repeat(65537));
    assert_eq!(app.clone().oneshot(post(large)).await.unwrap().status(),StatusCode::BAD_REQUEST);
    let mut unknown=body.clone(); unknown["path"]=serde_json::json!("/unrelated");
    assert_eq!(app.clone().oneshot(post(unknown)).await.unwrap().status(),StatusCode::BAD_REQUEST);
    let mut controls=body.clone(); controls["log_tail"]=serde_json::json!("\u{1b}[2J");
    assert_eq!(app.clone().oneshot(post(controls)).await.unwrap().status(),StatusCode::BAD_REQUEST);
    // Adding the exact support subdirectories must not break old report uploads.
    let ordinary=Request::builder().method("POST").uri("/v1/diagnostics")
        .header("authorization",format!("Bearer {token}")).body(Body::from(diagnostic_report(2).to_string())).unwrap();
    assert_eq!(app.oneshot(ordinary).await.unwrap().status(),StatusCode::ACCEPTED);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn diagnostics_authentication_schema_retention_limits_and_idempotency() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("plank-diagnostics-{}", rand::random::<u64>()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let h = harness_cfg(FakeKerberos::new(&[("anna", "secret123456")]), |cfg| {
        cfg.diagnostics = Some(crate::diagnostics::Config { directory: dir.clone(), enabled_until_unix: u64::MAX });
    });
    let token = h.login().await;
    let app = crate::api::router(h.b.clone());
    let request = |token: &str, body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/diagnostics")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request("bogus", diagnostic_report(1))).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut bad = diagnostic_report(1);
    bad["token"] = serde_json::json!("must-not-be-stored");
    assert_eq!(app.clone().oneshot(request(&token, bad)).await.unwrap().status(), StatusCode::BAD_REQUEST);
    let mut bad = diagnostic_report(1);
    bad["events"][0]["kind"] = serde_json::json!("arbitrary-raw-log");
    assert_eq!(app.clone().oneshot(request(&token, bad)).await.unwrap().status(), StatusCode::BAD_REQUEST);
    let mut bad = diagnostic_report(1);
    bad["displays"][0]["width"] = serde_json::json!(999999);
    assert_eq!(app.clone().oneshot(request(&token, bad)).await.unwrap().status(), StatusCode::BAD_REQUEST);
    let mut big = diagnostic_report(1);
    big["version"] = serde_json::json!("x".repeat(65536));
    assert_eq!(app.clone().oneshot(request(&token, big)).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Typical bounded reports exceed the normal 8 KiB auth body limit.
    let mut full = diagnostic_report(1);
    full["samples"] = serde_json::Value::Array(vec![full["samples"][0].clone(); 120]);
    full["lifecycle"] = serde_json::json!({"phase":"creating_window","termination_reason":"window_creation_failed",
        "error_code":-7,"window_created":false,"decoder_ready":false,"video_received":true,"renderer_progress":false});
    assert!(full.to_string().len() > 8192);
    assert_eq!(app.clone().oneshot(request(&token, full)).await.unwrap().status(), StatusCode::ACCEPTED);
    assert_eq!(
        app.clone().oneshot(request(&token, diagnostic_report(1))).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    for id in 2..=6 {
        assert_eq!(
            app.clone().oneshot(request(&token, diagnostic_report(id))).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
    }
    assert_eq!(
        app.clone().oneshot(request(&token, diagnostic_report(7))).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let files = std::fs::read_dir(&dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(files.len(), 6);
    for file in files {
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Revoked accounts retain no upload privilege.
    h.dir.users.lock().unwrap().get_mut("anna").unwrap().disabled = true;
    h.clock.advance(Duration::from_secs(h.cfg.ldap.cache_ttl_secs + 1));
    assert_eq!(app.oneshot(request(&token, diagnostic_report(8))).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn diagnostics_are_disabled_without_configuration_and_after_beta_expiry() {
    for expiry in [None, Some(1)] {
        let h = harness_cfg(FakeKerberos::new(&[]), |cfg| {
            cfg.diagnostics = expiry.map(|enabled_until_unix| crate::diagnostics::Config {
                directory: "/nonexistent".into(),
                enabled_until_unix,
            })
        });
        let response = crate::api::router(h.b)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/diagnostics")
                    .body(Body::from(diagnostic_report(1).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn mac_admission_is_explicit_hbac_bound_and_preserves_linux_gssapi() {
    let key = crate::mac_admission::tests::TestKey::new(WS1);
    let h = harness_cfg(FakeKerberos::new(&[("anna", "pw123456"), ("bob", "pw123456")]), |cfg| {
        cfg.mac_admission = Some(key.config.clone());
    });
    let owner = h.login_from(IP, "anna", "pw", "123456").await.unwrap();
    h.prober.busy.lock().unwrap().insert(WS1.into(), Some(true));
    let hosts = h.b.list_hosts(IP, &owner).await.unwrap().hosts;
    assert_eq!(hosts[0].shared_desktop, Some(true));
    assert_eq!(hosts[0].busy, Some(true));
    assert!(hosts[0].connectable);
    assert!(hosts[1].shared_desktop.is_none());
    assert!(serde_json::to_value(&hosts[1]).unwrap().get("shared_desktop").is_none());
    let reply = h.b.connect(IP, &owner, WS1, "remote.example.org").await.unwrap();
    assert_eq!(reply.auth_method, Some("broker_capability"));
    assert!(reply.gssapi_token.is_empty());
    assert_eq!(reply.username, "anna");
    assert_eq!(reply.local_username.as_deref(), Some("studio"));
    let claims = key.verify(reply.broker_token.as_ref().unwrap());
    assert_eq!(claims.host, WS1);
    assert_eq!(claims.subject, "anna");
    assert_eq!(claims.cert_sha256, reply.host_cert_sha256);
    assert_eq!(claims.exp - claims.iat, 60);
    assert!(!h.krb.log.lock().unwrap().iter().any(|line| line.starts_with("ap_req")));
    let linux = h.b.connect(IP, &owner, WS2, "remote.example.org").await.unwrap();
    assert!(!linux.gssapi_token.is_empty());
    assert!(linux.auth_method.is_none() && linux.broker_token.is_none() && linux.local_username.is_none());
    let body = serde_json::to_value(&linux).unwrap();
    assert!(body.get("broker_token").is_none() && body.get("auth_method").is_none());
    assert_eq!(h.b.connect(IP, &owner, "unassigned.example.org", "e").await.unwrap_err(), ApiError::Denied);
}

#[tokio::test]
async fn mac_admission_concurrent_users_behind_nat_have_independent_routes() {
    let key = crate::mac_admission::tests::TestKey::new(WS1);
    let h = harness_cfg(FakeKerberos::new(&[("anna", "pw123456"), ("bob", "pw123456")]), |cfg| {
        cfg.mac_admission = Some(key.config.clone());
    });
    let owner = h.login_from(IP, "anna", "pw", "123456").await.unwrap();
    let guest = h.login_from(IP, "bob", "pw", "123456").await.unwrap();
    let first = h.b.connect(IP, &owner, WS1, "remote.example.org").await.unwrap();
    let second = h.b.connect(IP, &guest, WS1, "remote.example.org").await.unwrap();
    assert_ne!(first.port, second.port);
    assert_eq!(key.verify(second.broker_token.as_ref().unwrap()).subject, "bob");
    assert_ne!(first.broker_token, second.broker_token);
    h.b.presence(IP, &owner, WS1, CONNECTION_A, 1, true).await.unwrap();
    h.b.presence(IP, &guest, WS1, CONNECTION_B, 1, true).await.unwrap();
    let host = h.b.list_hosts(IP, &owner).await.unwrap().hosts.remove(0);
    assert_eq!(host.shared_desktop, Some(true));
    assert_eq!(host.connected_users, vec!["anna", "bob"]);
    h.b.logout(&guest).await.unwrap();
    assert_eq!(h.b.list_hosts(IP, &owner).await.unwrap().hosts[0].connected_users, vec!["anna"]);
    assert!(h.b.keepalive(IP, &owner, WS1).await.is_ok());
    assert_eq!(h.b.keepalive(IP, &guest, WS1).await.unwrap_err(), ApiError::Unauthorized);
}

#[tokio::test]
async fn mac_admission_denies_bad_key_pins_and_disabled_user() {
    let key = crate::mac_admission::tests::TestKey::new(WS1);
    let h = harness_cfg(FakeKerberos::new(&[("anna", "pw123456")]), |cfg| {
        cfg.mac_admission = Some(key.config.clone());
    });
    let token = h.login_from(IP, "anna", "pw", "123456").await.unwrap();
    h.b.list_hosts(IP, &token).await.unwrap();
    h.prober.certs.lock().unwrap().insert(WS1.into(), Some([9; 32]));
    h.b.probe_all().await;
    assert_eq!(h.b.connect(IP, &token, WS1, "e").await.unwrap_err(), ApiError::Unavailable("certificate changed"));
    h.prober.certs.lock().unwrap().insert(WS1.into(), Some([1; 32]));
    h.b.probe_all().await;
    std::fs::write(&key.config.signing_key_file, b"invalid").unwrap();
    assert_eq!(h.b.connect(IP, &token, WS1, "e").await.unwrap_err(), ApiError::Internal("Mac admission unavailable"));
    assert!(h.relay.calls.lock().unwrap().is_empty());
    h.dir.users.lock().unwrap().get_mut("anna").unwrap().disabled = true;
    h.clock.advance(Duration::from_secs(61));
    assert_eq!(h.b.connect(IP, &token, WS1, "e").await.unwrap_err(), ApiError::Unauthorized);
}

#[tokio::test]
async fn mac_admission_direct_route_and_hbac_revocation_keep_existing_policy() {
    let key = crate::mac_admission::tests::TestKey::new(WS1);
    let h = harness_cfg(FakeKerberos::new(&[("anna", "pw123456")]), |cfg| {
        cfg.mac_admission = Some(key.config.clone());
        cfg.routing.direct_client_cidrs = vec!["10.1.0.0/24".into()];
    });
    let token = h.login_from(LAN, "anna", "pw", "123456").await.unwrap();
    let first = h.b.connect(LAN, &token, WS1, "e").await.unwrap();
    assert_eq!(first.route, "direct");
    assert_eq!(key.verify(first.broker_token.as_ref().unwrap()).host, WS1);
    assert!(h.relay_calls().is_empty());
    h.dir.view.lock().unwrap().rules[0].enabled = false;
    h.clock.advance(Duration::from_secs(61));
    assert_eq!(h.b.connect(LAN, &token, WS1, "e").await.unwrap_err(), ApiError::Denied);
    assert_eq!(h.b.keepalive(LAN, &token, WS1).await.unwrap_err(), ApiError::Unauthorized);
}

// ------------------------------------------------------------ admin socket

async fn admin_get(app: &axum::Router, method: &str, uri: &str) -> (StatusCode, serde_json::Value) {
    let r = app.clone().oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap()).await.unwrap();
    let status = r.status();
    assert_eq!(r.headers()["cache-control"], "no-store");
    let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn admin_status_lists_every_host_with_presence_grants_and_sessions() {
    let h = harness();
    let app = crate::admin::router(h.b.clone());
    // bob is only assigned ws1; ws2 belongs to nobody who is signed in. Both are listed.
    let token = h.login_from(IP, "bob", "hunter2", "654321").await.unwrap();
    h.b.probe_all().await;
    h.b.connect(IP, &token, WS1, "remote.example.org").await.unwrap();
    h.b.presence(IP, &token, WS1, CONNECTION_A, 1, true).await.unwrap();
    h.clock.advance(Duration::from_secs(7));
    let (code, j) = admin_get(&app, "GET", "/v1/admin/status").await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(j["cache_ttl_secs"], h.cfg.ldap.cache_ttl_secs);
    let hosts = j["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2);
    let ws1 = hosts.iter().find(|x| x["id"] == WS1).unwrap();
    let ws2 = hosts.iter().find(|x| x["id"] == WS2).unwrap();
    assert_eq!(ws1["online"], true);
    assert_eq!(ws1["name"], "ws1");
    assert_eq!(ws1["pin_mismatch"], false);
    assert_eq!(ws1["checked_age_secs"], 7);
    assert_eq!(ws1["connected_users"], serde_json::json!(["bob"]));
    assert_eq!(ws1["grants"][0]["user"], "bob");
    assert_eq!(ws1["grants"][0]["route"], "relay");
    assert_eq!(ws1["grants"][0]["client"], "203.0.113.7");
    assert!(ws1["grants"][0]["expires_in"].as_u64().unwrap() <= 30);
    assert!(ws1.get("image_sha256").is_none());
    assert_eq!(ws2["connected_users"], serde_json::json!([]));
    assert_eq!(ws2["grants"], serde_json::json!([]));
    assert_eq!(j["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(j["sessions"][0]["user"], "bob");
    assert_eq!(j["sessions"][0]["age_secs"], 7);
    // A host that is down shows why, even though nobody is assigned to it.
    h.prober.certs.lock().unwrap().insert(WS2.into(), None);
    h.b.probe_all().await;
    let (_, j) = admin_get(&app, "GET", "/v1/admin/status").await;
    let ws2 = j["hosts"].as_array().unwrap().iter().find(|x| x["id"] == WS2).unwrap().clone();
    assert_eq!(ws2["online"], false);
    assert_eq!(ws2["reason"], "offline");
}

#[tokio::test]
async fn admin_user_reports_what_the_broker_assigns() {
    let h = harness();
    let app = crate::admin::router(h.b.clone());
    let (code, j) = admin_get(&app, "GET", "/v1/admin/users/anna").await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(j["state"], "ok");
    assert_eq!(j["hosts"], serde_json::json!([WS1, WS2]));
    assert_eq!(j["groups"], serde_json::json!([crate::hbac::fixtures::group("artists")]));
    let (_, j) = admin_get(&app, "GET", "/v1/admin/users/BOB").await;
    assert_eq!(j["hosts"], serde_json::json!([WS1]), "names fold like sign-in");
    let (code, j) = admin_get(&app, "GET", "/v1/admin/users/nobody").await;
    assert_eq!((code, j["state"].clone()), (StatusCode::OK, serde_json::json!("not_found")));
    h.dir.users.lock().unwrap().get_mut("bob").unwrap().disabled = true;
    h.b.invalidate_caches().await;
    let (_, j) = admin_get(&app, "GET", "/v1/admin/users/bob").await;
    assert_eq!((j["state"].clone(), j["hosts"].clone()), (serde_json::json!("disabled"), serde_json::json!([])));
    assert_eq!(admin_get(&app, "GET", "/v1/admin/users/bad%20name").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(admin_get(&app, "GET", "/v1/admin/users/").await.0, StatusCode::NOT_FOUND);
    *h.dir.unavailable.lock().unwrap() = true;
    h.b.invalidate_caches().await;
    assert_eq!(admin_get(&app, "GET", "/v1/admin/users/anna").await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn admin_refresh_drops_the_view_and_user_caches_and_only_that() {
    let h = harness();
    let app = crate::admin::router(h.b.clone());
    let token = h.login_from(IP, "bob", "hunter2", "654321").await.unwrap();
    let hosts = || async { admin_get(&app, "GET", "/v1/admin/users/bob").await.1["hosts"].clone() };
    assert_eq!(hosts().await, serde_json::json!([WS1]));
    // Give bob ws2 in the directory; the caches still serve the old answer.
    h.dir.view.lock().unwrap().rules[1].member_hosts.push(crate::hbac::fixtures::host("ws2"));
    assert_eq!(hosts().await, serde_json::json!([WS1]));
    assert_eq!(admin_get(&app, "GET", "/v1/admin/refresh").await.0, StatusCode::METHOD_NOT_ALLOWED);
    let (code, j) = admin_get(&app, "POST", "/v1/admin/refresh").await;
    assert_eq!((code, j["state"].clone()), (StatusCode::OK, serde_json::json!("ok")));
    assert_eq!(hosts().await, serde_json::json!([WS1, WS2]));
    assert!(h.b.list_hosts(IP, &token).await.is_ok(), "sessions survive a refresh");
    assert_eq!(h.b.list_hosts(IP, &token).await.unwrap().hosts.len(), 2);
}

#[tokio::test]
async fn admin_socket_serves_only_the_api_uid() {
    let h = harness();
    let me = unsafe { libc::geteuid() };
    let dir = std::env::temp_dir().join(format!("fernweh-admin-sock-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    for (api_uid, served) in [(me, true), (me.wrapping_add(1), false)] {
        let path = dir.join(format!("a{api_uid}.sock"));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let b = h.b.clone();
        let task = tokio::spawn(crate::admin::serve_listener(b, listener, api_uid, std::future::pending()));
        let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = s.write_all(b"GET /v1/admin/status HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n").await;
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        let text = String::from_utf8_lossy(&out);
        if served {
            assert!(text.starts_with("HTTP/1.1 200"), "{text}");
            assert!(text.contains("\"hosts\""));
        } else {
            assert!(text.is_empty(), "refused peers get no bytes: {text}");
        }
        task.abort();
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn admin_bind_refuses_foreign_files_and_unknown_users() {
    let dir = std::env::temp_dir().join(format!("fernweh-admin-bind-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = |socket: std::path::PathBuf, user: &str| crate::config::AdminConfig {
        socket,
        api_user: user.into(),
        socket_group: None,
    };
    let file = dir.join("not-a-socket");
    std::fs::write(&file, b"keep me").unwrap();
    let me = unsafe { std::ffi::CStr::from_ptr(libc::getpwuid(libc::geteuid()).as_ref().unwrap().pw_name) }
        .to_string_lossy()
        .into_owned();
    assert!(crate::admin::bind(&cfg(file.clone(), &me)).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    assert!(crate::admin::bind(&cfg(dir.join("x.sock"), "no-such-user-here")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn admin_and_thumbnail_config_is_optional_and_validated() {
    let c = test_config();
    assert!(c.admin.is_none() && c.thumbnails.is_none());
    let base = include_str!("../packaging/broker.toml.example");
    let with = |v: &str| Config::parse(&format!("{base}\n{v}\n"));
    let c = with("[admin]\nsocket = \"/run/plank-broker-admin/admin.sock\"").unwrap();
    assert_eq!(c.admin.unwrap().api_user, "plank-admin");
    assert!(with("[admin]\nsocket = \"relative.sock\"").is_err());
    assert!(with("[admin]\nsocket = \"/run/x.sock\"\nbogus = 1").is_err());
    assert!(with("[thumbnails]\ndirectory = \"/var/lib/plank-thumbs\"").is_ok());
    assert!(with("[thumbnails]\ndirectory = \"thumbs\"").is_err());
}

// ------------------------------------------------------------ host images

fn thumb_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("fernweh-thumbs-api-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn harness_thumbs(dir: &std::path::Path) -> H {
    let dir = dir.to_path_buf();
    harness_cfg(FakeKerberos::new(&[("anna", "secret123456"), ("bob", "hunter2654321")]), move |cfg| {
        cfg.thumbnails = Some(crate::config::ThumbnailConfig { directory: dir });
    })
}

async fn get_image(app: &axum::Router, host: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut r = Request::builder().uri(format!("/v1/hosts/{host}/image")).extension(ConnectInfo(SocketAddr::new(IP, 1)));
    if let Some(t) = token {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let r = app.clone().oneshot(r.body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.headers()["cache-control"], "no-store");
    let status = r.status();
    let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn host_image_field_only_for_a_valid_png() {
    let d = thumb_dir();
    let h = harness_thumbs(&d);
    let token = h.login().await; // anna: ws1 and ws2
    let listed = || async { serde_json::to_value(h.b.list_hosts(IP, &token).await.unwrap()).unwrap() };
    let j = listed().await;
    assert!(j["hosts"][0].get("image_sha256").is_none() && j["hosts"][1].get("image_sha256").is_none());

    let good = crate::thumbs::test_png(128, 96, 1);
    std::fs::write(d.join("ws1.png"), &good).unwrap();
    let j = listed().await;
    assert_eq!(j["hosts"][0]["image_sha256"], hex::encode(crate::util::sha256(&good)));
    assert!(j["hosts"][1].get("image_sha256").is_none());

    // Everything below must be ignored, not break the list.
    let mut oversize = crate::thumbs::test_png(64, 64, 2);
    oversize.resize(128 * 1024 + 1, 0);
    for bad in [
        oversize,
        crate::thumbs::test_png(15, 64, 2),
        crate::thumbs::test_png(64, 300, 2),
        b"\x89PNG not really".to_vec(),
        b"GIF89a".to_vec(),
        Vec::new(),
    ] {
        std::fs::write(d.join("ws2.png"), &bad).unwrap();
        let j = listed().await;
        assert!(j["hosts"][1].get("image_sha256").is_none(), "{} bytes", bad.len());
        assert_eq!(j["hosts"][1]["id"], WS2);
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[tokio::test]
async fn host_image_endpoint_auth_assignment_and_replacement() {
    let d = thumb_dir();
    let h = harness_thumbs(&d);
    let first = crate::thumbs::test_png(64, 64, 1);
    std::fs::write(d.join("ws1.png"), &first).unwrap();
    std::fs::write(d.join("ws2.png"), crate::thumbs::test_png(64, 64, 9)).unwrap();
    let app = crate::api::router(h.b.clone());
    let bob = h.login_from(IP, "bob", "hunter2", "654321").await.unwrap(); // ws1 only

    assert_eq!(get_image(&app, WS1, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(get_image(&app, WS1, Some("garbage")).await.0, StatusCode::UNAUTHORIZED);
    let (code, j) = get_image(&app, WS1, Some(&bob)).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(j["type"], "image/png");
    assert_eq!(j["sha256"], hex::encode(crate::util::sha256(&first)));
    use base64::Engine;
    assert_eq!(base64::engine::general_purpose::STANDARD.decode(j["data"].as_str().unwrap()).unwrap(), first);
    assert_eq!(j.as_object().unwrap().len(), 3);
    // ws2 has an image but is not bob's; unknown and malformed hosts look the same.
    assert_eq!(get_image(&app, WS2, Some(&bob)).await, (StatusCode::NOT_FOUND, serde_json::json!({"state":"not_found"})));
    assert_eq!(get_image(&app, "nosuch.example.org", Some(&bob)).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get_image(&app, "..%2Fetc", Some(&bob)).await.0, StatusCode::NOT_FOUND);
    // Assigned but no (valid) image: 404 too.
    std::fs::remove_file(d.join("ws1.png")).unwrap();
    assert_eq!(get_image(&app, WS1, Some(&bob)).await.0, StatusCode::NOT_FOUND);

    // Replacing the file changes the hash the list and the endpoint report.
    std::fs::write(d.join("ws1.png"), &first).unwrap();
    let before = get_image(&app, WS1, Some(&bob)).await.1["sha256"].clone();
    std::thread::sleep(Duration::from_millis(50));
    let second = crate::thumbs::test_png(64, 64, 2);
    std::fs::write(d.join("ws1.png"), &second).unwrap();
    let after = get_image(&app, WS1, Some(&bob)).await.1["sha256"].clone();
    assert_ne!(before, after);
    assert_eq!(after, hex::encode(crate::util::sha256(&second)));
    let listed = serde_json::to_value(h.b.list_hosts(IP, &bob).await.unwrap()).unwrap();
    assert_eq!(listed["hosts"][0]["image_sha256"], after);
    std::fs::remove_dir_all(d).unwrap();
}

#[tokio::test]
async fn host_image_endpoint_is_off_without_thumbnails_config() {
    let h = harness();
    let app = crate::api::router(h.b.clone());
    let bob = h.login_from(IP, "bob", "hunter2", "654321").await.unwrap();
    assert_eq!(get_image(&app, WS1, Some(&bob)).await.0, StatusCode::NOT_FOUND);
}
