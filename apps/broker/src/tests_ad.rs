//! Active Directory backend: config rules and broker flows against fakes.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::ad::{build_view, AdComputer, AdGroup};
use crate::audit::Audit;
use crate::broker::{ApiError, Broker, Deps, Method};
use crate::config::{Config, DirectoryBackend};
use crate::directory::FakeDirectory;
use crate::hbac::UserView;
use crate::kerberos::FakeKerberos;
use crate::pins::PinStore;
use crate::probe::FakeProber;
use crate::relay::FakeRelay;
use crate::sessions::SessionStore;
use crate::util::FakeClock;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const WS01: &str = "ws01.example.org";
const WS02: &str = "ws02.example.org";

/// The commented AD block of the shipped example, uncommented.
fn ad_toml() -> String {
    let text = include_str!("../packaging/broker.toml.example");
    let block = text.split("# --- AD BEGIN").nth(1).unwrap().split("# --- AD END").next().unwrap();
    block
        .lines()
        .map(|l| l.strip_prefix("# ").or_else(|| l.strip_prefix('#')).unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

fn ad_cfg() -> Config {
    Config::parse(&ad_toml()).unwrap()
}

fn dn(cn: &str) -> String {
    format!("CN={cn},OU=Groups,DC=example,DC=org")
}

fn computer(name: &str, ip: [u8; 4]) -> AdComputer {
    AdComputer {
        dn: format!("CN={name},OU=Workstations,DC=example,DC=org"),
        sam: format!("{name}$"),
        dns_name: format!("{}.example.org", name.to_lowercase()),
        uac: Some("4096".into()),
        ipv4: Some(Ipv4Addr::from(ip)),
    }
}

struct H {
    clock: Arc<FakeClock>,
    dir: Arc<FakeDirectory>,
    b: Arc<Broker>,
    krb: Arc<FakeKerberos>,
    relay: Arc<FakeRelay>,
    pins: Arc<PinStore>,
}

fn harness(tweak: impl FnOnce(&mut Config)) -> H {
    harness_with(FakeKerberos::new(&[("anna", "pw-anna"), ("boss", "pw-boss"), ("eve", "pw-eve")]), tweak)
}

fn harness_with(krb: FakeKerberos, tweak: impl FnOnce(&mut Config)) -> H {
    let mut cfg = ad_cfg();
    cfg.limits.min_respond_ms = 0;
    cfg.relay.allowed_target_cidrs = vec!["192.0.2.0/24".into()];
    tweak(&mut cfg);
    let groups: Vec<AdGroup> = ["PLANK-WS01", "PLANK-WS02", "PLANK-AllHosts", "PLANK-Hosts"]
        .iter()
        .map(|cn| AdGroup { cn: cn.to_string(), dn: dn(cn) })
        .collect();
    let view = build_view(&cfg.ad, &[computer("WS01", [192, 0, 2, 11]), computer("WS02", [192, 0, 2, 12])], &groups);
    let user = |name: &str, gs: &[&str]| {
        (
            name.to_string(),
            UserView {
                disabled: false,
                dn: format!("CN={name},OU=Staff,DC=example,DC=org"),
                groups: gs.iter().map(|g| dn(g)).collect(),
                pwd_last_set_unix: None,
            },
        )
    };
    let users = vec![user("anna", &["PLANK-WS01", "Domain Users"]), user("boss", &["PLANK-AllHosts"]), user("eve", &[])];
    let dir = Arc::new(FakeDirectory::new(view, users.iter().map(|(n, v)| (n.as_str(), v.clone())).collect()));
    let krb = Arc::new(krb);
    let clock = FakeClock::new();
    let relay = Arc::new(FakeRelay::default());
    let prober = Arc::new(FakeProber {
        certs: Mutex::new(HashMap::from([(WS01.to_string(), Some([1u8; 32])), (WS02.to_string(), Some([2u8; 32]))])),
        busy: Mutex::new(HashMap::new()),
    });
    let pins = Arc::new(PinStore::memory());
    let b = Broker::new(
        cfg,
        Deps {
            krb: krb.clone(),
            dir: dir.clone(),
            relay: relay.clone(),
            prober,
            pins: pins.clone(),
            audit: Arc::new(Audit::memory()),
            clock: clock.clone(),
            sessions: Arc::new(SessionStore::memory()),
        },
    );
    H { clock, dir, b, krb, relay, pins }
}

fn z(v: &[&str]) -> Vec<Zeroizing<String>> {
    v.iter().map(|s| Zeroizing::new(s.to_string())).collect()
}

async fn login(h: &H, user: &str, pw: &str) -> Result<String, ApiError> {
    let c = h.b.auth_start(IP, user)?;
    h.b.auth_respond(IP, &c.conversation_id, z(&[pw])).await.map(|r| r.session_token)
}

#[test]
fn shipped_ad_example_parses_and_is_enforced() {
    let c = ad_cfg();
    assert_eq!(c.directory.backend, DirectoryBackend::Ad);
    assert_eq!(c.kerberos.realm, "EXAMPLE.ORG");
    assert_eq!(c.ad.hosts_group, "PLANK-Hosts");
    assert_eq!(c.limits.failures_per_user, 3);
    assert_eq!(c.limits.user_window_secs, 1800);
    assert_eq!(c.ad.groups_base.as_deref(), Some("OU=PLANK,OU=Groups,DC=example,DC=org"));
    assert_eq!(c.ad.lockout_margin_secs, 60);
    assert_eq!(c.kerberos.login_timeout_secs, 10);
    assert_eq!((c.ad.lockout_threshold, c.ad.lockout_window_secs), (Some(5), Some(1800)));
    assert_eq!(c.ldap.base_dn(&c.kerberos.realm), "dc=example,dc=org");
    let base = ad_toml();
    let bad = |from: &str, to: &str| {
        assert!(base.contains(from), "{from}");
        assert!(Config::parse(&base.replace(from, to)).is_err(), "{to}");
    };
    bad("password_only = true", "password_only = false");
    bad("enabled = false", "enabled = true");
    bad("failures_per_user = 3", "failures_per_user = 0");
    // Anything that could reach 5 within 30 min is refused.
    bad("failures_per_user = 3", "failures_per_user = 5");
    bad("lockout_margin_secs = 60", "lockout_margin_secs = 9");
    bad("lockout_threshold = 5", "");
    bad("lockout_window_secs = 1800", "");
    bad("lockout_threshold = 5", "lockout_threshold = 3");
    bad("groups_base = \"OU=PLANK,OU=Groups,DC=example,DC=org\"", "groups_base = \"\"");
    bad("verify_principal = \"host/broker.example.org@EXAMPLE.ORG\"", "verify_principal = \"host/x@OTHER\"");
    bad("[enrol]", "[mac_admission]\nsigning_key_file = \"/k\"\n[mac_admission.hosts]\n\"m.example.org\" = \"a\"\n[enrol]");
    bad("admission = \"none\"", "admission = \"gssapi\"");
    bad("hosts_group = \"PLANK-Hosts\"", "hosts_group = \"PLANK-AllHosts\"");
    bad("access_group_prefix = \"PLANK-\"", "access_group_prefix = \"a)(b\"");
    bad("probe_mode = \"tls\"", "probe_mode = \"tcp\"");
    // Static pins must be exact hex; per-host admission tables work.
    let pins = |v: &str| Config::parse(&format!("{base}\n[hosts.static_pins]\n\"ws01.example.org\" = \"{v}\"\n"));
    assert!(pins(&"ab".repeat(32)).is_ok());
    assert!(pins("AB").is_err());
    assert!(pins(&"AB".repeat(32)).is_err(), "lower-case hex only");
}

#[test]
fn freeipa_remains_the_default_backend() {
    let c = crate::config::test_config();
    assert_eq!(c.directory.backend, DirectoryBackend::Freeipa);
    assert_eq!(c.limits.failures_per_user, 0);
    assert_eq!(c.hosts.admission_for("ws1.example.org"), crate::config::Admission::Gssapi);
    // [ad] settings are not validated unless the backend is ad.
    let base = include_str!("../packaging/broker.toml.example");
    assert!(Config::parse(&format!("{base}\n[ad]\nhosts_group = \"x\"\n")).is_ok());
    assert!(Config::parse(&base.replacen("[kerberos]", "[kerberos]\npassword_only = true", 1)).is_err(), "password_only needs the ad backend");
    // Per-host admission table and the single-value form.
    let c = Config::parse(&format!("{base}\n[hosts.admission]\n\"win1.example.org\" = \"none\"\n")).unwrap();
    assert_eq!(c.hosts.admission_for("win1.example.org"), crate::config::Admission::None);
    assert_eq!(c.hosts.admission_for("ws1.example.org"), crate::config::Admission::Gssapi);
    assert!(Config::parse(&base.replacen("[hosts]", "[hosts]\nadmission = \"none\"", 1)).is_ok());
    assert!(Config::parse(&format!("{base}\n[hosts.static_pins]\n\"ws1.example.org\" = \"nothex\"\n")).is_err());
}

#[tokio::test]
async fn password_only_sign_in_and_generic_denials() {
    let h = harness(|_| {});
    let c = h.b.auth_start(IP, "Anna").unwrap();
    assert_eq!(
        serde_json::to_value(&c).unwrap()["prompts"],
        serde_json::json!([{"id":"password","style":"secret","text":"Password"}])
    );
    let r = h.b.auth_respond(IP, &c.conversation_id, z(&["pw-anna"])).await.unwrap();
    assert!(!r.passkey_setup_available);
    // The old two-prompt shape (password + code) is malformed here and never reaches the KDC.
    let before = h.krb.logins();
    let c = h.b.auth_start(IP, "anna").unwrap();
    assert_eq!(h.b.auth_respond(IP, &c.conversation_id, z(&["pw-anna", "123456"])).await.map(|r| r.session_token), Err(ApiError::Denied));
    assert_eq!(h.krb.logins(), before);
    // The secret sent to the KDC is the password alone.
    assert_eq!(login(&h, "anna", "wrong").await, Err(ApiError::Denied));
    assert_eq!(login(&h, "nobody", "x").await, Err(ApiError::Denied));
    // Passkey sign-in is refused outright.
    assert_eq!(h.b.auth_start_method(IP, "anna", Method::Passkey, None).await.unwrap_err(), ApiError::BadRequest);
    assert_eq!(h.krb.passkey_logins(), 0);
}

#[tokio::test]
async fn hosts_follow_the_plank_groups() {
    let h = harness(|_| {});
    let hosts = |t: String| {
        let b = h.b.clone();
        async move { b.list_hosts(IP, &t).await.unwrap().hosts.into_iter().map(|e| e.id).collect::<Vec<_>>() }
    };
    assert_eq!(hosts(login(&h, "anna", "pw-anna").await.unwrap()).await, [WS01]);
    assert_eq!(hosts(login(&h, "boss", "pw-boss").await.unwrap()).await, [WS01, WS02]);
    assert!(hosts(login(&h, "eve", "pw-eve").await.unwrap()).await.is_empty());
    let t = login(&h, "anna", "pw-anna").await.unwrap();
    assert_eq!(h.b.connect(IP, &t, WS02, "plank.example.org").await.unwrap_err(), ApiError::Denied);
}

#[tokio::test]
async fn admission_none_returns_an_empty_token_and_still_leases_the_relay() {
    let h = harness(|_| {});
    let t = login(&h, "anna", "pw-anna").await.unwrap();
    let r = h.b.connect(IP, &t, WS01, "plank.example.org").await.unwrap();
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["route"], "relay");
    assert_eq!(j["gssapi_token"], "");
    assert_eq!(j["auth_method"], "host_login");
    assert_eq!(j["host_cert_sha256"], hex::encode([1u8; 32]), "the host certificate is never empty");
    assert_eq!(j["port"], 29001);
    assert!(h.krb.log.lock().unwrap().iter().all(|l| !l.starts_with("ap_req")), "no service ticket requested");
    assert_eq!(h.relay.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn static_pin_replaces_tofu() {
    let good = hex::encode([1u8; 32]);
    let h = harness(|c| {
        c.hosts.static_pins.insert(WS01.into(), good.clone());
        c.hosts.static_pins.insert(WS02.into(), hex::encode([9u8; 32]));
    });
    let t = login(&h, "boss", "pw-boss").await.unwrap();
    assert!(h.b.connect(IP, &t, WS01, "plank.example.org").await.is_ok());
    assert_eq!(
        h.b.connect(IP, &t, WS02, "plank.example.org").await.unwrap_err(),
        ApiError::Unavailable("certificate changed")
    );
    assert_eq!(h.pins.get(WS01), None, "a statically pinned host is never TOFU-stored");
    assert_eq!(h.pins.get(WS02), None);
}

#[tokio::test]
async fn failures_for_one_user_from_many_addresses_block_that_user() {
    let h = harness(|_| {});
    for i in 0..3u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i + 1));
        let c = h.b.auth_start(ip, "anna").unwrap();
        assert_eq!(h.b.auth_respond(ip, &c.conversation_id, z(&["bad"])).await.map(|r| r.session_token), Err(ApiError::Denied));
    }
    let logins = h.krb.logins();
    let fresh = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
    // The per-user refusal looks like a wrong password: a normal challenge, then a generic
    // denial (no 429, no retry-after), even for the RIGHT password, and the KDC is not asked.
    assert_eq!(login_from(&h, fresh, "anna", "pw-anna").await, Err(ApiError::Denied));
    assert_eq!(h.krb.logins(), logins, "the KDC (AD lockout counter) is no longer reached");
    assert!(login_from(&h, fresh, "boss", "pw-boss").await.is_ok(), "other users are unaffected");
}

#[tokio::test]
async fn infrastructure_errors_and_success_are_not_counted_toward_the_user_block() {
    let mut k = FakeKerberos::new(&[("anna", "pw-anna")]);
    k.unavailable = true;
    let h = harness_with(k, |_| {});
    for i in 0..8u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i + 1));
        let c = h.b.auth_start(ip, "anna").unwrap();
        let r = h.b.auth_respond(ip, &c.conversation_id, z(&["pw-anna"])).await.map(|r| r.session_token);
        assert_eq!(r, Err(ApiError::Denied));
    }
    let fresh = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
    assert_eq!(h.krb.logins(), 8, "a KDC outage is never counted: every attempt reached the KDC");
    assert!(h.b.auth_start(fresh, "anna").is_ok());
    // Successful sign-ins are refunded too.
    let h = harness(|_| {});
    for _ in 0..6 {
        login(&h, "anna", "pw-anna").await.unwrap();
        h.clock.advance(std::time::Duration::from_secs(20));
    }
    assert!(login(&h, "anna", "pw-anna").await.is_ok());
}

#[tokio::test]
async fn password_change_ends_older_sessions() {
    let h = harness(|_| {});
    let t = login(&h, "anna", "pw-anna").await.unwrap();
    assert!(h.b.list_hosts(IP, &t).await.is_ok());
    let later = crate::util::Clock::unix(&*h.clock) + 3600;
    h.dir.users.lock().unwrap().get_mut("anna").unwrap().pwd_last_set_unix = Some(later);
    h.clock.advance(std::time::Duration::from_secs(61)); // past the directory cache
    assert_eq!(h.b.list_hosts(IP, &t).await.unwrap_err(), ApiError::Unauthorized);
    // A password set before the sign-in leaves new sessions alone.
    h.dir.users.lock().unwrap().get_mut("anna").unwrap().pwd_last_set_unix = Some(crate::util::Clock::unix(&*h.clock) - 10);
    h.clock.advance(std::time::Duration::from_secs(61));
    let t = login(&h, "anna", "pw-anna").await.unwrap();
    assert!(h.b.list_hosts(IP, &t).await.is_ok());
}

#[tokio::test]
async fn failures_spaced_below_the_observation_window_cannot_chain_to_a_lockout() {
    use std::time::Duration;
    let h = harness(|_| {});
    let ips: Vec<IpAddr> = (1..=9u8).map(|i| IpAddr::V4(Ipv4Addr::new(198, 51, 100, i))).collect();
    // N = 3 wrong passwords 901 s apart: AD's counter would chain (resets only 1800 s after the
    // LAST failure), so a sliding window would let this go on until the account locks.
    for (i, wait) in [0u64, 901, 901].iter().enumerate() {
        h.clock.advance(Duration::from_secs(*wait));
        let c = h.b.auth_start(ips[i], "anna").unwrap();
        let r = h.b.auth_respond(ips[i], &c.conversation_id, z(&["bad"])).await.map(|r| r.session_token);
        assert_eq!(r, Err(ApiError::Denied));
    }
    let logins = h.krb.logins();
    h.clock.advance(Duration::from_secs(901));
    assert_eq!(login_from(&h, ips[5], "anna", "pw-anna").await, Err(ApiError::Denied), "the 4th is refused");
    assert_eq!(h.krb.logins(), logins, "without asking the KDC");
    // 1800 s window + 60 s margin after the last failure (t = 1802): free again at 3662.
    h.clock.advance(Duration::from_secs(958));
    assert_eq!(login_from(&h, ips[6], "anna", "pw-anna").await, Err(ApiError::Denied), "1 s early");
    h.clock.advance(Duration::from_secs(1));
    assert!(login_from(&h, ips[7], "anna", "pw-anna").await.is_ok());
    assert_eq!(h.krb.logins(), logins + 1);
}

#[tokio::test]
async fn names_that_are_not_an_exact_samaccountname_never_reach_the_kdc() {
    let h = harness(|_| {});
    // `anna2`, `anna@example.org`, a UPN spelling...: not a sAMAccountName, so no KDC call and
    // nothing tracked (an alias must not get its own N attempts at the same account).
    for (i, n) in ["anna2", "anna.x", "eve1", "nobody"].iter().enumerate() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 102, i as u8 + 1));
        assert_eq!(login_from(&h, ip, n, "pw-anna").await, Err(ApiError::Denied));
    }
    assert_eq!(h.krb.logins(), 0);
    // The real account is unaffected, in any letter case.
    assert!(login(&h, "ANNA", "pw-anna").await.is_ok());
    assert_eq!(h.krb.logins(), 1);
    // A directory outage is a generic denial, never counted and never a KDC call.
    *h.dir.unavailable.lock().unwrap() = true;
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 102, 99));
    assert_eq!(login_from(&h, ip, "eve", "pw-eve").await, Err(ApiError::Denied), "no cached lookup for eve yet");
    assert_eq!(h.krb.logins(), 1);
    *h.dir.unavailable.lock().unwrap() = false;
    assert!(login_from(&h, ip, "eve", "pw-eve").await.is_ok());
}

async fn login_from(h: &H, ip: IpAddr, user: &str, pw: &str) -> Result<String, ApiError> {
    let c = h.b.auth_start(ip, user)?;
    h.b.auth_respond(ip, &c.conversation_id, z(&[pw])).await.map(|r| r.session_token)
}

#[tokio::test]
async fn unknown_users_are_not_tracked_and_never_block_anyone() {
    let h = harness(|_| {});
    for i in 0..40u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 101, i + 1));
        assert_eq!(login_from(&h, ip, &format!("ghost{i}"), "x").await, Err(ApiError::Denied));
        assert_eq!(login_from(&h, ip, "nobody", "x").await, Err(ApiError::Denied));
    }
    let fresh = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    assert!(login_from(&h, fresh, "anna", "pw-anna").await.is_ok());
    assert_eq!(h.krb.logins(), 1, "unknown names never reach the KDC (only anna's login did)");
}
