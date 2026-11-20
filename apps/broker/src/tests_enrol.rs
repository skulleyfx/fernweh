//! Enrolment flow tests (`/v1/enroll/*`, bde-linux `docs/plank-broker.md` §16)
//! against the fakes: gates G1-G5, password change, local TOTP check, the writes as
//! the user, the final password‖code login, passkey mapping, limits and HTTP shapes.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt;
use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::broker::{ApiError, Broker, Deps, EnrolReply};
use crate::config::{test_config, Config};
use crate::device::testkey::TestDevice;
use crate::device::DeviceKey;
use crate::directory::FakeDirectory;
use crate::enrol::{EnrolFacts, PwReject};
use crate::hbac::fixtures::*;
use crate::kerberos::FakeKerberos;
use crate::pins::PinStore;
use crate::probe::FakeProber;
use crate::relay::FakeRelay;
use crate::sessions::SessionStore;
use crate::totp;
use crate::util::{Clock, FakeClock};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const IP2: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
const IP3: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
const ONE_TIME: &str = "Studio-OneTime-77";
const NEW_PW: &str = "correct horse battery";
const DAY: u64 = 86400;

struct E {
    b: Arc<Broker>,
    krb: Arc<FakeKerberos>,
    dir: Arc<FakeDirectory>,
    audit: Arc<Audit>,
    clock: Arc<FakeClock>,
}

/// `groups`: IPA group names; `set_ago`: seconds since the password was set;
/// `expired`: admin-issued (expiration == last change) or a self-chosen one.
fn facts(clock: &FakeClock, u: &str, groups: &[&str], set_ago: u64, expired: bool) -> EnrolFacts {
    let now = clock.unix();
    let set = now - set_ago;
    EnrolFacts {
        dn: user(u),
        groups: groups.iter().map(|g| group(g)).collect(),
        last_password_change: Some(set),
        password_expiration: Some(if expired { set } else { set + 90 * DAY }),
        auth_types: vec!["password".into(), "otp".into()],
        ..Default::default()
    }
}

fn harness_cfg(tweak: impl FnOnce(&mut Config)) -> E {
    let mut cfg = test_config();
    cfg.limits.min_respond_ms = 0;
    cfg.limits.starts_per_minute_per_ip = 100;
    tweak(&mut cfg);
    let clock = FakeClock::new();
    let passwords = Arc::new(Mutex::new(HashMap::new()));
    let otp_keys = Arc::new(Mutex::new(HashMap::new()));
    let mut krb = FakeKerberos::new(&[("anna", "secret123456")]);
    krb.end_unix = clock.unix() + DAY;
    krb.renew_till_unix = clock.unix() + i32::MAX as u64;
    krb.passwords = passwords.clone();
    krb.otp_keys = otp_keys.clone();
    *krb.otp_clock.lock().unwrap() = Some(clock.clone() as Arc<dyn Clock>);
    let mut dir = FakeDirectory::new(view(vec![]), vec![]);
    dir.passwords = passwords.clone();
    dir.otp_keys = otp_keys.clone();
    {
        let mut f = dir.enrol.lock().unwrap();
        let mut pw = passwords.lock().unwrap();
        let mut add = |u: &str, fx: EnrolFacts| {
            f.insert(u.to_string(), fx);
            pw.insert(u.to_string(), ONE_TIME.to_string());
            dir.users.lock().unwrap().insert(u.to_string(), crate::hbac::UserView {
                disabled: false, dn: user(u), groups: vec![], ..Default::default()
            });
        };
        add("carol", facts(&clock, "carol", &["fernweh", "staff"], DAY, true));
        add("dave", facts(&clock, "dave", &["fernweh", "admins"], DAY, true));
        add("erin", facts(&clock, "erin", &["staff"], DAY, true));
        add("fred", facts(&clock, "fred", &["fernweh"], 8 * DAY, true));
        add("gina", EnrolFacts { tokens: 1, ..facts(&clock, "gina", &["fernweh"], DAY, true) });
        add("hank", facts(&clock, "hank", &["fernweh"], 2 * DAY, false));
        let mut ivy = facts(&clock, "ivy", &["fernweh"], DAY, true);
        ivy.auth_types.push("passkey".into());
        add("ivy", ivy);
        add("jack", facts(&clock, "jack", &["fernweh"], DAY, true));
        add("kim", EnrolFacts { disabled: true, ..facts(&clock, "kim", &["fernweh"], DAY, true) });
        // In fernweh by hand, but without the plank_remote assignment's otp auth type.
        add(
            "lena",
            EnrolFacts { auth_types: vec!["password".into()], ..facts(&clock, "lena", &["fernweh"], DAY, true) },
        );
    }
    // jack already has an ENABLED token: FAST makes the KDC demand the code.
    otp_keys.lock().unwrap().insert("jack".into(), vec![1u8; 20]);
    let krb = Arc::new(krb);
    let dir = Arc::new(dir);
    let audit = Arc::new(Audit::memory());
    let b = Broker::new(
        cfg,
        Deps {
            krb: krb.clone(),
            dir: dir.clone(),
            relay: Arc::new(FakeRelay::default()),
            prober: Arc::new(FakeProber { certs: Mutex::new(HashMap::new()), busy: Mutex::new(HashMap::new()) }),
            pins: Arc::new(PinStore::memory()),
            audit: audit.clone(),
            clock: clock.clone(),
            sessions: Arc::new(SessionStore::memory()),
        },
    );
    E { b, krb, dir, audit, clock }
}

fn harness() -> E {
    harness_cfg(|_| {})
}

fn z(v: &str) -> Vec<Zeroizing<String>> {
    vec![Zeroizing::new(v.to_string())]
}

fn j(r: &EnrolReply) -> Value {
    serde_json::to_value(r).unwrap()
}

impl E {
    async fn start(&self, ip: IpAddr, u: &str) -> String {
        self.b.enroll_start(ip, u, None).await.unwrap().conversation_id
    }
    async fn respond(&self, ip: IpAddr, id: &str, pw: &str) -> Result<EnrolReply, ApiError> {
        self.b.enroll_respond(ip, id, z(pw)).await
    }
    async fn password(&self, id: &str, pw: &str) -> Result<EnrolReply, ApiError> {
        self.b.enroll_password(IP, id, Zeroizing::new(pw.to_string())).await
    }
    fn code(&self, reply: &EnrolReply) -> String {
        let secret = j(reply)["secret"].as_str().unwrap().to_string();
        totp::code_at(&totp::base32_decode(&secret).unwrap(), self.clock.unix())
    }
    fn reasons(&self) -> Vec<String> {
        self.audit
            .events()
            .into_iter()
            .filter(|e| e["event"] == "enrol_denied")
            .map(|e| e["reason"].as_str().unwrap().to_string())
            .collect()
    }
    /// Start + respond for a user whose gates pass (expired one-time password).
    async fn to_new_password(&self, u: &str) -> String {
        let id = self.start(IP, u).await;
        assert_eq!(self.respond(IP, &id, ONE_TIME).await.unwrap().state(), "new_password");
        id
    }
}

fn wrong(code: &str) -> String {
    format!("{:06}", (code.parse::<u32>().unwrap() + 500_000) % 1_000_000)
}

#[tokio::test]
async fn full_flow_expired_password_totp_and_session() {
    let e = harness();
    let s = e.b.enroll_start(IP, "Carol", None).await.unwrap();
    assert_eq!(
        serde_json::to_value(&s).unwrap()["prompts"],
        json!([{"id": "password", "style": "secret"}]),
        "exact contract shape"
    );
    let id = s.conversation_id;

    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    assert_eq!(j(&r), json!({"state": "new_password", "policy": {"min_length": 8, "min_classes": 0}}));
    assert_eq!(e.krb.proofs(), 1);

    // Policy answers keep the conversation; none of them changes anything.
    let r = e.password(&id, "short").await.unwrap();
    assert_eq!(j(&r), json!({"state": "password_rejected", "reason": "too_short"}));
    let r = e.password(&id, ONE_TIME).await.unwrap();
    assert_eq!(j(&r), json!({"state": "password_rejected", "reason": "reused"}), "the issuer knows the old one");
    *e.krb.reject_change.lock().unwrap() = Some(PwReject::TooSimple);
    let r = e.password(&id, "aaaaaaaaaaaa").await.unwrap();
    assert_eq!(j(&r), json!({"state": "password_rejected", "reason": "too_simple"}));
    assert_eq!(e.krb.passwords.lock().unwrap()["carol"], ONE_TIME);

    let r = e.password(&id, NEW_PW).await.unwrap();
    let v = j(&r);
    assert_eq!(v["state"], "totp");
    let secret = v["secret"].as_str().unwrap();
    assert_eq!(secret.len(), 56, "35-byte key like IPA's default");
    assert_eq!(
        v["otpauth_uri"],
        format!(
            "otpauth://totp/BDE%20Fernweh:carol?secret={secret}&issuer=BDE%20Fernweh&algorithm=SHA1&digits=6&period=30"
        )
    );
    assert_eq!(e.krb.passwords.lock().unwrap()["carol"], NEW_PW);
    let code = e.code(&r);

    // A wrong code never reaches the directory.
    let binds = e.dir.user_binds.lock().unwrap().len();
    let r = e.b.enroll_totp(IP, &id, &wrong(&code)).await.unwrap();
    assert_eq!(j(&r), json!({"state": "code_rejected"}));
    assert_eq!(e.dir.user_binds.lock().unwrap().len(), binds);
    assert!(e.dir.tokens.lock().unwrap().is_empty());

    let r = e.b.enroll_totp(IP, &id, &code).await.unwrap();
    let v = j(&r);
    assert_eq!(v["state"], "authenticated");
    assert_eq!(v["username"], "carol");
    assert_eq!(v["passkey_available"], false);
    assert_eq!(v["expires_in"], 36000);
    assert!(v.get("device_bound").is_none());
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys.len(), 5, "auth/respond fields + passkey_available: {keys:?}");
    let token = v["session_token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 43);
    // A normal session: the host list works (carol has no hosts assigned).
    assert!(e.b.list_hosts(IP, &token).await.unwrap().hosts.is_empty());

    let t = e.dir.tokens.lock().unwrap().clone();
    assert_eq!(t.len(), 1);
    assert_eq!((t[0].0.as_str(), t[0].2.as_str()), ("carol", "BDE Fernweh"));
    assert_eq!(t[0].1.len(), 36, "uuid");
    // Not a passkey user: the conversation is gone already.
    assert_eq!(e.b.enrol_conversations(), 0);
    assert_eq!(j(&e.b.enroll_finish(IP, &id)), json!({"state": "done"}));

    for ev in [
        "enrol_start",
        "enrol_proven",
        "enrol_password_changed",
        "enrol_totp_created",
        "enrol_totp_enabled",
        "enrol_login_ok",
        "login_ok",
    ] {
        assert_eq!(e.audit.count(ev), 1, "{ev}");
    }
    let all = serde_json::to_string(&e.audit.events()).unwrap();
    for secret_text in [ONE_TIME, NEW_PW, secret, &code, &token] {
        assert!(!all.contains(secret_text), "audit must not carry secrets");
    }
}

#[tokio::test]
async fn start_is_identical_for_every_name() {
    let e = harness();
    let shape = |r: crate::broker::EnrolStartReply| {
        let mut v = serde_json::to_value(r).unwrap();
        assert_eq!(v["conversation_id"].as_str().unwrap().len(), 43);
        v.as_object_mut().unwrap().remove("conversation_id");
        v
    };
    let a = shape(e.b.enroll_start(IP, "carol", None).await.unwrap());
    for u in ["nobody", "dave", "Not A Valid Name", "admin"] {
        assert_eq!(shape(e.b.enroll_start(IP, u, None).await.unwrap()), a, "{u}");
    }
    assert_eq!(e.b.enroll_start(IP, "", None).await.unwrap_err(), ApiError::BadRequest);
    assert_eq!(e.krb.proofs(), 0);
}

#[tokio::test]
async fn gates_deny_generically_and_skip_the_kdc() {
    let e = harness();
    for (u, reason) in [
        ("dave", "privileged"),
        ("erin", "entitlement"),
        ("lena", "entitlement"),
        ("fred", "window"),
        ("nobody", "credentials"),
        ("kim", "credentials"),
        ("bad name!", "credentials"),
    ] {
        let id = e.start(IP3, u).await;
        assert_eq!(e.respond(IP3, &id, ONE_TIME).await.unwrap_err(), ApiError::Denied, "{u}");
        assert_eq!(e.reasons().last().unwrap(), reason, "{u}");
    }
    assert_eq!(e.krb.proofs(), 0, "no KDC exchange for users who could not enrol");
    assert!(e.dir.user_binds.lock().unwrap().is_empty());

    // Wrong password for an entitled user: the KDC says no.
    let id = e.start(IP, "carol").await;
    assert_eq!(e.respond(IP, &id, "guess").await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.reasons().last().unwrap(), "credentials");
    assert_eq!(e.krb.proofs(), 1);
    // The conversation is used up.
    assert_eq!(e.respond(IP, &id, ONE_TIME).await.unwrap_err(), ApiError::Denied);
}

#[tokio::test]
async fn age_limit_can_be_disabled_for_beta_enrolment() {
    let e = harness_cfg(|cfg| cfg.enrol.window_days = 0);
    let id = e.start(IP, "fred").await;
    let reply = e.respond(IP, &id, ONE_TIME).await.unwrap();
    assert!(matches!(reply, EnrolReply::NewPassword { .. }));
}

#[tokio::test]
async fn existing_factor_is_already_enrolled_only_after_proof() {
    let e = harness();
    // Disabled token (invisible to the KDC): wrong password is plain denied ...
    let id = e.start(IP, "gina").await;
    assert_eq!(e.respond(IP, &id, "guess").await.unwrap_err(), ApiError::Denied);
    // ... the right one reveals it.
    let id = e.start(IP, "gina").await;
    assert_eq!(j(&e.respond(IP, &id, ONE_TIME).await.unwrap()), json!({"state": "already_enrolled"}));
    assert_eq!(e.reasons().last().unwrap(), "has_factor");
    assert_eq!(e.b.enrol_conversations(), 0);
    // Enabled token: the FAST proof needs the code, so the password alone fails.
    let id = e.start(IP2, "jack").await;
    assert_eq!(e.respond(IP2, &id, ONE_TIME).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.krb.password_changes(), 0);
    assert!(e.dir.tokens.lock().unwrap().is_empty());
}

#[tokio::test]
async fn factor_seen_only_by_the_user_still_counts() {
    let e = harness();
    // The broker's own read shows nothing (e.g. its IPA permission is missing); the
    // check bound as the user still finds the factor before anything changes.
    *e.dir.broker_blind.lock().unwrap() = true;
    e.dir.enrol.lock().unwrap().get_mut("carol").unwrap().passkeys = 1;
    let id = e.start(IP, "carol").await;
    assert_eq!(e.respond(IP, &id, ONE_TIME).await.unwrap().state(), "already_enrolled");
    assert_eq!(e.dir.user_binds.lock().unwrap().clone(), vec!["carol".to_string()]);
    assert_eq!(e.krb.password_changes(), 0);
}

#[tokio::test]
async fn fresh_self_chosen_password_skips_the_change() {
    let e = harness();
    let id = e.start(IP, "hank").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    assert_eq!(r.state(), "totp");
    // No password step in this conversation.
    assert_eq!(e.password(&id, NEW_PW).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.krb.password_changes(), 0);

    let id = e.start(IP, "hank").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    let r = e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap();
    assert_eq!(r.state(), "authenticated");
    assert_eq!(e.krb.password_changes(), 0);
    assert_eq!(e.krb.passwords.lock().unwrap()["hank"], ONE_TIME);
}

#[tokio::test]
async fn g3_is_checked_again_before_the_token_write() {
    let e = harness();
    let id = e.start(IP, "hank").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    // Meanwhile a factor appears (e.g. the LAN portal).
    e.dir.passkeys.lock().unwrap().push(("hank".into(), "passkey:a,b".into()));
    assert_eq!(e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap_err(), ApiError::Denied);
    assert!(e.dir.tokens.lock().unwrap().is_empty());
    assert_eq!(e.reasons().last().unwrap(), "has_factor");
}

#[tokio::test]
async fn passkey_step_for_passkey_users() {
    let e = harness();
    let id = e.to_new_password("ivy").await;
    let r = e.password(&id, NEW_PW).await.unwrap();
    let r = e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap();
    assert_eq!(j(&r)["state"], "authenticated");
    assert_eq!(j(&r)["passkey_available"], true);

    let r = e.b.enroll_passkey(IP, &id, "passkey:nonsense").await.unwrap();
    assert_eq!(j(&r), json!({"state": "passkey_rejected"}));
    let d = TestDevice::new();
    let mapping = format!("passkey:{},{}", STANDARD.encode([9u8; 32]), STANDARD.encode(d.spki()));
    assert!(DeviceKey::from_spki(&d.spki()).is_some());
    let r = e.b.enroll_passkey(IP, &id, &mapping).await.unwrap();
    assert_eq!(j(&r), json!({"state": "passkey_added"}));
    assert_eq!(e.dir.passkeys.lock().unwrap().clone(), vec![("ivy".to_string(), mapping.clone())]);
    assert_eq!(e.audit.count("enrol_passkey_added"), 1);
    // One mapping per conversation.
    assert_eq!(e.b.enroll_passkey(IP, &id, &mapping).await.unwrap_err(), ApiError::Denied);
}

#[tokio::test]
async fn passkey_step_denied_without_passkey_auth_type() {
    let e = harness();
    let id = e.start(IP, "hank").await;
    e.respond(IP, &id, ONE_TIME).await.unwrap();
    // Before the token: wrong stage (and the conversation is dropped).
    let d = TestDevice::new();
    let mapping = format!("passkey:{},{}", STANDARD.encode([9u8; 32]), STANDARD.encode(d.spki()));
    assert_eq!(e.b.enroll_passkey(IP, &id, &mapping).await.unwrap_err(), ApiError::Denied);
    let id = e.start(IP, "hank").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    let r = e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap();
    assert_eq!(j(&r)["passkey_available"], false);
    assert_eq!(e.b.enroll_passkey(IP, &id, &mapping).await.unwrap_err(), ApiError::Denied);
    assert!(e.dir.passkeys.lock().unwrap().is_empty());
}

#[tokio::test]
async fn enrolled_when_the_follow_up_login_fails() {
    let e = harness();
    *e.krb.otp_login_fails.lock().unwrap() = true;
    let id = e.to_new_password("carol").await;
    let r = e.password(&id, NEW_PW).await.unwrap();
    let r = e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap();
    assert_eq!(j(&r), json!({"state": "enrolled", "passkey_available": false}));
    assert_eq!(e.dir.tokens.lock().unwrap().len(), 1, "the token stays enabled");
    assert_eq!(e.audit.count("login_fail"), 0, "not counted as a failed sign-in");
    // The next sign-in works normally with password + next code.
    *e.krb.otp_login_fails.lock().unwrap() = false;
    e.clock.advance(Duration::from_secs(30));
    let key = e.krb.otp_keys.lock().unwrap()["carol"].clone();
    let code = totp::code_at(&key, e.clock.unix());
    let c = e.b.auth_start(IP, "carol").unwrap();
    let a = e.b.auth_respond(IP, &c.conversation_id, vec![Zeroizing::new(NEW_PW.into()), Zeroizing::new(code)]).await;
    assert!(a.is_ok());
}

#[tokio::test]
async fn five_wrong_codes_end_the_conversation() {
    let e = harness();
    let id = e.start(IP, "hank").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    let bad = wrong(&e.code(&r));
    for _ in 0..4 {
        assert_eq!(e.b.enroll_totp(IP, &id, &bad).await.unwrap().state(), "code_rejected");
    }
    assert_eq!(e.b.enroll_totp(IP, &id, &bad).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap_err(), ApiError::Denied);
    assert!(e.dir.tokens.lock().unwrap().is_empty());
    assert_eq!(e.reasons().last().unwrap(), "limit");
}

#[tokio::test]
async fn codes_outside_one_step_are_rejected() {
    let e = harness();
    let id = e.start(IP, "hank").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    let key = totp::base32_decode(j(&r)["secret"].as_str().unwrap()).unwrap();
    let old = totp::code_at(&key, e.clock.unix() - 90);
    if totp::verify(&key, &old, e.clock.unix()).is_none() {
        assert_eq!(e.b.enroll_totp(IP, &id, &old).await.unwrap().state(), "code_rejected");
    }
    let prev = totp::code_at(&key, e.clock.unix() - 30);
    assert_eq!(e.b.enroll_totp(IP, &id, &prev).await.unwrap().state(), "authenticated");
}

#[tokio::test]
async fn conversation_is_bound_to_address_and_lifetime() {
    let e = harness();
    let id = e.start(IP, "carol").await;
    assert_eq!(e.respond(IP2, &id, ONE_TIME).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.krb.proofs(), 0);

    let id = e.to_new_password("carol").await;
    e.clock.advance(Duration::from_secs(601));
    assert_eq!(e.password(&id, NEW_PW).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.krb.password_changes(), 0);

    // The reaper drops expired conversations.
    let _id = e.start(IP, "carol").await;
    assert_eq!(e.b.enrol_conversations(), 1);
    e.clock.advance(Duration::from_secs(601));
    e.b.reap().await;
    assert_eq!(e.b.enrol_conversations(), 0);
}

#[tokio::test]
async fn one_live_conversation_per_user() {
    let e = harness();
    let first = e.to_new_password("carol").await;
    let second = e.to_new_password("carol").await;
    assert_eq!(e.password(&first, NEW_PW).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.password(&second, NEW_PW).await.unwrap().state(), "totp");
    // A start alone (no proof) does not displace a live conversation.
    let other = e.start(IP2, "carol").await;
    let _ = other;
    assert_eq!(e.b.enrol_conversations(), 2);
}

#[tokio::test]
async fn daily_cap_counts_every_proof_from_any_address() {
    let e = harness_cfg(|c| c.enrol.daily_cap = 2);
    for ip in [IP, IP2] {
        let id = e.start(ip, "carol").await;
        assert_eq!(e.respond(ip, &id, "guess").await.unwrap_err(), ApiError::Denied);
    }
    let id = e.start(IP3, "carol").await;
    assert_eq!(e.respond(IP3, &id, ONE_TIME).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.reasons().last().unwrap(), "limit");
    assert_eq!(e.krb.proofs(), 2);
    // A day later it works again.
    e.clock.advance(Duration::from_secs(DAY));
    let id = e.start(IP3, "carol").await;
    assert_eq!(e.respond(IP3, &id, ONE_TIME).await.unwrap().state(), "new_password");
}

#[tokio::test]
async fn failures_share_the_sign_in_limiter() {
    let e = harness();
    for _ in 0..3 {
        let id = e.start(IP, "carol").await;
        assert_eq!(e.respond(IP, &id, "guess").await.unwrap_err(), ApiError::Denied);
    }
    assert!(matches!(e.b.enroll_start(IP, "carol", None).await.unwrap_err(), ApiError::RateLimited(_)));
    assert!(matches!(e.b.auth_start(IP, "carol").unwrap_err(), ApiError::RateLimited(_)));
    // Other addresses are not blocked by this (user, IP) pair.
    let id = e.start(IP2, "carol").await;
    assert_eq!(e.respond(IP2, &id, ONE_TIME).await.unwrap().state(), "new_password");
}

#[tokio::test]
async fn password_attempts_are_capped() {
    let e = harness_cfg(|c| c.enrol.max_password_attempts = 2);
    let id = e.to_new_password("carol").await;
    assert_eq!(e.password(&id, "x").await.unwrap().state(), "password_rejected");
    assert_eq!(e.password(&id, "y").await.unwrap().state(), "password_rejected");
    assert_eq!(e.password(&id, NEW_PW).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.krb.password_changes(), 0);
}

#[tokio::test]
async fn directory_policy_is_shown() {
    let e = harness();
    e.dir.enrol.lock().unwrap().get_mut("carol").unwrap().policy =
        Some(crate::enrol::PwPolicy { min_length: 12, min_classes: 3 });
    let id = e.start(IP, "carol").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    assert_eq!(j(&r)["policy"], json!({"min_length": 12, "min_classes": 3}));
    assert_eq!(e.password(&id, "elevenchars").await.unwrap().state(), "password_rejected");
    assert_eq!(e.krb.password_changes(), 0, "length checked locally first");
}

#[tokio::test]
async fn refused_write_and_directory_outage_deny() {
    let e = harness();
    *e.dir.refuse_writes.lock().unwrap() = Some("insufficient access".into());
    let id = e.start(IP, "hank").await;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    assert_eq!(e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap_err(), ApiError::Denied);
    assert!(e.krb.otp_keys.lock().unwrap().get("hank").is_none());
    assert_eq!(e.audit.count("enrol_login_ok"), 0);

    *e.dir.unavailable.lock().unwrap() = true;
    let id = e.start(IP, "carol").await;
    assert_eq!(e.respond(IP, &id, ONE_TIME).await.unwrap_err(), ApiError::Denied);
    assert_eq!(e.reasons().last().unwrap(), "directory");
    assert_eq!(e.krb.proofs(), 1, "only hank's proof");
}

#[tokio::test]
async fn device_key_binds_the_final_session() {
    let e = harness();
    let d = TestDevice::new();
    let key = DeviceKey::from_spki(&d.spki()).unwrap();
    let id = e.b.enroll_start(IP, "hank", Some(key)).await.unwrap().conversation_id;
    let r = e.respond(IP, &id, ONE_TIME).await.unwrap();
    let r = e.b.enroll_totp(IP, &id, &e.code(&r)).await.unwrap();
    let v = j(&r);
    assert_eq!(v["state"], "authenticated");
    assert_eq!(v["device_bound"], true);
    assert_eq!(v["expires_in"], i32::MAX as u64);
    // Bound: a bare bearer without proof is refused.
    let token = v["session_token"].as_str().unwrap();
    assert_eq!(e.b.list_hosts(IP, token).await.unwrap_err(), ApiError::Unauthorized);
}

// ------------------------------------------------------------------ HTTP layer

async fn call(app: &axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
    let mut req = Request::builder().method("POST").uri(uri).body(Body::from(body.to_string())).unwrap();
    req.extensions_mut().insert(ConnectInfo(std::net::SocketAddr::from(([203, 0, 113, 7], 50000))));
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn http_contract() {
    let e = harness();
    let app = crate::api::router(e.b.clone());
    let (s, v) = call(&app, "/v1/enroll/start", r#"{"username":"hank"}"#).await;
    assert_eq!(s, StatusCode::OK);
    let id = v["conversation_id"].as_str().unwrap().to_string();
    assert_eq!(v["prompts"], json!([{"id":"password","style":"secret"}]));

    // Malformed → 400; unknown conversation → 200 denied.
    assert_eq!(call(&app, "/v1/enroll/respond", "nope").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "/v1/enroll/start", r#"{"username":"x","bogus":1}"#).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        call(&app, "/v1/enroll/start", r#"{"username":"x","device_key":"AAAA"}"#).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&app, "/v1/enroll/totp", r#"{"conversation_id":"nope","code":"123456"}"#).await,
        (StatusCode::OK, json!({"state":"denied"}))
    );

    let (s, v) =
        call(&app, "/v1/enroll/respond", &format!(r#"{{"conversation_id":"{id}","responses":["{ONE_TIME}"]}}"#)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["state"], "totp");
    let key = totp::base32_decode(v["secret"].as_str().unwrap()).unwrap();
    let code = totp::code_at(&key, e.clock.unix());
    let (s, v) = call(&app, "/v1/enroll/totp", &format!(r#"{{"conversation_id":"{id}","code":"{code}"}}"#)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["state"], "authenticated");
    assert_eq!(v["passkey_available"], false);
    assert_eq!(
        call(&app, "/v1/enroll/finish", &format!(r#"{{"conversation_id":"{id}"}}"#)).await,
        (StatusCode::OK, json!({"state":"done"}))
    );
    assert_eq!(
        call(&app, "/v1/enroll/passkey", r#"{"conversation_id":"x","mapping":"passkey:a,b"}"#).await,
        (StatusCode::OK, json!({"state":"denied"}))
    );
    assert_eq!(
        call(&app, "/v1/enroll/password", r#"{"conversation_id":"x","new_password":"p"}"#).await,
        (StatusCode::OK, json!({"state":"denied"}))
    );

    // Rate limit → 429 with retry_after.
    for _ in 0..3 {
        let (_, v) = call(&app, "/v1/enroll/start", r#"{"username":"carol"}"#).await;
        let id = v["conversation_id"].as_str().unwrap().to_string();
        call(&app, "/v1/enroll/respond", &format!(r#"{{"conversation_id":"{id}","responses":["guess"]}}"#)).await;
    }
    let (s, v) = call(&app, "/v1/enroll/start", r#"{"username":"carol"}"#).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(v["retry_after"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn disabled_enrolment_is_not_found() {
    let e = harness_cfg(|c| c.enrol.enabled = false);
    let app = crate::api::router(e.b.clone());
    for p in ["start", "respond", "password", "totp", "passkey", "finish"] {
        let (s, v) = call(&app, &format!("/v1/enroll/{p}"), r#"{"username":"carol"}"#).await;
        assert_eq!((s, v), (StatusCode::NOT_FOUND, json!({"state":"not_found"})), "{p}");
    }
}
