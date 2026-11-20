//! FreeIPA directory over LDAP (ldaps:// or ldap:// + StartTLS), SASL/GSSAPI bind
//! as the broker principal. The process sets `KRB5_CLIENT_KTNAME` to the broker
//! keytab and `KRB5CCNAME` to a private `MEMORY:` cache at start-up, so MIT GSSAPI
//! acquires the initiator ticket from the keytab by itself (no kinit, no cyrus-sasl).
//!
//! Enrolment (§16) writes bind as the USER (simple bind over TLS with the user's
//! own password) and rely only on IPA's self-service ACIs: "Users can create
//! self-managed tokens", "Managers can write basic token info", "Managers can delete
//! tokens" and "selfservice:Users can manage their own passkey mappings". The broker
//! principal itself only reads.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use ldap3::{dn_escape, ldap_escape, Ldap, LdapConnAsync, LdapConnSettings, LdapError, Mod, Scope, SearchEntry};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, error, warn};

use zeroize::Zeroizing;

use crate::config::Config;
use crate::directory::{DirError, Directory};
use crate::enrol::{parse_generalized_time, EnrolFacts, Factors, NewToken, PwPolicy};
use crate::hbac::{closure, DirectoryView, HbacRule, RemoteHost, UserView};
use crate::util::{first_rdn_value, norm_dn};

const RC_NO_SUCH_OBJECT: u32 = 32;
const RC_INSUFFICIENT_ACCESS: u32 = 50;
const RC_INVALID_CREDENTIALS: u32 = 49;
const RC_UNWILLING_TO_PERFORM: u32 = 53;

pub struct IpaDirectory {
    uris: Vec<String>,
    /// URIs for the binds as the user (enrolment writes).
    user_uris: Vec<String>,
    realm: String,
    suffix: String,
    hostgroup: String,
    hbac_service: String,
    timeout: Duration,
    tls: Arc<rustls::ClientConfig>,
    ca_cert: std::path::PathBuf,
}

impl IpaDirectory {
    pub fn new(cfg: &Config) -> anyhow::Result<IpaDirectory> {
        let pem = std::fs::read(&cfg.ldap.ca_cert)
            .map_err(|e| anyhow::anyhow!("reading ldap.ca_cert {}: {e}", cfg.ldap.ca_cert.display()))?;
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(&pem) {
            roots.add(c?)?;
        }
        if roots.is_empty() {
            anyhow::bail!("ldap.ca_cert contains no certificate");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(IpaDirectory {
            uris: cfg.ldap.uris.clone(),
            user_uris: cfg.enrol.user_ldap_uris(&cfg.ldap).to_vec(),
            realm: cfg.kerberos.realm.clone(),
            suffix: cfg.ldap.base_dn(&cfg.kerberos.realm),
            hostgroup: cfg.ldap.hostgroup.clone(),
            hbac_service: cfg.ldap.hbac_service.clone(),
            timeout: Duration::from_secs(cfg.ldap.timeout_secs),
            tls: Arc::new(tls),
            ca_cert: cfg.ldap.ca_cert.clone(),
        })
    }

    /// ldap3's GSSAPI bind uses the process default credential cache. A child
    /// ldapmodify gets this session's FILE: cache through its own environment,
    /// so concurrent users cannot accidentally bind with each other's ticket.
    async fn modify_as_ticket(&self, ccache: &str, ldif: &str) -> Result<(), DirError> {
        if !ccache.starts_with("FILE:") {
            return Err(DirError::InvalidCredentials);
        }
        let mut unavailable = false;
        for uri in &self.user_uris {
            let mut child = Command::new("/usr/bin/ldapmodify")
                .args(["-Q", "-Y", "GSSAPI", "-H", uri])
                .env("KRB5CCNAME", ccache)
                .env("LDAPTLS_CACERT", &self.ca_cert)
                .env("LDAPTLS_REQCERT", "demand")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| DirError::Unavailable(format!("ldapmodify start: {e}")))?;
            if let Some(mut stdin) = child.stdin.take() {
                if stdin.write_all(ldif.as_bytes()).await.is_err() {
                    unavailable = true;
                    continue;
                }
            }
            match tokio::time::timeout(self.timeout, child.wait()).await {
                Ok(Ok(status)) if status.success() => return Ok(()),
                Ok(Ok(_)) => return Err(DirError::Rejected("ticket-bound LDAP modify refused".into())),
                Ok(Err(_)) | Err(_) => unavailable = true,
            }
        }
        if unavailable {
            Err(DirError::Unavailable("ticket-bound LDAP modify unavailable".into()))
        } else {
            Err(DirError::Unavailable("no user LDAP URI".into()))
        }
    }

    async fn connect(&self) -> Result<Ldap, DirError> {
        let mut last = String::from("no LDAP URI configured");
        for uri in &self.uris {
            match tokio::time::timeout(self.timeout, self.connect_one(uri)).await {
                Ok(Ok(l)) => return Ok(l),
                Ok(Err(e)) => last = format!("{uri}: {e}"),
                Err(_) => last = format!("{uri}: timeout"),
            }
            warn!("LDAP {last}");
        }
        Err(DirError::Unavailable(last))
    }

    async fn connect_one(&self, uri: &str) -> Result<Ldap, String> {
        let (mut ldap, host) = self.open(uri).await?;
        let res = ldap.sasl_gssapi_bind(&host).await.map_err(|e| format!("GSSAPI bind: {e}"))?;
        res.success().map_err(|e| format!("GSSAPI bind: {e}"))?;
        Ok(ldap)
    }

    /// A TLS connection (ldaps://, or ldap:// + StartTLS) without a bind, and the host name.
    async fn open(&self, uri: &str) -> Result<(Ldap, String), String> {
        let host = uri
            .split("://")
            .nth(1)
            .and_then(|r| r.split(['/', ':']).next())
            .filter(|h| !h.is_empty())
            .ok_or("bad URI")?
            .to_string();
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.timeout)
            .set_config(self.tls.clone())
            .set_starttls(uri.starts_with("ldap://"));
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, uri).await.map_err(|e| e.to_string())?;
        ldap3::drive!(conn);
        ldap.with_timeout(self.timeout);
        Ok((ldap, host))
    }

    fn user_dn(&self, uid: &str) -> String {
        format!("uid={},cn=users,cn=accounts,{}", dn_escape(uid), self.suffix)
    }

    /// Simple bind as the user over TLS. Stops at the first server that refuses the
    /// credentials: every refused bind counts towards IPA's per-server lockout.
    async fn connect_user(&self, uid: &str, password: &Zeroizing<String>) -> Result<(Ldap, String), DirError> {
        let dn = self.user_dn(uid);
        let mut last = String::from("no LDAP URI configured");
        for uri in &self.user_uris {
            let (mut ldap, _) = match tokio::time::timeout(self.timeout, self.open(uri)).await {
                Ok(Ok(l)) => l,
                Ok(Err(e)) => {
                    last = format!("{uri}: {e}");
                    warn!("LDAP {last}");
                    continue;
                }
                Err(_) => {
                    last = format!("{uri}: timeout");
                    warn!("LDAP {last}");
                    continue;
                }
            };
            match ldap.simple_bind(&dn, password).await {
                Ok(r) if r.rc == 0 => return Ok((ldap, dn)),
                Ok(r) if r.rc == RC_INVALID_CREDENTIALS || r.rc == RC_UNWILLING_TO_PERFORM => {
                    let _ = ldap.unbind().await;
                    return Err(DirError::InvalidCredentials);
                }
                Ok(r) => last = format!("{uri}: user bind: rc={} {}", r.rc, r.text),
                Err(e) => last = format!("{uri}: user bind: {e}"),
            }
            warn!("LDAP {last}");
            let _ = ldap.unbind().await;
        }
        Err(DirError::Unavailable(last))
    }

    /// Tokens owned by `user_dn` (enabled or disabled) and passkey mappings on the entry.
    async fn factors(&self, ldap: &mut Ldap, user_dn: &str) -> Result<Factors, DirError> {
        let tokens = self
            .search(
                ldap,
                &format!("cn=otp,{}", self.suffix),
                Scope::OneLevel,
                &format!("(&(objectClass=ipatoken)(ipatokenOwner={}))", ldap_escape(user_dn)),
                &["ipatokenUniqueID"],
            )
            .await?;
        let user = self.search(ldap, user_dn, Scope::Base, "(objectClass=*)", &["ipaPasskey"]).await?;
        let passkeys = user.first().map(|e| attr(e, "ipapasskey").len()).unwrap_or(0);
        Ok(Factors { tokens: tokens.len(), passkeys })
    }

    async fn policy(&self, ldap: &mut Ldap) -> Option<PwPolicy> {
        let base = format!("cn=global_policy,cn={},cn=kerberos,{}", self.realm, self.suffix);
        let e = match self
            .search(ldap, &base, Scope::Base, "(objectClass=*)", &["krbPwdMinLength", "krbPwdMinDiffChars"])
            .await
        {
            Ok(e) => e,
            Err(e) => {
                debug!("password policy not readable: {e}");
                return None;
            }
        };
        let e = e.first()?;
        let num = |a: &str| attr(e, a).first().and_then(|v| v.trim().parse::<u32>().ok());
        Some(PwPolicy { min_length: num("krbpwdminlength")?, min_classes: num("krbpwdmindiffchars").unwrap_or(0) })
    }

    async fn load_enrol_facts(&self, ldap: &mut Ldap, uid: &str) -> Result<Option<EnrolFacts>, DirError> {
        let base = self.user_dn(uid);
        let attrs =
            ["memberOf", "krbLastPwdChange", "krbPasswordExpiration", "ipaPasskey", "ipaUserAuthType", "nsAccountLock"];
        let Some(e) = self.search(ldap, &base, Scope::Base, "(objectClass=*)", &attrs).await?.into_iter().next() else {
            return Ok(None);
        };
        let time = |a: &str| attr(&e, a).first().and_then(|v| parse_generalized_time(v));
        let f = self.factors(ldap, &e.dn).await?;
        Ok(Some(EnrolFacts {
            groups: attr(&e, "memberof"),
            last_password_change: time("krblastpwdchange"),
            password_expiration: time("krbpasswordexpiration"),
            tokens: f.tokens,
            passkeys: attr(&e, "ipapasskey").len(),
            auth_types: attr(&e, "ipauserauthtype").iter().map(|t| t.to_ascii_lowercase()).collect(),
            disabled: attr(&e, "nsaccountlock").iter().any(|v| v.eq_ignore_ascii_case("TRUE")),
            policy: self.policy(ldap).await,
            dn: e.dn,
        }))
    }

    async fn write_token(&self, ldap: &mut Ldap, user_dn: &str, t: &NewToken) -> Result<(), DirError> {
        let dn = format!("ipatokenuniqueid={},cn=otp,{}", dn_escape(&t.uuid), self.suffix);
        let v = |s: &str| HashSet::from([s.as_bytes().to_vec()]);
        let attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
            (b"objectClass".to_vec(), HashSet::from([b"top".to_vec(), b"ipatoken".to_vec(), b"ipatokentotp".to_vec()])),
            (b"ipatokenUniqueID".to_vec(), v(&t.uuid)),
            (b"ipatokenOwner".to_vec(), v(user_dn)),
            (b"managedBy".to_vec(), v(user_dn)),
            (b"ipatokenDisabled".to_vec(), v("TRUE")),
            (b"ipatokenOTPkey".to_vec(), HashSet::from([t.key.to_vec()])),
            (b"ipatokenOTPalgorithm".to_vec(), v("sha1")),
            (b"ipatokenOTPdigits".to_vec(), v("6")),
            (b"ipatokenTOTPclockOffset".to_vec(), v("0")),
            (b"ipatokenTOTPtimeStep".to_vec(), v("30")),
            (b"description".to_vec(), v(&t.description)),
        ];
        ldap.with_timeout(self.timeout);
        let r = ldap.add(&dn, attrs).await.map_err(|e| DirError::Unavailable(format!("token add: {e}")))?;
        if r.rc != 0 {
            return Err(DirError::Rejected(format!("token add: rc={} {}", r.rc, r.text)));
        }
        let enable = vec![Mod::Replace(b"ipatokenDisabled".to_vec(), HashSet::from([b"FALSE".to_vec()]))];
        ldap.with_timeout(self.timeout);
        let r = ldap.modify(&dn, enable).await;
        let err = match r {
            Ok(r) if r.rc == 0 => return Ok(()),
            Ok(r) => DirError::Rejected(format!("token enable: rc={} {}", r.rc, r.text)),
            Err(e) => DirError::Unavailable(format!("token enable: {e}")),
        };
        // Leave nothing behind that would block the next attempt (G3 counts disabled tokens).
        ldap.with_timeout(self.timeout);
        match ldap.delete(&dn).await {
            Ok(r) if r.rc == 0 => {}
            Ok(r) => error!("removing the disabled token {dn} failed: rc={} {}", r.rc, r.text),
            Err(e) => error!("removing the disabled token {dn} failed: {e}"),
        }
        Err(err)
    }

    async fn write_passkey(&self, ldap: &mut Ldap, user_dn: &str, mapping: &str) -> Result<(), DirError> {
        let e = self.search(ldap, user_dn, Scope::Base, "(objectClass=*)", &["objectClass"]).await?;
        let has_class = e
            .first()
            .map(|e| attr(e, "objectclass").iter().any(|c| c.eq_ignore_ascii_case("ipapasskeyuser")))
            .unwrap_or(false);
        let mut mods = Vec::new();
        if !has_class {
            // New users lack it; the self-service ACI allows adding exactly this class.
            mods.push(Mod::Add(b"objectClass".to_vec(), HashSet::from([b"ipapasskeyuser".to_vec()])));
        }
        mods.push(Mod::Add(b"ipapasskey".to_vec(), HashSet::from([mapping.as_bytes().to_vec()])));
        ldap.with_timeout(self.timeout);
        match ldap.modify(user_dn, mods).await {
            Ok(r) if r.rc == 0 => Ok(()),
            Ok(r) => Err(DirError::Rejected(format!("passkey add: rc={} {}", r.rc, r.text))),
            Err(e) => Err(DirError::Unavailable(format!("passkey add: {e}"))),
        }
    }

    async fn search(
        &self,
        ldap: &mut Ldap,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, DirError> {
        ldap.with_timeout(self.timeout);
        let r =
            ldap.search(base, scope, filter, attrs.to_vec()).await.map_err(|e| DirError::Unavailable(e.to_string()))?;
        match r.success() {
            Ok((entries, _)) => Ok(entries.into_iter().map(SearchEntry::construct).collect()),
            Err(LdapError::LdapResult { result }) if result.rc == RC_NO_SUCH_OBJECT => Ok(Vec::new()),
            Err(LdapError::LdapResult { result }) if result.rc == RC_INSUFFICIENT_ACCESS => {
                Err(DirError::InsufficientAccess(format!("search {base}")))
            }
            Err(e) => Err(DirError::Unavailable(format!("search {base}: {e}"))),
        }
    }

    async fn dns_a(&self, ldap: &mut Ldap, fqdn: &str) -> Result<Option<Ipv4Addr>, DirError> {
        let labels: Vec<&str> = fqdn.split('.').collect();
        for i in 1..labels.len() {
            let name = labels[..i].join(".");
            let zone = labels[i..].join(".");
            for z in [format!("{zone}."), zone.clone()] {
                let base = format!("idnsname={name},idnsname={z},cn=dns,{}", self.suffix);
                let e = self.search(ldap, &base, Scope::Base, "(objectClass=*)", &["aRecord"]).await?;
                if let Some(e) = e.first() {
                    return Ok(attr(e, "arecord").iter().find_map(|a| a.parse().ok()));
                }
            }
        }
        // Nothing found: distinguish "no record" from "cannot read cn=dns at all".
        let zones = self
            .search(ldap, &format!("cn=dns,{}", self.suffix), Scope::OneLevel, "(objectClass=idnszone)", &["idnsname"])
            .await?;
        if zones.is_empty() {
            return Err(DirError::InsufficientAccess(
                "cannot read any DNS zone under cn=dns; grant the broker principal read access to DNS records".into(),
            ));
        }
        Ok(None)
    }

    async fn load_view(&self, ldap: &mut Ldap) -> Result<DirectoryView, DirError> {
        let s = &self.suffix;
        let service_dn = format!("cn={},cn=hbacservices,cn=hbac,{s}", self.hbac_service);
        let rules_raw = self
            .search(
                ldap,
                &format!("cn=hbac,{s}"),
                Scope::OneLevel,
                "(objectClass=ipahbacrule)",
                &[
                    "cn",
                    "ipaEnabledFlag",
                    "accessRuleType",
                    "userCategory",
                    "hostCategory",
                    "serviceCategory",
                    "memberUser",
                    "memberHost",
                    "memberService",
                ],
            )
            .await?;
        let rules: Vec<HbacRule> = rules_raw
            .iter()
            .map(|e| HbacRule {
                name: attr(e, "cn").first().cloned().unwrap_or_default(),
                enabled: attr(e, "ipaenabledflag").first().map(|v| v.eq_ignore_ascii_case("TRUE")).unwrap_or(false),
                allow: attr(e, "accessruletype").first().map(|v| v.eq_ignore_ascii_case("allow")).unwrap_or(true),
                user_category_all: attr(e, "usercategory").iter().any(|v| v.eq_ignore_ascii_case("all")),
                host_category_all: attr(e, "hostcategory").iter().any(|v| v.eq_ignore_ascii_case("all")),
                service_category_all: attr(e, "servicecategory").iter().any(|v| v.eq_ignore_ascii_case("all")),
                member_users: attr(e, "memberuser"),
                member_hosts: attr(e, "memberhost"),
                member_services: attr(e, "memberservice"),
            })
            .collect();

        let svc_groups = self
            .search(
                ldap,
                &format!("cn=hbacservicegroups,cn=hbac,{s}"),
                Scope::OneLevel,
                &format!("(member={})", ldap_escape(&service_dn)),
                &["cn"],
            )
            .await?;
        let service_groups: HashSet<String> = svc_groups.iter().map(|e| norm_dn(&e.dn)).collect();

        // Host groups: parent map for hosts and nested host groups.
        let hgs = self
            .search(
                ldap,
                &format!("cn=hostgroups,cn=accounts,{s}"),
                Scope::OneLevel,
                "(objectClass=ipahostgroup)",
                &["member"],
            )
            .await?;
        let mut parents: HashMap<String, Vec<String>> = HashMap::new();
        let mut hosts: HashSet<String> = HashSet::new();
        for g in &hgs {
            let gdn = norm_dn(&g.dn);
            for m in attr(g, "member") {
                let m = norm_dn(&m);
                if m.starts_with("fqdn=") {
                    hosts.insert(m.clone());
                }
                parents.entry(m).or_default().push(gdn.clone());
            }
        }
        let remote_dn = norm_dn(&format!("cn={},cn=hostgroups,cn=accounts,{s}", self.hostgroup));
        let mut remote_hosts = Vec::new();
        let mut dns_denied = None;
        for h in hosts {
            let groups = closure(parents.get(&h).cloned().unwrap_or_default(), &parents);
            if !groups.contains(&remote_dn) {
                continue;
            }
            let Some(fqdn) = first_rdn_value(&h, "fqdn") else { continue };
            let ipv4 = match self.dns_a(ldap, &fqdn).await {
                Ok(a) => a,
                Err(DirError::InsufficientAccess(m)) => {
                    dns_denied = Some(m);
                    None
                }
                Err(e) => return Err(e),
            };
            if ipv4.is_none() {
                debug!(host = %fqdn, "no A record");
            }
            remote_hosts.push(RemoteHost { fqdn, dn: h, ipv4, hostgroups: groups });
        }
        if let Some(m) = dns_denied {
            error!("LDAP insufficient access: {m}");
        }
        remote_hosts.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));

        // User groups: parent map for nested groups.
        let groups = self
            .search(
                ldap,
                &format!("cn=groups,cn=accounts,{s}"),
                Scope::OneLevel,
                "(objectClass=ipausergroup)",
                &["member"],
            )
            .await?;
        let mut group_parents: HashMap<String, Vec<String>> = HashMap::new();
        for g in &groups {
            let gdn = norm_dn(&g.dn);
            for m in attr(g, "member") {
                let m = norm_dn(&m);
                if m.contains(",cn=groups,cn=accounts,") {
                    group_parents.entry(m).or_default().push(gdn.clone());
                }
            }
        }
        Ok(DirectoryView { rules, service_dn: norm_dn(&service_dn), service_groups, remote_hosts, group_parents })
    }
}

/// Attribute values by lower-cased name.
fn attr(e: &SearchEntry, name: &str) -> Vec<String> {
    e.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).unwrap_or_default()
}

#[async_trait]
impl Directory for IpaDirectory {
    async fn view(&self) -> Result<DirectoryView, DirError> {
        let mut ldap = self.connect().await?;
        let r = tokio::time::timeout(self.timeout * 6, self.load_view(&mut ldap))
            .await
            .unwrap_or_else(|_| Err(DirError::Unavailable("directory snapshot timed out".into())));
        let _ = ldap.unbind().await;
        r
    }

    async fn user(&self, uid: &str) -> Result<Option<UserView>, DirError> {
        let mut ldap = self.connect().await?;
        let base = format!("uid={},cn=users,cn=accounts,{}", ldap_escape(uid), self.suffix);
        let r = self.search(&mut ldap, &base, Scope::Base, "(objectClass=*)", &["memberOf", "nsAccountLock"]).await;
        let _ = ldap.unbind().await;
        Ok(r?.into_iter().next().map(|e| UserView {
            disabled: attr(&e, "nsaccountlock").iter().any(|v| v.eq_ignore_ascii_case("TRUE")),
            groups: attr(&e, "memberof"),
            dn: e.dn,
            pwd_last_set_unix: None,
        }))
    }

    async fn enrol_facts(&self, uid: &str) -> Result<Option<EnrolFacts>, DirError> {
        let mut ldap = self.connect().await?;
        let r = tokio::time::timeout(self.timeout * 3, self.load_enrol_facts(&mut ldap, uid))
            .await
            .unwrap_or_else(|_| Err(DirError::Unavailable("enrolment facts timed out".into())));
        let _ = ldap.unbind().await;
        r
    }

    async fn user_factors(&self, uid: &str, password: &Zeroizing<String>) -> Result<Factors, DirError> {
        let (mut ldap, dn) = self.connect_user(uid, password).await?;
        let r = self.factors(&mut ldap, &dn).await;
        let _ = ldap.unbind().await;
        r
    }

    async fn add_totp_token(&self, uid: &str, password: &Zeroizing<String>, token: &NewToken) -> Result<(), DirError> {
        let (mut ldap, dn) = self.connect_user(uid, password).await?;
        let r = self.write_token(&mut ldap, &dn, token).await;
        let _ = ldap.unbind().await;
        r
    }

    async fn add_passkey(&self, uid: &str, password: &Zeroizing<String>, mapping: &str) -> Result<(), DirError> {
        let (mut ldap, dn) = self.connect_user(uid, password).await?;
        let r = self.write_passkey(&mut ldap, &dn, mapping).await;
        let _ = ldap.unbind().await;
        r
    }

    async fn add_passkey_with_ticket(&self, uid: &str, ccache: &str, mapping: &str) -> Result<(), DirError> {
        let dn = self.user_dn(uid);
        let value = STANDARD.encode(mapping.as_bytes());
        let header = format!("dn: {dn}\nchangetype: modify\n");
        let with_class = format!(
            "{header}add: objectClass\nobjectClass: ipapasskeyuser\n-\nadd: ipapasskey\nipapasskey:: {value}\n"
        );
        match self.modify_as_ticket(ccache, &with_class).await {
            Ok(()) => Ok(()),
            Err(DirError::Rejected(_)) => {
                // An account with a mapping already has the object class.
                let mapping_only = format!("{header}add: ipapasskey\nipapasskey:: {value}\n");
                self.modify_as_ticket(ccache, &mapping_only).await
            }
            Err(e) => Err(e),
        }
    }
}
