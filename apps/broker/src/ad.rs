//! Active Directory backend (this fork; `directory.backend = "ad"`).
//!
//! AD has no HBAC rules, so the directory view is *synthesized* from groups:
//!
//! * Inventory: enabled computer accounts that are (nested) members of the computer
//!   group `ad.hosts_group` (default `PLANK-Hosts`).
//! * Access: a user reaches host `H` when a (nested) member of the security group
//!   `<ad.access_group_prefix><H>` (default `PLANK-<H>`, `H` = the computer's
//!   sAMAccountName without `$`) or of `ad.all_hosts_group` (default `PLANK-AllHosts`).
//!
//! Each host becomes one synthetic [`HbacRule`] naming those groups, so `hbac.rs` and
//! everything above it work unchanged. Nesting is resolved by the DC itself with
//! LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941): [`UserView::groups`] is
//! already transitive and `group_parents` stays empty. The user's primary group
//! (normally Domain Users) is not visible through `member`; do not use it for access.
//!
//! Sign-in is a plain-password Kerberos AS exchange (see `mit.rs`, `kerberos.password_only`);
//! nothing here binds as the user. Enrolment, tokens and passkeys do not exist in AD.
//!
//! The pure part (view synthesis, account flags) is always compiled and unit tested.
//! The LDAP part needs the `system` feature, like `ldap.rs`.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use tracing::{error, warn};

use crate::config::AdConfig;
use crate::hbac::{DirectoryView, HbacRule, RemoteHost};
use crate::util::{norm_dn, valid_hostname};

/// LDAP_MATCHING_RULE_IN_CHAIN: transitive group membership evaluated by the DC.
pub const IN_CHAIN: &str = "1.2.840.113556.1.4.1941";
/// Synthetic HBAC service the generated rules name (never read from the directory).
pub const SERVICE_DN: &str = "cn=plank-remote,cn=hbacservices,cn=ad-synthetic";

const UF_ACCOUNTDISABLE: u32 = 0x2;
/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;

/// A computer account found in the hosts group.
#[derive(Debug, Clone)]
pub struct AdComputer {
    pub dn: String,
    /// sAMAccountName, usually `NAME$`.
    pub sam: String,
    pub dns_name: String,
    /// Raw `userAccountControl`.
    pub uac: Option<String>,
    pub ipv4: Option<Ipv4Addr>,
}

/// A security group (name and DN).
#[derive(Debug, Clone)]
pub struct AdGroup {
    pub cn: String,
    pub dn: String,
}

/// `userAccountControl` ACCOUNTDISABLE. A missing or unparsable value counts as disabled
/// (fail closed).
pub fn account_disabled(uac: Option<&str>) -> bool {
    match uac.and_then(|v| v.trim().parse::<u32>().ok()) {
        Some(v) => v & UF_ACCOUNTDISABLE != 0,
        None => true,
    }
}

/// `accountExpires` (FILETIME, 100 ns since 1601). Absent, `0` and `0x7FFF…` mean never.
pub fn account_expired(expires: Option<&str>, now_unix: u64) -> bool {
    let Some(v) = expires.and_then(|v| v.trim().parse::<u64>().ok()) else { return false };
    if v == 0 || v >= i64::MAX as u64 {
        return false;
    }
    let unix = (v / 10_000_000) as i128 - FILETIME_UNIX_OFFSET as i128;
    unix <= now_unix as i128
}

const UF_LOCKOUT: u32 = 0x10;
const UF_PASSWORD_EXPIRED: u32 = 0x80_0000;

/// FILETIME (100 ns since 1601) to unix seconds; `None` for 0 / never / before 1970.
fn filetime_unix(v: Option<&str>) -> Option<u64> {
    let v = v?.trim().parse::<u64>().ok()?;
    if v == 0 || v >= i64::MAX as u64 {
        return None;
    }
    (v / 10_000_000).checked_sub(FILETIME_UNIX_OFFSET)
}

/// Account state of a user: `(disabled, password last set)`. Disabled covers ACCOUNTDISABLE,
/// an expired account, a locked-out account and an expired (or must-change) password; an
/// unreadable `userAccountControl` fails closed.
pub fn user_state(
    uac: Option<&str>,
    expires: Option<&str>,
    computed_uac: Option<&str>,
    pwd_last_set: Option<&str>,
    now_unix: u64,
) -> (bool, Option<u64>) {
    // A constructed attribute: if the DC does not return it we cannot tell locked-out or
    // expired accounts apart, so fail closed.
    let Some(computed) = computed_uac.and_then(|v| v.trim().parse::<u32>().ok()) else {
        return (true, filetime_unix(pwd_last_set));
    };
    // pwdLastSet = 0: the user must change the password at next logon.
    let must_change = pwd_last_set.is_some_and(|v| v.trim() == "0");
    let disabled = account_disabled(uac)
        || account_expired(expires, now_unix)
        || computed & (UF_LOCKOUT | UF_PASSWORD_EXPIRED) != 0
        || must_change;
    (disabled, filetime_unix(pwd_last_set))
}

/// Computer name as admins see it: sAMAccountName without the trailing `$`.
fn computer_name(c: &AdComputer) -> String {
    let n = c.sam.trim().trim_end_matches('$');
    if n.is_empty() {
        c.dns_name.split('.').next().unwrap_or("").to_string()
    } else {
        n.to_string()
    }
}

/// Synthesize the directory view. `groups` are the groups whose name starts with the
/// access prefix plus the all-hosts group (the hosts group itself is ignored).
///
/// Fail closed on ambiguity: a group name that occurs twice grants nothing, a computer whose
/// `dNSHostName` does not start with its own name (a spoofable attribute) is skipped, and
/// host names claimed by more than one computer are all dropped.
pub fn build_view(cfg: &AdConfig, computers: &[AdComputer], groups: &[AdGroup]) -> DirectoryView {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for g in groups {
        *seen.entry(g.cn.to_ascii_lowercase()).or_default() += 1;
    }
    for (name, n) in &seen {
        if *n > 1 {
            error!("AD: {n} groups are named {name}; none of them grants access until the name is unique");
        }
    }
    let groups: Vec<&AdGroup> = groups.iter().filter(|g| seen[&g.cn.to_ascii_lowercase()] == 1).collect();

    let mut eligible: Vec<(String, &AdComputer)> = Vec::new();
    for c in computers {
        if account_disabled(c.uac.as_deref()) {
            continue;
        }
        let fqdn = c.dns_name.trim().trim_end_matches('.').to_ascii_lowercase();
        if !valid_hostname(&fqdn) {
            continue;
        }
        let name = computer_name(c);
        let label = fqdn.split('.').next().unwrap_or("");
        if !c.sam.trim().ends_with('$') || name.is_empty() || !label.eq_ignore_ascii_case(&name) {
            warn!(dn = %c.dn, host = %fqdn, "AD: dNSHostName does not start with the computer name; skipped");
            continue;
        }
        eligible.push((fqdn, c));
    }
    let mut count: HashMap<&str, usize> = HashMap::new();
    for (f, _) in &eligible {
        *count.entry(f.as_str()).or_default() += 1;
    }
    let mut remote_hosts = Vec::new();
    let mut rules = Vec::new();
    for (fqdn, c) in &eligible {
        if count[fqdn.as_str()] > 1 {
            error!(host = %fqdn, "AD: several computers claim this host name; all of them are dropped");
            continue;
        }
        let want = format!("{}{}", cfg.access_group_prefix, computer_name(c));
        let member_users: Vec<String> = groups
            .iter()
            .filter(|g| !g.cn.eq_ignore_ascii_case(&cfg.hosts_group))
            .filter(|g| g.cn.eq_ignore_ascii_case(&want) || g.cn.eq_ignore_ascii_case(&cfg.all_hosts_group))
            .map(|g| g.dn.clone())
            .collect();
        rules.push(HbacRule {
            name: format!("plank-{fqdn}"),
            enabled: true,
            allow: true,
            member_users,
            member_hosts: vec![c.dn.clone()],
            member_services: vec![SERVICE_DN.to_string()],
            ..Default::default()
        });
        remote_hosts.push(RemoteHost { fqdn: fqdn.clone(), dn: c.dn.clone(), ipv4: c.ipv4, hostgroups: Default::default() });
    }
    remote_hosts.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));
    DirectoryView {
        rules,
        service_dn: norm_dn(SERVICE_DN),
        service_groups: Default::default(),
        remote_hosts,
        group_parents: Default::default(),
    }
}

#[cfg(feature = "system")]
pub use backend::AdDirectory;

#[cfg(feature = "system")]
mod backend {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use ldap3::{ldap_escape, Ldap, LdapConnAsync, LdapConnSettings, LdapError, Scope, SearchEntry};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    use tracing::debug;
    use zeroize::Zeroizing;

    use super::*;
    use crate::config::Config;
    use crate::directory::{DirError, Directory};
    use crate::enrol::{EnrolFacts, Factors, NewToken};
    use crate::hbac::UserView;

    /// groupType bit 0x80000000: security-enabled (a distribution group cannot grant access).
    const SECURITY_GROUP: &str = "(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648)";
    const RC_NO_SUCH_OBJECT: u32 = 32;
    const RC_INSUFFICIENT_ACCESS: u32 = 50;

    pub struct AdDirectory {
        uris: Vec<String>,
        cfg: AdConfig,
        base: String,
        timeout: Duration,
        tls: Arc<rustls::ClientConfig>,
    }

    fn attr(e: &SearchEntry, name: &str) -> Vec<String> {
        e.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    fn unsupported<T>() -> Result<T, DirError> {
        Err(DirError::Rejected("not supported with Active Directory".into()))
    }

    impl AdDirectory {
        pub fn new(cfg: &Config) -> anyhow::Result<AdDirectory> {
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
            Ok(AdDirectory {
                uris: cfg.ldap.uris.clone(),
                cfg: cfg.ad.clone(),
                base: cfg.ldap.base_dn(&cfg.kerberos.realm),
                timeout: Duration::from_secs(cfg.ldap.timeout_secs),
                tls: Arc::new(tls),
            })
        }

        fn user_base(&self) -> &str {
            self.cfg.user_base.as_deref().unwrap_or(&self.base)
        }

        fn computer_base(&self) -> &str {
            self.cfg.computer_base.as_deref().unwrap_or(&self.base)
        }

        /// The OU holding the PLANK groups (validated as present by the config).
        fn groups_base(&self) -> &str {
            self.cfg.groups_base.as_deref().unwrap_or(&self.base)
        }

        /// SASL/GSSAPI bind as the broker's machine account (keytab via KRB5_CLIENT_KTNAME).
        /// The URI host must be the DC's FQDN: it names the `ldap/<fqdn>` service
        /// principal and the certificate subject.
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
            let res = ldap.sasl_gssapi_bind(&host).await.map_err(|e| format!("GSSAPI bind: {e}"))?;
            res.success().map_err(|e| format!("GSSAPI bind: {e}"))?;
            Ok(ldap)
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
            let r = ldap
                .search(base, scope, filter, attrs.to_vec())
                .await
                .map_err(|e| DirError::Unavailable(e.to_string()))?;
            match r.success() {
                Ok((entries, _)) => Ok(entries.into_iter().map(SearchEntry::construct).collect()),
                Err(LdapError::LdapResult { result }) if result.rc == RC_NO_SUCH_OBJECT => Ok(Vec::new()),
                Err(LdapError::LdapResult { result }) if result.rc == RC_INSUFFICIENT_ACCESS => {
                    Err(DirError::InsufficientAccess(format!("search {base}")))
                }
                Err(e) => Err(DirError::Unavailable(format!("search {base}: {e}"))),
            }
        }

        /// IPv4 address of a host: the configured override, else the system resolver.
        async fn resolve(&self, fqdn: &str) -> Option<Ipv4Addr> {
            if let Some(a) = self.cfg.host_ipv4.get(fqdn) {
                return Some(*a);
            }
            let lookup = tokio::net::lookup_host((fqdn.to_string(), 0));
            match tokio::time::timeout(self.timeout, lookup).await {
                Ok(Ok(addrs)) => addrs.into_iter().find_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                }),
                Ok(Err(e)) => {
                    debug!(host = %fqdn, "DNS: {e}");
                    None
                }
                Err(_) => {
                    debug!(host = %fqdn, "DNS: timeout");
                    None
                }
            }
        }

        async fn load_view(&self, ldap: &mut Ldap) -> Result<DirectoryView, DirError> {
            let base = self.computer_base().to_string();
            let gbase = self.groups_base().to_string();
            let hg = self
                .search(
                    ldap,
                    &gbase,
                    Scope::Subtree,
                    &format!("(&{SECURITY_GROUP}(cn={}))", ldap_escape(&self.cfg.hosts_group)),
                    &["cn"],
                )
                .await?;
            if hg.len() > 1 {
                error!("AD: {} groups are named {}; no hosts are listed", hg.len(), self.cfg.hosts_group);
                return Ok(build_view(&self.cfg, &[], &[]));
            }
            let Some(hosts_group) = hg.into_iter().next() else {
                error!("AD security group {} not found under {gbase}", self.cfg.hosts_group);
                return Ok(build_view(&self.cfg, &[], &[]));
            };
            let comps = self
                .search(
                    ldap,
                    &base,
                    Scope::Subtree,
                    &format!(
                        "(&(objectCategory=computer)(memberOf:{IN_CHAIN}:={}))",
                        ldap_escape(&hosts_group.dn)
                    ),
                    &["dNSHostName", "sAMAccountName", "userAccountControl"],
                )
                .await?;
            let mut computers = Vec::new();
            for e in comps {
                let Some(dns_name) = attr(&e, "dnshostname").into_iter().next() else {
                    warn!(dn = %e.dn, "computer has no dNSHostName; skipped");
                    continue;
                };
                let fqdn = dns_name.trim_end_matches('.').to_ascii_lowercase();
                let ipv4 = self.resolve(&fqdn).await;
                if ipv4.is_none() {
                    debug!(host = %fqdn, "no address");
                }
                computers.push(AdComputer {
                    sam: attr(&e, "samaccountname").into_iter().next().unwrap_or_default(),
                    uac: attr(&e, "useraccountcontrol").into_iter().next(),
                    dns_name,
                    ipv4,
                    dn: e.dn,
                });
            }
            let g = self
                .search(
                    ldap,
                    &gbase,
                    Scope::Subtree,
                    &format!(
                        "(&{SECURITY_GROUP}(|(cn={}*)(cn={})))",
                        ldap_escape(&self.cfg.access_group_prefix),
                        ldap_escape(&self.cfg.all_hosts_group)
                    ),
                    &["cn"],
                )
                .await?;
            let groups: Vec<AdGroup> = g
                .into_iter()
                .filter_map(|e| Some(AdGroup { cn: attr(&e, "cn").into_iter().next()?, dn: e.dn }))
                .collect();
            Ok(build_view(&self.cfg, &computers, &groups))
        }

        /// Which account attributes the DC returns for `uid` (for `selftest`).
        pub async fn account_report(&self, uid: &str) -> Result<String, DirError> {
            let mut ldap = self.connect().await?;
            let found = self
                .search(
                    &mut ldap,
                    self.user_base(),
                    Scope::Subtree,
                    &format!("(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))", ldap_escape(uid)),
                    &["userAccountControl", "accountExpires", "msDS-User-Account-Control-Computed", "pwdLastSet"],
                )
                .await;
            let _ = ldap.unbind().await;
            let Some(e) = found?.into_iter().next() else { return Ok(format!("user {uid}: not found")) };
            let has = |a: &str| if attr(&e, a).is_empty() { "MISSING" } else { "returned" };
            Ok(format!(
                "attributes for {uid}: userAccountControl {}, accountExpires {}, \
                 msDS-User-Account-Control-Computed {} (missing = every user is treated as disabled), pwdLastSet {}",
                has("useraccountcontrol"),
                has("accountexpires"),
                has("msds-user-account-control-computed"),
                has("pwdlastset"),
            ))
        }

        async fn load_user(&self, ldap: &mut Ldap, uid: &str) -> Result<Option<UserView>, DirError> {
            let found = self
                .search(
                    ldap,
                    self.user_base(),
                    Scope::Subtree,
                    &format!(
                        "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
                        ldap_escape(uid)
                    ),
                    &["userAccountControl", "accountExpires", "msDS-User-Account-Control-Computed", "pwdLastSet"],
                )
                .await?;
            let mut it = found.into_iter();
            let (Some(e), None) = (it.next(), it.next()) else { return Ok(None) };
            let first = |a: &str| attr(&e, a).into_iter().next();
            if first("msds-user-account-control-computed").is_none() {
                warn!("AD did not return msDS-User-Account-Control-Computed for {uid}: treated as disabled");
            }
            let (disabled, pwd_last_set_unix) = user_state(
                first("useraccountcontrol").as_deref(),
                first("accountexpires").as_deref(),
                first("msds-user-account-control-computed").as_deref(),
                first("pwdlastset").as_deref(),
                crate::util::unix_now(),
            );
            let groups = self
                .search(
                    ldap,
                    self.groups_base(),
                    Scope::Subtree,
                    &format!("(&{SECURITY_GROUP}(member:{IN_CHAIN}:={}))", ldap_escape(&e.dn)),
                    &["cn"],
                )
                .await?
                .into_iter()
                .map(|g| g.dn)
                .collect();
            Ok(Some(UserView { disabled, dn: e.dn, groups, pwd_last_set_unix }))
        }
    }

    #[async_trait]
    impl Directory for AdDirectory {
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
            let r = tokio::time::timeout(self.timeout * 3, self.load_user(&mut ldap, uid))
                .await
                .unwrap_or_else(|_| Err(DirError::Unavailable("user lookup timed out".into())));
            let _ = ldap.unbind().await;
            r
        }

        async fn enrol_facts(&self, _uid: &str) -> Result<Option<EnrolFacts>, DirError> {
            Ok(None)
        }
        async fn user_factors(&self, _uid: &str, _pw: &Zeroizing<String>) -> Result<Factors, DirError> {
            unsupported()
        }
        async fn add_totp_token(&self, _uid: &str, _pw: &Zeroizing<String>, _t: &NewToken) -> Result<(), DirError> {
            unsupported()
        }
        async fn add_passkey(&self, _uid: &str, _pw: &Zeroizing<String>, _m: &str) -> Result<(), DirError> {
            unsupported()
        }
        async fn add_passkey_with_ticket(&self, _uid: &str, _cc: &str, _m: &str) -> Result<(), DirError> {
            unsupported()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AdConfig {
        AdConfig::default()
    }

    fn comp(name: &str, uac: &str) -> AdComputer {
        AdComputer {
            dn: format!("CN={name},OU=Workstations,DC=example,DC=org"),
            sam: format!("{name}$"),
            dns_name: format!("{name}.example.org"),
            uac: Some(uac.into()),
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 50)),
        }
    }

    fn grp(cn: &str) -> AdGroup {
        AdGroup { cn: cn.into(), dn: format!("CN={cn},OU=Groups,DC=example,DC=org") }
    }

    #[test]
    fn disabled_flag_and_expiry() {
        assert!(!account_disabled(Some("4096")));
        assert!(account_disabled(Some("4098")), "workstation trust + ACCOUNTDISABLE");
        assert!(account_disabled(None) && account_disabled(Some("x")), "unknown fails closed");
        let now = 1_800_000_000;
        assert!(!account_expired(None, now));
        assert!(!account_expired(Some("0"), now));
        assert!(!account_expired(Some("9223372036854775807"), now));
        let ft = |unix: u64| ((unix + FILETIME_UNIX_OFFSET) * 10_000_000).to_string();
        assert!(account_expired(Some(&ft(now - 1)), now));
        assert!(account_expired(Some(&ft(now)), now));
        assert!(!account_expired(Some(&ft(now + 3600)), now));
        assert!(account_expired(Some("1"), now), "a date before 1970 is long past");
    }

    #[test]
    fn view_names_the_per_host_and_all_hosts_groups() {
        let comps = [comp("WS01", "4096"), comp("WS02", "4096"), comp("OFF", "4098")];
        let groups = [grp("PLANK-WS01"), grp("PLANK-ws02"), grp("PLANK-AllHosts"), grp("PLANK-Hosts"), grp("PLANK-OFF")];
        let v = build_view(&cfg(), &comps, &groups);
        let names: Vec<&str> = v.remote_hosts.iter().map(|h| h.fqdn.as_str()).collect();
        assert_eq!(names, ["ws01.example.org", "ws02.example.org"], "disabled computer is not listed");
        assert_eq!(v.rules.len(), 2);
        let r = &v.rules[0];
        assert!(r.counts());
        assert_eq!(r.member_users.len(), 2, "PLANK-WS01 and PLANK-AllHosts, not PLANK-Hosts or PLANK-WS02");
        assert!(r.member_users.iter().any(|d| d.starts_with("CN=PLANK-WS01,")));
        assert!(r.member_users.iter().any(|d| d.starts_with("CN=PLANK-AllHosts,")));
        assert!(v.rules[1].member_users.iter().any(|d| d.starts_with("CN=PLANK-ws02,")), "group names match case-insensitively");
    }

    #[test]
    fn assignment_through_direct_nested_and_all_hosts_groups() {
        use crate::hbac::{assigned_hosts, UserView};
        let comps = [comp("WS01", "4096"), comp("WS02", "4096")];
        let groups = [grp("PLANK-WS01"), grp("PLANK-AllHosts")];
        let v = build_view(&cfg(), &comps, &groups);
        let user = |gs: &[&str]| UserView {
            disabled: false,
            pwd_last_set_unix: None,
            dn: "CN=Anna,OU=Staff,DC=example,DC=org".into(),
            // The DC already expands nesting (IN_CHAIN), so nested membership arrives as a flat list.
            groups: gs.iter().map(|g| grp(g).dn).collect(),
        };
        assert_eq!(assigned_hosts(&v, &user(&["PLANK-WS01"])), ["ws01.example.org"]);
        assert_eq!(assigned_hosts(&v, &user(&["PLANK-AllHosts"])), ["ws01.example.org", "ws02.example.org"]);
        assert_eq!(assigned_hosts(&v, &user(&["PLANK-WS01", "Domain Users"])), ["ws01.example.org"]);
        assert!(assigned_hosts(&v, &user(&["PLANK-Hosts", "Domain Users"])).is_empty());
        assert!(assigned_hosts(&v, &user(&[])).is_empty());
        // DNs from the directory differ in case and spacing from the rule's.
        let mixed = UserView { groups: vec!["cn=plank-ws01, ou=groups,dc=EXAMPLE,dc=org".into()], ..user(&[]) };
        assert_eq!(assigned_hosts(&v, &mixed), ["ws01.example.org"]);
    }

    #[test]
    fn ambiguity_fails_closed() {
        // Two groups with one name grant nothing; the other group still works.
        let dup = [grp("PLANK-WS01"), AdGroup { cn: "plank-ws01".into(), dn: "CN=x,OU=Elsewhere,DC=example,DC=org".into() }, grp("PLANK-AllHosts")];
        let v = build_view(&cfg(), &[comp("WS01", "4096")], &dup);
        assert_eq!(v.rules[0].member_users.len(), 1);
        assert!(v.rules[0].member_users[0].starts_with("CN=PLANK-AllHosts,"));
        // dNSHostName must start with the computer's own name.
        let mut spoof = comp("WS02", "4096");
        spoof.dns_name = "ws01.example.org".into();
        let v = build_view(&cfg(), &[comp("WS01", "4096"), spoof], &[]);
        assert_eq!(v.remote_hosts.len(), 1, "the lookalike is skipped, the real one stays");
        // Two computers claiming one host name: both dropped.
        let mut other = comp("WS01", "4096");
        other.dn = "CN=WS01,OU=Other,DC=example,DC=org".into();
        let v = build_view(&cfg(), &[comp("WS01", "4096"), other], &[grp("PLANK-WS01")]);
        assert!(v.remote_hosts.is_empty() && v.rules.is_empty());
        // No `$` in sAMAccountName: not a computer account name.
        let mut nodollar = comp("WS03", "4096");
        nodollar.sam = "WS03".into();
        assert!(build_view(&cfg(), &[nodollar], &[]).remote_hosts.is_empty());
    }

    #[test]
    fn user_state_covers_lockout_expired_password_and_password_age() {
        let now = 1_800_000_000;
        let ft = |unix: u64| ((unix + FILETIME_UNIX_OFFSET) * 10_000_000).to_string();
        assert_eq!(user_state(Some("512"), Some("0"), Some("0"), Some(&ft(now - 100)), now), (false, Some(now - 100)));
        assert!(user_state(Some("514"), None, Some("0"), None, now).0, "disabled");
        assert!(user_state(Some("512"), None, Some("16"), None, now).0, "locked out");
        assert!(user_state(Some("512"), None, Some("8388608"), None, now).0, "password expired");
        assert!(user_state(Some("512"), None, Some("0"), Some("0"), now).0, "must change password");
        assert!(user_state(None, None, Some("0"), None, now).0, "unreadable flags fail closed");
        assert!(user_state(Some("512"), None, None, None, now).0, "missing computed attribute fails closed");
        assert!(!user_state(Some("512"), None, Some("0"), None, now).0);
    }

    #[test]
    fn custom_prefix_and_bad_host_names() {
        let c = AdConfig { access_group_prefix: "Remote ".into(), ..AdConfig::default() };
        let mut bad = comp("WS03", "4096");
        bad.dns_name = "not a name".into();
        let v = build_view(&c, &[comp("WS01", "4096"), bad], &[grp("Remote WS01"), grp("PLANK-WS01")]);
        assert_eq!(v.remote_hosts.len(), 1, "invalid dNSHostName is skipped");
        assert_eq!(v.rules[0].member_users.len(), 1);
        assert!(v.rules[0].member_users[0].starts_with("CN=Remote WS01,"));
    }
}
