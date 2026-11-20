//! Pure HBAC evaluation: which members of the remote host group may `user` reach
//! through the remote HBAC service. Inputs come from LDAP (see `ldap.rs`) or test
//! fixtures. All DNs are compared after [`norm_dn`].
//!
//! Rules count only when enabled, of access type `allow`, not named `allow_all`,
//! with no `usercategory`/`hostcategory`/`servicecategory = all`, and they must name
//! the service (directly or through a service group), the user (directly or through
//! a possibly nested user group) and the host (directly or through a possibly
//! nested host group).

use std::collections::{HashMap, HashSet};

use crate::util::norm_dn;

#[derive(Debug, Clone, Default)]
pub struct HbacRule {
    pub name: String,
    pub enabled: bool,
    /// `accessruletype` (only `allow` exists in current IPA).
    pub allow: bool,
    pub user_category_all: bool,
    pub host_category_all: bool,
    pub service_category_all: bool,
    pub member_users: Vec<String>,
    pub member_hosts: Vec<String>,
    pub member_services: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RemoteHost {
    pub fqdn: String,
    pub dn: String,
    /// A record from the directory's DNS (None if it has none).
    pub ipv4: Option<std::net::Ipv4Addr>,
    /// Every host group (normalised DN) that contains the host, transitively.
    pub hostgroups: HashSet<String>,
}

/// Directory snapshot shared by all users (cached).
#[derive(Debug, Clone, Default)]
pub struct DirectoryView {
    pub rules: Vec<HbacRule>,
    /// Normalised DN of the HBAC service (e.g. `cn=plank-remote,cn=hbacservices,…`).
    pub service_dn: String,
    /// Normalised DNs of service groups containing the service.
    pub service_groups: HashSet<String>,
    /// Members of the remote host group (only these are ever listed).
    pub remote_hosts: Vec<RemoteHost>,
    /// user group DN → parent group DNs (normalised), for nested groups.
    pub group_parents: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct UserView {
    /// Administrative account lock, independent of ticket renewal.
    pub disabled: bool,
    pub dn: String,
    /// Group DNs as read from the directory (direct or already transitive).
    pub groups: Vec<String>,
    /// When the password was last set (unix seconds), if the directory tells. A session
    /// created before this (beyond clock skew) is ended.
    pub pwd_last_set_unix: Option<u64>,
}

/// Transitive closure of `start` over `parents`.
pub fn closure(start: impl IntoIterator<Item = String>, parents: &HashMap<String, Vec<String>>) -> HashSet<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = start.into_iter().map(|d| norm_dn(&d)).collect();
    while let Some(d) = stack.pop() {
        if seen.insert(d.clone()) {
            if let Some(ps) = parents.get(&d) {
                stack.extend(ps.iter().cloned());
            }
        }
    }
    seen
}

impl HbacRule {
    pub fn counts(&self) -> bool {
        self.enabled
            && self.allow
            && !self.name.eq_ignore_ascii_case("allow_all")
            && !self.user_category_all
            && !self.host_category_all
            && !self.service_category_all
    }
}

/// FQDNs (sorted) of remote hosts assigned to `user`.
pub fn assigned_hosts(view: &DirectoryView, user: &UserView) -> Vec<String> {
    let user_dn = norm_dn(&user.dn);
    let groups = closure(user.groups.iter().cloned(), &view.group_parents);
    let svc = norm_dn(&view.service_dn);
    let mut out: Vec<String> = Vec::new();
    for rule in view.rules.iter().filter(|r| r.counts()) {
        let service_ok =
            rule.member_services.iter().map(|d| norm_dn(d)).any(|d| d == svc || view.service_groups.contains(&d));
        if !service_ok {
            continue;
        }
        let user_ok = rule.member_users.iter().map(|d| norm_dn(d)).any(|d| d == user_dn || groups.contains(&d));
        if !user_ok {
            continue;
        }
        let members: HashSet<String> = rule.member_hosts.iter().map(|d| norm_dn(d)).collect();
        for h in &view.remote_hosts {
            if members.contains(&norm_dn(&h.dn)) || h.hostgroups.iter().any(|g| members.contains(g)) {
                out.push(h.fqdn.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub const SUFFIX: &str = "dc=example,dc=org";

    pub fn user(u: &str) -> String {
        format!("uid={u},cn=users,cn=accounts,{SUFFIX}")
    }
    pub fn group(g: &str) -> String {
        format!("cn={g},cn=groups,cn=accounts,{SUFFIX}")
    }
    pub fn host(h: &str) -> String {
        format!("fqdn={h}.example.org,cn=computers,cn=accounts,{SUFFIX}")
    }
    pub fn hostgroup(g: &str) -> String {
        format!("cn={g},cn=hostgroups,cn=accounts,{SUFFIX}")
    }
    pub fn svc(s: &str) -> String {
        format!("cn={s},cn=hbacservices,cn=hbac,{SUFFIX}")
    }
    pub fn svcgroup(s: &str) -> String {
        format!("cn={s},cn=hbacservicegroups,cn=hbac,{SUFFIX}")
    }

    pub fn rule(name: &str, users: &[String], hosts: &[String], services: &[String]) -> HbacRule {
        HbacRule {
            name: name.into(),
            enabled: true,
            allow: true,
            member_users: users.to_vec(),
            member_hosts: hosts.to_vec(),
            member_services: services.to_vec(),
            ..Default::default()
        }
    }

    /// ws1, ws2 in plank-remote (ws2 via nested hostgroup `remote-nested`), ws3
    /// NOT in plank-remote. Groups: artists ⊂ staff (nested).
    pub fn view(rules: Vec<HbacRule>) -> DirectoryView {
        let pr = norm_dn(&hostgroup("plank-remote"));
        let nested = norm_dn(&hostgroup("remote-nested"));
        let mut gp = HashMap::new();
        gp.insert(norm_dn(&group("artists")), vec![norm_dn(&group("staff"))]);
        DirectoryView {
            rules,
            service_dn: svc("plank-remote"),
            service_groups: [norm_dn(&svcgroup("remote-services"))].into_iter().collect(),
            remote_hosts: vec![
                RemoteHost {
                    fqdn: "ws1.example.org".into(),
                    dn: host("ws1"),
                    ipv4: Some([192, 0, 2, 11].into()),
                    hostgroups: [pr.clone()].into_iter().collect(),
                },
                RemoteHost {
                    fqdn: "ws2.example.org".into(),
                    dn: host("ws2"),
                    ipv4: Some([192, 0, 2, 12].into()),
                    hostgroups: [pr.clone(), nested.clone()].into_iter().collect(),
                },
            ],
            group_parents: gp,
        }
    }

    pub fn anna() -> UserView {
        UserView { disabled: false, dn: user("anna"), groups: vec![group("artists")], ..Default::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn svc_remote() -> Vec<String> {
        vec![svc("plank-remote")]
    }

    #[test]
    fn direct_user_direct_host() {
        let v = view(vec![rule("plank_remote_anna", &[user("anna")], &[host("ws1")], &svc_remote())]);
        assert_eq!(assigned_hosts(&v, &anna()), vec!["ws1.example.org"]);
        let bob = UserView { disabled: false, dn: user("bob"), groups: vec![], ..Default::default() };
        assert!(assigned_hosts(&v, &bob).is_empty());
    }

    #[test]
    fn via_group_and_nested_group() {
        let v = view(vec![rule("r", &[group("artists")], &[host("ws1")], &svc_remote())]);
        assert_eq!(assigned_hosts(&v, &anna()), vec!["ws1.example.org"]);
        // staff contains artists: anna reaches it only through nesting.
        let v = view(vec![rule("r", &[group("staff")], &[host("ws2")], &svc_remote())]);
        assert_eq!(assigned_hosts(&v, &anna()), vec!["ws2.example.org"]);
    }

    #[test]
    fn via_hostgroup_including_nested() {
        let v = view(vec![rule("r", &[user("anna")], &[hostgroup("plank-remote")], &svc_remote())]);
        assert_eq!(assigned_hosts(&v, &anna()), vec!["ws1.example.org", "ws2.example.org"]);
        let v = view(vec![rule("r", &[user("anna")], &[hostgroup("remote-nested")], &svc_remote())]);
        assert_eq!(assigned_hosts(&v, &anna()), vec!["ws2.example.org"]);
    }

    #[test]
    fn via_service_group() {
        let v = view(vec![rule("r", &[user("anna")], &[host("ws1")], &[svcgroup("remote-services")])]);
        assert_eq!(assigned_hosts(&v, &anna()), vec!["ws1.example.org"]);
    }

    #[test]
    fn other_service_does_not_count() {
        let v = view(vec![rule("r", &[user("anna")], &[host("ws1")], &[svc("plank-host"), svc("sshd")])]);
        assert!(assigned_hosts(&v, &anna()).is_empty());
    }

    #[test]
    fn disabled_rule_ignored() {
        let mut r = rule("r", &[user("anna")], &[host("ws1")], &svc_remote());
        r.enabled = false;
        assert!(assigned_hosts(&view(vec![r]), &anna()).is_empty());
    }

    #[test]
    fn category_all_and_allow_all_ignored() {
        let mut a = rule("allow_all", &[user("anna")], &[host("ws1")], &svc_remote());
        let mut u = rule("u", &[], &[host("ws1")], &svc_remote());
        u.user_category_all = true;
        let mut h = rule("h", &[user("anna")], &[], &svc_remote());
        h.host_category_all = true;
        let mut s = rule("allow_sysadmins", &[user("anna")], &[host("ws1")], &[]);
        s.service_category_all = true;
        a.enabled = true;
        assert!(assigned_hosts(&view(vec![a, u, h, s]), &anna()).is_empty());
    }

    #[test]
    fn host_outside_remote_group_never_listed() {
        let v = view(vec![rule("r", &[user("anna")], &[host("ws3"), hostgroup("servers")], &svc_remote())]);
        assert!(assigned_hosts(&v, &anna()).is_empty());
    }

    #[test]
    fn dn_comparison_is_normalised() {
        let v = view(vec![rule(
            "r",
            &["UID=anna, cn=users,cn=accounts,DC=example,dc=org".into()],
            &["FQDN=WS1.example.org,cn=computers,cn=accounts,dc=example,dc=org".into()],
            &["cn=Plank-Remote,cn=hbacservices,cn=hbac,dc=example,dc=org".into()],
        )]);
        assert_eq!(assigned_hosts(&v, &anna()), vec!["ws1.example.org"]);
    }

    #[test]
    fn closure_handles_cycles() {
        let mut p = HashMap::new();
        p.insert("cn=a".to_string(), vec!["cn=b".to_string()]);
        p.insert("cn=b".to_string(), vec!["cn=a".to_string()]);
        assert_eq!(closure(["cn=a".to_string()], &p).len(), 2);
    }
}
