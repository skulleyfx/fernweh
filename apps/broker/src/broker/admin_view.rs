//! Read-only views for the local admin socket (`crate::admin`). Nothing here
//! changes broker state; `invalidate_caches` only forgets what was cached.

use std::time::Duration;

use serde::Serialize;

use super::*;
use crate::util::valid_username;

#[derive(Debug, Serialize)]
pub struct AdminGrant {
    pub user: String,
    /// `relay` or `direct`.
    pub route: &'static str,
    pub client: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct AdminHost {
    pub id: String,
    pub name: String,
    pub online: bool,
    pub busy: Option<bool>,
    pub reason: Option<String>,
    pub pin_mismatch: bool,
    /// Seconds since the last probe finished; `null` when never probed.
    pub checked_age_secs: Option<u64>,
    pub connected_users: Vec<String>,
    pub grants: Vec<AdminGrant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminSession {
    pub user: String,
    pub age_secs: u64,
    pub idle_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct AdminStatus {
    pub generated_unix: u64,
    pub cache_ttl_secs: u64,
    pub hosts: Vec<AdminHost>,
    pub sessions: Vec<AdminSession>,
}

#[derive(Debug, Serialize)]
pub struct AdminUser {
    /// `ok`, `disabled` or `not_found`.
    pub state: &'static str,
    /// Group DNs as the directory reported them.
    pub groups: Vec<String>,
    /// What the broker would list for this user right now.
    pub hosts: Vec<String>,
}

impl Broker {
    /// Every remote host in the directory view (assigned to anyone or not), with
    /// the broker's last probe result, live presence and transport grants.
    pub async fn admin_status(&self) -> Result<AdminStatus, ApiError> {
        let view = self.view(false).await?;
        let now = self.now();
        let unix = self.d.clock.unix();
        let probes = self.status.read().unwrap().clone();
        let mut hosts = Vec::new();
        for h in view.remote_hosts.iter() {
            let st = probes.get(&h.fqdn);
            let e = self.entry(&h.fqdn, h.ipv4, st);
            hosts.push(AdminHost {
                id: e.id,
                name: e.name,
                online: e.online,
                busy: e.busy,
                reason: e.reason,
                pin_mismatch: st.is_some_and(|s| s.pin_mismatch),
                checked_age_secs: st.map(|s| now.saturating_duration_since(s.checked).as_secs()),
                connected_users: self.connected_users(&h.fqdn),
                grants: Vec::new(),
                image_sha256: e.image_sha256,
            });
        }
        let st = self.st.lock().unwrap();
        let name = |key: &[u8; 32]| st.sessions.get(key).map(|s| s.username.clone());
        let left = |t: Instant| t.saturating_duration_since(now).as_secs();
        for l in st.leases.values().filter(|l| l.expires > now) {
            if let (Some(user), Some(h)) = (name(&l.session), hosts.iter_mut().find(|h| h.id == l.host)) {
                h.grants.push(AdminGrant {
                    user,
                    route: "relay",
                    client: l.client.to_string(),
                    expires_in: left(l.expires),
                });
            }
        }
        for g in st.direct.iter().filter(|g| g.expires > now) {
            if let (Some(user), Some(h)) = (name(&g.session), hosts.iter_mut().find(|h| h.id == g.host)) {
                h.grants.push(AdminGrant {
                    user,
                    route: "direct",
                    client: g.client.to_string(),
                    expires_in: left(g.expires),
                });
            }
        }
        for h in hosts.iter_mut() {
            h.grants.sort_by(|a, b| (&a.user, a.route, &a.client).cmp(&(&b.user, b.route, &b.client)));
        }
        let mut sessions: Vec<AdminSession> = st
            .sessions
            .values()
            .map(|s| AdminSession {
                user: s.username.clone(),
                age_secs: unix.saturating_sub(s.created_unix),
                idle_secs: unix.saturating_sub(s.last_used_unix),
            })
            .collect();
        sessions.sort_by(|a, b| a.user.cmp(&b.user).then(a.age_secs.cmp(&b.age_secs)));
        Ok(AdminStatus { generated_unix: unix, cache_ttl_secs: self.cfg.ldap.cache_ttl_secs, hosts, sessions })
    }

    /// What the broker's own `assigned()` says for `sam` (from the same caches
    /// the sign-in path uses). `Err(BadRequest)` for a name no account can have.
    pub async fn admin_user(&self, sam: &str) -> Result<AdminUser, ApiError> {
        // The sign-in path folds names to lower case before the directory sees them.
        let sam = sam.to_ascii_lowercase();
        let sam = sam.as_str();
        if !valid_username(sam) {
            return Err(ApiError::BadRequest);
        }
        let view = self.view(false).await?;
        Ok(match self.user(sam, false).await? {
            None => AdminUser { state: "not_found", groups: Vec::new(), hosts: Vec::new() },
            Some(u) if u.disabled => AdminUser { state: "disabled", groups: u.groups, hosts: Vec::new() },
            Some(u) => {
                let hosts = assigned_hosts(&view, &u);
                AdminUser { state: "ok", groups: u.groups, hosts }
            }
        })
    }

    /// Forget the cached directory view and user entries; the next request reads
    /// the directory again. Sessions, leases and probe results are untouched.
    pub async fn invalidate_caches(&self) {
        *self.view.lock().await = None;
        self.users.lock().unwrap().clear();
    }

    /// Seconds the directory view may be served from cache.
    pub fn cache_ttl(&self) -> Duration {
        Duration::from_secs(self.cfg.ldap.cache_ttl_secs)
    }
}
