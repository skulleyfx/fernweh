//! `/etc/plank-broker/broker.toml`. Every field except the identity/directory
//! basics has a default matching docs (contracts v1).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = "/etc/plank-broker/broker.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// API listen address (TLS 1.3, HTTP/1.1). Default `0.0.0.0:29000`.
    #[serde(default = "d_listen")]
    pub listen: SocketAddr,
    /// Public broker name returned as `endpoint` when the request carries no
    /// usable `Host` header (normally the client-supplied host name is echoed).
    pub public_endpoint: String,
    pub tls: TlsConfig,
    pub kerberos: KerberosConfig,
    pub ldap: LdapConfig,
    /// Which directory backs sign-in and host assignment (default FreeIPA).
    #[serde(default)]
    pub directory: DirectoryConfig,
    /// Active Directory backend settings (used when `directory.backend = "ad"`).
    #[serde(default)]
    pub ad: AdConfig,
    #[serde(default)]
    pub hosts: HostsConfig,
    /// Explicit broker-trusted admission for unjoined, shared macOS desktops.
    #[serde(default)]
    pub mac_admission: Option<crate::mac_admission::MacAdmissionConfig>,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub passkey: PasskeyConfig,
    #[serde(default)]
    pub enrol: EnrolConfig,
    /// Optional directories containing the current platform client releases.
    #[serde(default)]
    pub client_updates: Option<ClientUpdatesConfig>,
    /// Beta-only diagnostic collection, disabled unless explicitly configured.
    #[serde(default)]
    pub diagnostics: Option<crate::diagnostics::Config>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DirectoryBackend {
    /// FreeIPA: HBAC rules, OTP tokens, enrolment (the upstream behaviour).
    #[default]
    Freeipa,
    /// Active Directory: password-only Kerberos sign-in, access by `PLANK-*` groups.
    Ad,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConfig {
    #[serde(default)]
    pub backend: DirectoryBackend,
}

/// Active Directory backend (`directory.backend = "ad"`, this fork).
///
/// Inventory: computer accounts that are (possibly nested) members of
/// `hosts_group`. Access: a user may reach host `H` when a member (possibly
/// nested, resolved by the DC with LDAP_MATCHING_RULE_IN_CHAIN) of the group
/// `<access_group_prefix><H>` or of `all_hosts_group`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdConfig {
    /// Computer group listing the PLANK hosts (name, not DN).
    #[serde(default = "d_ad_hosts_group")]
    pub hosts_group: String,
    /// Per-host access groups are `<prefix><computer name>` (e.g. `PLANK-WS01`).
    #[serde(default = "d_ad_prefix")]
    pub access_group_prefix: String,
    /// Members of this group reach every host in `hosts_group`.
    #[serde(default = "d_ad_all_hosts")]
    pub all_hosts_group: String,
    /// Search base for users; default `ldap.base_dn` (derived from the realm).
    #[serde(default)]
    pub user_base: Option<String>,
    /// Search base for computers; default `ldap.base_dn`.
    #[serde(default)]
    pub computer_base: Option<String>,
    /// OU (DN) holding the PLANK security groups. Required: only groups under it count, so
    /// a same-named group elsewhere in the domain cannot grant access.
    #[serde(default)]
    pub groups_base: Option<String>,
    /// The domain's account lockout threshold and observation window (seconds). When given,
    /// the broker's limits are checked against them at start-up.
    #[serde(default)]
    pub lockout_threshold: Option<u32>,
    #[serde(default)]
    pub lockout_window_secs: Option<u64>,
    /// Safety margin added to the observation window before the broker treats a user's
    /// directory counter as reset.
    #[serde(default = "d_60u64")]
    pub lockout_margin_secs: u64,
    /// Optional fixed IPv4 address per host FQDN (lower case); otherwise the
    /// broker resolves the host's `dNSHostName` through the system resolver.
    #[serde(default)]
    pub host_ipv4: std::collections::HashMap<String, std::net::Ipv4Addr>,
}

impl Default for AdConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

fn d_ad_hosts_group() -> String {
    "PLANK-Hosts".into()
}
fn d_ad_prefix() -> String {
    "PLANK-".into()
}
fn d_ad_all_hosts() -> String {
    "PLANK-AllHosts".into()
}

/// A group name usable in an LDAP filter and a DN lookup without escaping surprises.
pub fn valid_ad_group_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        && !n.starts_with(' ')
        && !n.ends_with(' ')
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientUpdatesConfig {
    /// Root-owned, broker-readable directory with current.json and immutable DMGs.
    pub directory: PathBuf,
    /// Optional independent Windows feed; unsigned ALPHA installers are allowed.
    #[serde(default)]
    pub windows_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain served on the API port.
    pub cert: PathBuf,
    /// PEM private key (PKCS#8, SEC1 or PKCS#1).
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosConfig {
    /// Realm of users and hosts, e.g. `EXAMPLE.ORG`.
    pub realm: String,
    /// Broker service keytab (FAST armour + LDAP bind).
    #[serde(default = "d_keytab")]
    pub keytab: PathBuf,
    /// Broker principal in the keytab, e.g. `HTTP/broker.example.org@EXAMPLE.ORG`.
    pub principal: String,
    /// GSSAPI host-based service name of the PLANK hosts (`plank@<fqdn>`).
    #[serde(default = "d_host_service")]
    pub host_service: String,
    /// Upper bound for the requested user TGT lifetime (seconds).
    #[serde(default = "d_ticket_lifetime")]
    pub ticket_lifetime_secs: u32,
    /// Device-bound sessions (§14): session records and their `FILE:` ccaches.
    /// Must be private to the broker (the systemd StateDirectory).
    #[serde(default = "d_session_dir")]
    pub session_dir: PathBuf,
    /// Plain password AS exchange: no OTP pre-auth list and no FAST armour.
    /// Required for Active Directory (`directory.backend = "ad"`).
    #[serde(default)]
    pub password_only: bool,
    /// Active Directory: service principal in the keytab used to verify that the KDC's
    /// answer is genuine (`krb5_verify_init_creds`), e.g. `host/<broker fqdn>@REALM`.
    #[serde(default)]
    pub verify_principal: Option<String>,
    /// How long `auth/respond` waits for the KDC. The attempt is counted whatever its outcome.
    #[serde(default = "d_10secs")]
    pub login_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapConfig {
    /// Tried in order, e.g. `["ldaps://ipa1.example.org:636", "ldaps://ipa2.example.org:636"]`.
    /// `ldap://` URIs use StartTLS; plain LDAP is never used.
    pub uris: Vec<String>,
    /// CA bundle that signed the directory servers' certificates (`/etc/ipa/ca.crt`).
    pub ca_cert: PathBuf,
    /// Directory suffix; derived from the realm (`dc=example,dc=org`) when absent.
    #[serde(default)]
    pub base_dn: Option<String>,
    /// Only members of this host group are ever listed or relayed to.
    #[serde(default = "d_hostgroup")]
    pub hostgroup: String,
    /// HBAC service name whose explicit rules assign hosts to users.
    #[serde(default = "d_hbac_service")]
    pub hbac_service: String,
    /// Directory snapshot / per-user cache lifetime.
    #[serde(default = "d_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "d_ldap_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostsConfig {
    /// PLANK host HTTPS/QUIC port.
    #[serde(default = "d_plank_port")]
    pub port: u16,
    #[serde(default = "d_probe_interval")]
    pub probe_interval_secs: u64,
    #[serde(default = "d_probe_timeout")]
    pub probe_timeout_secs: u64,
    /// TOFU host certificate pins.
    #[serde(default = "d_pins")]
    pub pins_file: PathBuf,
    /// How hosts are probed. Only `tls` exists: a TLS 1.3 handshake without a
    /// client certificate, then the leaf certificate hash is checked.
    #[serde(default)]
    pub probe_mode: ProbeMode,
    /// Static pins (`fqdn = "<sha256 hex of the leaf certificate DER>"`). A host
    /// listed here is never TOFU-pinned; any other certificate marks it changed.
    #[serde(default)]
    pub static_pins: std::collections::HashMap<String, String>,
    /// Host admission at `connect`: one value for every host (`"gssapi"` or
    /// `"none"`) or a table of fqdn -> value. `none` returns an empty
    /// `gssapi_token` (`auth_method: "host_login"`): the Host does its own sign-in.
    #[serde(default)]
    pub admission: AdmissionPolicy,
    /// Hosts missing from a per-host `admission` table.
    #[serde(default)]
    pub default_admission: Admission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMode {
    #[default]
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Admission {
    /// The broker obtains a GSSAPI AP-REQ for `plank@<fqdn>` (FreeIPA hosts).
    #[default]
    Gssapi,
    /// No broker admission token; the host authenticates the client itself.
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AdmissionPolicy {
    All(Admission),
    PerHost(std::collections::HashMap<String, Admission>),
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        AdmissionPolicy::PerHost(Default::default())
    }
}

impl HostsConfig {
    pub fn admission_for(&self, fqdn: &str) -> Admission {
        match &self.admission {
            AdmissionPolicy::All(a) => *a,
            AdmissionPolicy::PerHost(m) => m.get(fqdn).copied().unwrap_or(self.default_admission),
        }
    }

    /// The admission used by every host not named explicitly.
    pub fn base_admission(&self) -> Admission {
        match &self.admission {
            AdmissionPolicy::All(a) => *a,
            AdmissionPolicy::PerHost(_) => self.default_admission,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    #[serde(default = "d_socket")]
    pub socket: PathBuf,
    #[serde(default = "d_port_min")]
    pub port_min: u16,
    #[serde(default = "d_port_max")]
    pub port_max: u16,
    /// Lease lifetime right after `connect` (contract: 30 s).
    #[serde(default = "d_lease_initial")]
    pub lease_initial_secs: u64,
    /// Lease lifetime after each keepalive / host list (contract: keepalive at least every 60 s).
    #[serde(default = "d_lease_keepalive")]
    pub lease_keepalive_secs: u64,
    /// Relay side: the only local user allowed to talk to the relay socket.
    #[serde(default = "d_api_user")]
    pub api_user: String,
    /// Relay side: DNAT targets must fall into one of these networks (defence in depth;
    /// the API already restricts targets to the host group).
    #[serde(default)]
    pub allowed_target_cidrs: Vec<String>,
    #[serde(default = "d_nft")]
    pub nft: PathBuf,
    #[serde(default = "d_conntrack")]
    pub conntrack: PathBuf,
    #[serde(default = "d_table")]
    pub table: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    /// Clients connecting from these networks already reach the hosts directly
    /// (office LAN): `connect` returns the host itself instead of a relay lease.
    /// Empty (default): every client is relayed.
    #[serde(default)]
    pub direct_client_cidrs: Vec<String>,
}

impl RoutingConfig {
    /// Parsed `direct_client_cidrs`; `validate` has already rejected bad entries.
    pub fn direct_nets(&self) -> Vec<ipnet::Ipv4Net> {
        self.direct_client_cidrs.iter().filter_map(|c| c.parse().ok()).collect()
    }
}

/// Passkey sign-in (`auth/start` with `method: "passkey"`, contract §13.3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyConfig {
    /// Relying party id sent to clients (the IPA domain the KDC verifies against).
    /// Default: the realm in lower case (`IPA.EXAMPLE.ORG` → `ipa.example.org`).
    #[serde(default)]
    pub rp_id: Option<String>,
    /// Passkey conversations waiting for the client's assertion (each holds a KDC
    /// exchange on a worker thread). Beyond this, `auth/start` answers 429.
    #[serde(default = "d_32")]
    pub max_pending: usize,
    /// How long `auth/start` waits for the KDC's challenge before it answers with a
    /// synthetic one.
    #[serde(default = "d_10u64")]
    pub challenge_timeout_secs: u64,
}

impl PasskeyConfig {
    pub fn rp_id(&self, realm: &str) -> String {
        self.rp_id.clone().unwrap_or_else(|| realm.to_ascii_lowercase())
    }
}

/// First sign-in and 2FA enrolment in the client (`/v1/enroll/*`, bde-linux
/// `docs/plank-broker.md` §16). Gates: member of `group`, of none of
/// `excluded_groups`, no OTP token or passkey yet, optional password age limit,
/// and proof of that password (FAST AS for `kadmin/changepw`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolConfig {
    /// Off: every `/v1/enroll/*` call answers 404, as on a broker without enrolment.
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// IPA group whose members may enrol (G1).
    #[serde(default = "d_enrol_group")]
    pub group: String,
    /// Members of these groups never enrol remotely (G2).
    #[serde(default = "d_enrol_excluded")]
    pub excluded_groups: Vec<String>,
    /// Maximum password age in days (G4); 0 disables the age limit.
    #[serde(default = "d_7u64")]
    pub window_days: u64,
    /// Password proofs (`enroll/respond`) per user per 24 h, from any address.
    #[serde(default = "d_5")]
    pub daily_cap: u32,
    /// Issuer label in the authenticator app (otpauth URI) and token description.
    #[serde(default = "d_enrol_issuer")]
    pub issuer: String,
    /// LDAP URIs for the binds as the user (writes). Default: `ldap.uris`.
    #[serde(default)]
    pub ldap_uris: Option<Vec<String>>,
    /// Lifetime of one enrolment conversation (bound to the client address).
    #[serde(default = "d_600")]
    pub conversation_ttl_secs: u64,
    /// Wrong authenticator codes before the conversation is ended.
    #[serde(default = "d_5")]
    pub max_code_attempts: u32,
    /// Refused new passwords before the conversation is ended.
    #[serde(default = "d_5")]
    pub max_password_attempts: u32,
    /// Policy shown to the client when the broker cannot read IPA's global policy.
    #[serde(default = "d_8")]
    pub fallback_min_length: u32,
    #[serde(default)]
    pub fallback_min_classes: u32,
}

impl EnrolConfig {
    pub fn user_ldap_uris<'a>(&'a self, ldap: &'a LdapConfig) -> &'a [String] {
        self.ldap_uris.as_deref().unwrap_or(&ldap.uris)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "d_5")]
    pub starts_per_minute_per_ip: u32,
    #[serde(default = "d_3")]
    pub failures_per_user_ip: u32,
    #[serde(default = "d_10")]
    pub failures_per_ip: u32,
    /// Wrong passwords per user name, from ANY address, per quiet period before that user is
    /// refused (protects the directory's own account lockout; see `ratelimit.rs`). 0 disables
    /// it; required (> 0, and below `ad.lockout_threshold`) for Active Directory.
    #[serde(default)]
    pub failures_per_user: u32,
    /// Quiet period after which a user's failure count resets (non-AD backends). With
    /// `directory.backend = "ad"` it is `ad.lockout_window_secs + ad.lockout_margin_secs`
    /// instead and this value is ignored.
    #[serde(default = "d_1800")]
    pub user_window_secs: u64,
    #[serde(default = "d_900")]
    pub block_secs: u64,
    #[serde(default = "d_20")]
    pub global_failure_burst_per_minute: u32,
    #[serde(default = "d_120")]
    pub conversation_ttl_secs: u64,
    #[serde(default = "d_36000")]
    pub session_absolute_secs: u64,
    #[serde(default = "d_3600")]
    pub session_idle_secs: u64,
    #[serde(default = "d_500")]
    pub max_sessions: usize,
    #[serde(default = "d_1000")]
    pub max_conversations: usize,
    #[serde(default = "d_256")]
    pub max_connections: usize,
    /// Every `auth/respond` answer takes at least this long (constant-ish timing).
    #[serde(default = "d_1500")]
    pub min_respond_ms: u64,
    /// Device-bound sessions (§14): 0 disables the corresponding application
    /// expiry. Kerberos credentials are renewed within the KDC's own limits.
    #[serde(default)]
    pub device_session_absolute_secs: u64,
    #[serde(default)]
    pub device_session_idle_secs: u64,
    /// Renew a device-bound session's TGT when less than this is left.
    #[serde(default = "d_7200")]
    pub renew_before_secs: u64,
    /// Accepted clock skew of `X-Plank-Device-Time`; also the replay window.
    #[serde(default = "d_60")]
    pub device_proof_skew_secs: u64,
}

fn d_listen() -> SocketAddr {
    "0.0.0.0:29000".parse().unwrap()
}
fn d_session_dir() -> PathBuf {
    "/var/lib/plank-broker/sessions".into()
}
fn d_7200() -> u64 {
    7200
}
fn d_60() -> u64 {
    60
}
fn d_keytab() -> PathBuf {
    "/etc/plank-broker/broker.keytab".into()
}
fn d_host_service() -> String {
    "plank".into()
}
fn d_ticket_lifetime() -> u32 {
    36000
}
fn d_hostgroup() -> String {
    "plank-remote".into()
}
fn d_hbac_service() -> String {
    "plank-remote".into()
}
fn d_cache_ttl() -> u64 {
    60
}
fn d_ldap_timeout() -> u64 {
    5
}
fn d_plank_port() -> u16 {
    28989
}
fn d_probe_interval() -> u64 {
    15
}
fn d_probe_timeout() -> u64 {
    3
}
fn d_pins() -> PathBuf {
    "/var/lib/plank-broker/pins.json".into()
}
fn d_socket() -> PathBuf {
    "/run/plank-broker/relay.sock".into()
}
fn d_port_min() -> u16 {
    29001
}
fn d_port_max() -> u16 {
    29100
}
fn d_lease_initial() -> u64 {
    30
}
fn d_lease_keepalive() -> u64 {
    90
}
fn d_api_user() -> String {
    "plank-broker".into()
}
fn d_nft() -> PathBuf {
    "/usr/sbin/nft".into()
}
fn d_conntrack() -> PathBuf {
    "/usr/sbin/conntrack".into()
}
fn d_table() -> String {
    "plank_broker".into()
}
fn d_true() -> bool {
    true
}
fn d_enrol_group() -> String {
    "fernweh".into()
}
fn d_enrol_excluded() -> Vec<String> {
    vec!["admins".into(), "sysadmins".into()]
}
fn d_enrol_issuer() -> String {
    "BDE Fernweh".into()
}
fn d_7u64() -> u64 {
    7
}
fn d_8() -> u32 {
    8
}
fn d_600() -> u64 {
    600
}
fn d_3() -> u32 {
    3
}
fn d_5() -> u32 {
    5
}
fn d_10() -> u32 {
    10
}
fn d_20() -> u32 {
    20
}
fn d_32() -> usize {
    32
}
fn d_10u64() -> u64 {
    10
}
fn d_120() -> u64 {
    120
}
fn d_900() -> u64 {
    900
}
fn d_1500() -> u64 {
    1500
}
fn d_60u64() -> u64 {
    60
}
fn d_10secs() -> u64 {
    10
}
fn d_1800() -> u64 {
    1800
}
fn d_3600() -> u64 {
    3600
}
fn d_36000() -> u64 {
    36000
}
fn d_256() -> usize {
    256
}
fn d_500() -> usize {
    500
}
fn d_1000() -> usize {
    1000
}

impl Default for HostsConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}
impl Default for RelayConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}
impl Default for PasskeyConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}
impl Default for EnrolConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}
impl Default for Limits {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

impl LdapConfig {
    pub fn base_dn(&self, realm: &str) -> String {
        match &self.base_dn {
            Some(b) => b.clone(),
            None => realm
                .split('.')
                .filter(|p| !p.is_empty())
                .map(|p| format!("dc={}", p.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// The relay shares the policy file but must never open the API service's
    /// private signing key. Broker startup and check-config use `load` instead.
    pub fn load_for_relay(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate_policy()?;
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_policy()?;
        if let Some(mac) = &self.mac_admission {
            mac.validate()?;
        }
        Ok(())
    }

    fn validate_policy(&self) -> Result<()> {
        if let Some(mac) = &self.mac_admission {
            mac.validate_policy()?;
        }
        if let Some(diagnostics) = &self.diagnostics {
            if !diagnostics.directory.is_absolute() || diagnostics.enabled_until_unix == 0 {
                bail!("diagnostics requires an absolute directory and an explicit beta expiry");
            }
        }
        if let Some(updates) = &self.client_updates {
            if updates.windows_directory.as_ref().is_some_and(|p| !p.is_absolute()) {
                bail!("client_updates.windows_directory must be absolute");
            }
            if !updates.directory.is_absolute() {
                bail!("client_updates.directory must be absolute");
            }
        }
        let l = &self.limits;
        if l.device_session_absolute_secs != 0 && l.device_session_idle_secs > l.device_session_absolute_secs {
            bail!("limits.device_session_idle_secs must not exceed a finite device_session_absolute_secs");
        }
        if l.device_proof_skew_secs == 0 || l.device_proof_skew_secs > 300 {
            bail!("limits.device_proof_skew_secs must be 1..=300");
        }
        if !self.kerberos.session_dir.is_absolute() {
            bail!("kerberos.session_dir must be absolute");
        }
        let r = &self.relay;
        if r.port_min == 0 || r.port_min > r.port_max {
            bail!("relay.port_min/port_max: invalid range");
        }
        if r.port_max - r.port_min > 4096 {
            bail!("relay port range too large");
        }
        if self.ldap.uris.is_empty() {
            bail!("ldap.uris is empty");
        }
        for u in &self.ldap.uris {
            if !(u.starts_with("ldaps://") || u.starts_with("ldap://")) {
                bail!("ldap.uris: unsupported scheme in {u}");
            }
        }
        if self.kerberos.realm.is_empty() || self.kerberos.realm != self.kerberos.realm.to_ascii_uppercase() {
            bail!("kerberos.realm must be upper case");
        }
        if !self.kerberos.principal.ends_with(&format!("@{}", self.kerberos.realm)) {
            bail!("kerberos.principal must be in kerberos.realm");
        }
        for c in &r.allowed_target_cidrs {
            c.parse::<ipnet::Ipv4Net>().with_context(|| format!("relay.allowed_target_cidrs: {c}"))?;
        }
        for c in &self.routing.direct_client_cidrs {
            let n: ipnet::Ipv4Net = c.parse().with_context(|| format!("routing.direct_client_cidrs: {c}"))?;
            if n.prefix_len() < 8 {
                bail!("routing.direct_client_cidrs: {c} is too broad");
            }
            if !n.network().is_private() {
                bail!("routing.direct_client_cidrs: {c} is not a private network");
            }
        }
        if r.table.is_empty() || !r.table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            bail!("relay.table: letters, digits and '_' only");
        }
        let rp = self.passkey.rp_id(&self.kerberos.realm);
        if !crate::util::valid_hostname(&rp) || rp != rp.to_ascii_lowercase() {
            bail!("passkey.rp_id must be a lower-case domain name");
        }
        if self.passkey.max_pending == 0 {
            bail!("passkey.max_pending must be at least 1");
        }
        if !(1..=60).contains(&self.passkey.challenge_timeout_secs) {
            bail!("passkey.challenge_timeout_secs must be 1-60");
        }
        let e = &self.enrol;
        if !crate::enrol::valid_group_name(&e.group)
            || !e.excluded_groups.iter().all(|g| crate::enrol::valid_group_name(g))
        {
            bail!("enrol.group / enrol.excluded_groups: IPA group names only");
        }
        if e.excluded_groups.iter().any(|g| g.eq_ignore_ascii_case(&e.group)) {
            bail!("enrol.group must not be one of enrol.excluded_groups");
        }
        if e.window_days > 90 {
            bail!("enrol.window_days must be 0-90");
        }
        if e.daily_cap == 0 || e.max_code_attempts == 0 || e.max_password_attempts == 0 {
            bail!("enrol.daily_cap / max_code_attempts / max_password_attempts must be at least 1");
        }
        if !(60..=3600).contains(&e.conversation_ttl_secs) {
            bail!("enrol.conversation_ttl_secs must be 60-3600");
        }
        if e.issuer.trim().is_empty()
            || e.issuer.len() > 64
            || e.issuer.contains(':')
            || e.issuer.chars().any(char::is_control)
        {
            bail!("enrol.issuer: 1-64 printable characters, no ':'");
        }
        if let Some(uris) = &e.ldap_uris {
            if uris.is_empty() {
                bail!("enrol.ldap_uris is empty");
            }
            for u in uris {
                if !(u.starts_with("ldaps://") || u.starts_with("ldap://")) {
                    bail!("enrol.ldap_uris: unsupported scheme in {u}");
                }
            }
        }
        if self.public_endpoint.is_empty() || !crate::util::valid_hostname(&self.public_endpoint) {
            bail!("public_endpoint must be a host name");
        }
        for (h, pin) in &self.hosts.static_pins {
            if !crate::util::valid_hostname(h) || h != &h.to_ascii_lowercase() {
                bail!("hosts.static_pins: {h} is not a lower-case host name");
            }
            if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                bail!("hosts.static_pins: {h}: expected 64 lower-case hex digits (SHA-256 of the certificate DER)");
            }
        }
        if let AdmissionPolicy::PerHost(m) = &self.hosts.admission {
            for h in m.keys() {
                if !crate::util::valid_hostname(h) || h != &h.to_ascii_lowercase() {
                    bail!("hosts.admission: {h} is not a lower-case host name");
                }
            }
        }
        if self.directory.backend == DirectoryBackend::Ad {
            self.validate_ad()?;
        } else if self.kerberos.password_only {
            bail!("kerberos.password_only is only valid with directory.backend = \"ad\"");
        }
        Ok(())
    }
}

impl Config {
    fn validate_ad(&self) -> Result<()> {
        let a = &self.ad;
        for (what, n) in [
            ("ad.hosts_group", &a.hosts_group),
            ("ad.all_hosts_group", &a.all_hosts_group),
        ] {
            if !valid_ad_group_name(n) {
                bail!("{what}: letters, digits, '-', '_', '.' and inner blanks only (max 64)");
            }
        }
        if !valid_ad_group_name(&a.access_group_prefix) {
            bail!("ad.access_group_prefix: letters, digits, '-', '_', '.' and inner blanks only (max 64)");
        }
        if a.hosts_group.eq_ignore_ascii_case(&a.all_hosts_group) {
            bail!("ad.hosts_group and ad.all_hosts_group must differ");
        }
        for (h, _) in &a.host_ipv4 {
            if !crate::util::valid_hostname(h) || h != &h.to_ascii_lowercase() {
                bail!("ad.host_ipv4: {h} is not a lower-case host name");
            }
        }
        if !self.kerberos.password_only {
            bail!("directory.backend = \"ad\" requires kerberos.password_only = true");
        }
        match &self.kerberos.verify_principal {
            Some(v) if v.ends_with(&format!("@{}", self.kerberos.realm)) && !v.starts_with('@') => {}
            _ => bail!("directory.backend = \"ad\" requires kerberos.verify_principal (e.g. host/<broker fqdn>@REALM)"),
        }
        if self.mac_admission.is_some() {
            bail!("directory.backend = \"ad\" does not support mac_admission");
        }
        match &a.groups_base {
            Some(b) if b.contains('=') && !b.trim().is_empty() => {}
            _ => bail!("ad.groups_base (the OU holding the PLANK groups, as a DN) is required"),
        }
        if self.enrol.enabled {
            bail!("directory.backend = \"ad\" requires enrol.enabled = false (enrolment is FreeIPA only)");
        }
        if self.limits.failures_per_user == 0 {
            bail!("directory.backend = \"ad\" requires limits.failures_per_user > 0 (AD account lockout)");
        }
        if self.hosts.base_admission() != Admission::None {
            bail!("directory.backend = \"ad\" requires hosts.admission = \"none\" (no plank/<host> Kerberos service)");
        }
        // AD's badPwdCount resets one observation window W after the LAST failure, so failures
        // chain. The broker keeps its own (count, last) per user: at most N wrong passwords per
        // quiet period W + margin, whatever their spacing. That is safe iff N < T.
        let (Some(t), Some(w)) = (a.lockout_threshold, a.lockout_window_secs) else {
            bail!("ad.lockout_threshold and ad.lockout_window_secs are required (the domain's lockout policy)");
        };
        if t == 0 || w == 0 {
            bail!("ad.lockout_threshold / ad.lockout_window_secs must be positive (a domain without lockout needs no broker limit: set both from the real policy)");
        }
        if self.limits.failures_per_user >= t {
            bail!(
                "limits.failures_per_user ({}) must be below the AD lockout threshold ({t})",
                self.limits.failures_per_user
            );
        }
        if a.lockout_margin_secs < 10 {
            bail!("ad.lockout_margin_secs must be at least 10 (the KDC answers and the counter resets are not instantaneous)");
        }
        if self.kerberos.login_timeout_secs == 0 || self.kerberos.login_timeout_secs > 120 {
            bail!("kerberos.login_timeout_secs must be 1-120");
        }
        if let AdmissionPolicy::PerHost(m) = &self.hosts.admission {
            if m.values().any(|v| *v != Admission::None) {
                bail!("directory.backend = \"ad\": every hosts.admission entry must be \"none\"");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    Config::parse(
        r#"
public_endpoint = "broker.example.org"
[tls]
cert = "/nonexistent/cert.pem"
key = "/nonexistent/key.pem"
[kerberos]
realm = "EXAMPLE.ORG"
principal = "HTTP/broker.example.org@EXAMPLE.ORG"
[ldap]
uris = ["ldaps://ipa1.example.org"]
ca_cert = "/nonexistent/ca.crt"
[hosts]
pins_file = "/nonexistent/pins.json"
[relay]
port_min = 29001
port_max = 29003
allowed_target_cidrs = ["192.0.2.0/24"]
"#,
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_base_dn() {
        let c = test_config();
        assert_eq!(c.listen.port(), 29000);
        assert_eq!(c.ldap.hbac_service, "plank-remote");
        assert_eq!(c.ldap.hostgroup, "plank-remote");
        assert_eq!(c.limits.starts_per_minute_per_ip, 5);
        assert_eq!(c.limits.device_session_absolute_secs, 0);
        assert_eq!(c.limits.device_session_idle_secs, 0);
        assert_eq!(c.ldap.base_dn("EXAMPLE.ORG"), "dc=example,dc=org");
        assert_eq!(c.hosts.port, 28989);
        assert_eq!(c.passkey.rp_id(&c.kerberos.realm), "example.org");
        assert_eq!(c.passkey.max_pending, 32);
        assert_eq!(c.passkey.challenge_timeout_secs, 10);
    }

    #[test]
    fn passkey_settings_are_validated() {
        let base = include_str!("../packaging/broker.toml.example");
        let with = |v: &str| Config::parse(&format!("{base}\n[passkey]\n{v}\n"));
        let c = with(r#"rp_id = "ipa.example.org""#).unwrap();
        assert_eq!(c.passkey.rp_id(&c.kerberos.realm), "ipa.example.org");
        assert!(with(r#"rp_id = "IPA.example.org""#).is_err());
        assert!(with(r#"rp_id = "not a domain""#).is_err());
        assert!(with("max_pending = 0").is_err());
        assert!(with("challenge_timeout_secs = 0").is_err());
        assert!(with("bogus = 1").is_err());
    }

    #[test]
    fn shipped_example_parses() {
        let c = Config::parse(include_str!("../packaging/broker.toml.example")).unwrap();
        assert_eq!(c.relay.port_max, 29100);
        assert_eq!(c.limits.min_respond_ms, 1500);
    }

    #[test]
    fn routing_cidrs_are_validated() {
        assert!(test_config().routing.direct_nets().is_empty());
        let base = include_str!("../packaging/broker.toml.example");
        let with = |v: &str| Config::parse(&format!("{base}\n[routing]\ndirect_client_cidrs = [{v}]\n"));
        let c = with(r#""192.168.10.0/24""#).unwrap();
        assert_eq!(c.routing.direct_nets(), vec!["192.168.10.0/24".parse::<ipnet::Ipv4Net>().unwrap()]);
        assert!(with(r#""0.0.0.0/0""#).is_err());
        assert!(with(r#""203.0.113.0/24""#).is_err());
        assert!(with(r#""not-a-cidr""#).is_err());
    }

    #[test]
    fn enrol_defaults_and_validation() {
        let c = test_config();
        assert!(c.enrol.enabled);
        assert_eq!(c.enrol.group, "fernweh");
        assert_eq!(c.enrol.excluded_groups, vec!["admins", "sysadmins"]);
        assert_eq!(c.enrol.window_days, 7);
        assert_eq!(c.enrol.daily_cap, 5);
        assert_eq!(c.enrol.issuer, "BDE Fernweh");
        assert_eq!(c.enrol.conversation_ttl_secs, 600);
        assert_eq!(c.enrol.user_ldap_uris(&c.ldap), &c.ldap.uris[..]);
        let base = include_str!("../packaging/broker.toml.example");
        let with = |v: &str| Config::parse(&format!("{base}\n[enrol]\n{v}\n"));
        // Exactly what bde-linux roles/plank_broker renders.
        let c = with(
            "enabled = true\ngroup = \"fernweh\"\nexcluded_groups = [\"admins\",\"sysadmins\"]\nwindow_days = 7\n\
             daily_cap = 5\nissuer = \"BDE Fernweh\"",
        )
        .unwrap();
        assert_eq!(c.enrol.issuer, "BDE Fernweh");
        let c = with(r#"ldap_uris = ["ldaps://ipa1.example.org:636"]"#).unwrap();
        assert_eq!(c.enrol.user_ldap_uris(&c.ldap), &["ldaps://ipa1.example.org:636".to_string()][..]);
        assert!(with(r#"group = "admins""#).is_err());
        assert!(with(r#"group = "bad group""#).is_err());
        assert_eq!(with("window_days = 0").unwrap().enrol.window_days, 0);
        assert!(with("daily_cap = 0").is_err());
        assert!(with(r#"issuer = "a:b""#).is_err());
        assert!(with(r#"ldap_uris = ["http://x"]"#).is_err());
        assert!(with("bogus = 1").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::parse("bogus = 1").is_err());
    }
}
