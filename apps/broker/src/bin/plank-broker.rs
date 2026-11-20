//! `plank-broker` — public API service and admin CLI.

use std::path::PathBuf;
#[cfg(feature = "system")]
use std::sync::Arc;
#[cfg(feature = "system")]
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
#[cfg(feature = "system")]
use tracing::{error, info, warn};

use plank_broker::config::{Config, DEFAULT_CONFIG};
use plank_broker::pins::PinStore;
#[cfg(feature = "system")]
use plank_broker::sessions::SessionStore;

#[derive(Parser)]
#[command(name = "plank-broker", version, about = "PLANK remote broker")]
struct Cli {
    /// Configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG, global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the API service (foreground; systemd unit `plank-broker.service`).
    Serve,
    /// Host certificate pins.
    Pin {
        #[command(subcommand)]
        cmd: PinCmd,
    },
    /// Print the SPKI SHA-256 (hex) of a PEM certificate: the value clients pin.
    Spki { cert: PathBuf },
    /// Parse and validate the configuration file.
    CheckConfig,
    /// Live diagnostics against the real directory / KDC (no service state touched).
    #[cfg(feature = "system")]
    Selftest {
        #[command(subcommand)]
        cmd: SelftestCmd,
    },
}

#[derive(Subcommand)]
enum PinCmd {
    /// List pinned host certificates.
    List,
    /// Forget the pin for FQDN; the next probe pins the current certificate.
    Reset { fqdn: String },
}

#[cfg(feature = "system")]
#[derive(Subcommand)]
enum SelftestCmd {
    /// Bind to LDAP and print the HBAC view (optionally the hosts assigned to USER).
    Directory {
        #[arg(long)]
        user: Option<String>,
    },
    /// Log USER in (password line then OTP line on stdin; with --password-only just
    /// the password) and build an AP-REQ for HOST using its live certificate.
    Kerberos {
        #[arg(long)]
        user: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        password_only: bool,
        /// Use this leaf hash (hex) instead of probing the host (e.g. host not running).
        #[arg(long)]
        cert_sha256: Option<String>,
        /// Write the base64 AP-REQ and the certificate hash to this file (0600).
        #[arg(long)]
        token_out: Option<PathBuf>,
    },
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("PLANK_BROKER_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).with_target(false).init();
}

/// MIT GSSAPI picks the LDAP initiator credentials from the client keytab into a
/// private memory cache. Must run before any thread exists.
#[cfg(feature = "system")]
fn kerberos_env(cfg: &Config) {
    // AD mode: `MitKerberos` fills this same cache with a keytab ticket for `kerberos.principal`,
    // which makes it the LDAP GSSAPI credential (the default principal of the cache).
    std::env::set_var("KRB5_CLIENT_KTNAME", format!("FILE:{}", cfg.kerberos.keytab.display()));
    std::env::set_var("KRB5CCNAME", format!("MEMORY:plank-broker-ldap-{}", std::process::id()));
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Spki { cert } => {
            let pem = std::fs::read(&cert).with_context(|| format!("reading {}", cert.display()))?;
            println!("{}", plank_broker::spki_sha256_hex(&pem)?);
            Ok(())
        }
        Cmd::CheckConfig => {
            let cfg = Config::load(&cli.config)?;
            println!(
                "ok: listen {} endpoint {} ports {}-{}",
                cfg.listen, cfg.public_endpoint, cfg.relay.port_min, cfg.relay.port_max
            );
            Ok(())
        }
        Cmd::Pin { cmd } => {
            let cfg = Config::load(&cli.config)?;
            let pins = PinStore::open(&cfg.hosts.pins_file)?;
            match cmd {
                PinCmd::List => {
                    for (h, p) in pins.list()? {
                        println!("{h} {p}");
                    }
                }
                PinCmd::Reset { fqdn } => {
                    if pins.reset(&fqdn)? {
                        println!("pin for {fqdn} removed; the next probe pins the current certificate");
                    } else {
                        println!("no pin for {fqdn}");
                    }
                }
            }
            Ok(())
        }
        Cmd::Serve => {
            let cfg = Config::load(&cli.config)?;
            #[cfg(feature = "system")]
            kerberos_env(&cfg);
            init_tracing();
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(serve(cfg))
        }
        #[cfg(feature = "system")]
        Cmd::Selftest { cmd } => {
            let cfg = Config::load(&cli.config)?;
            kerberos_env(&cfg);
            init_tracing();
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(selftest(cfg, cmd))
        }
    }
}

/// FreeIPA (default) or Active Directory, by `directory.backend`.
#[cfg(feature = "system")]
fn make_directory(cfg: &Config) -> Result<Arc<dyn plank_broker::directory::Directory>> {
    use plank_broker::config::DirectoryBackend;
    Ok(match cfg.directory.backend {
        DirectoryBackend::Freeipa => Arc::new(plank_broker::ldap::IpaDirectory::new(cfg)?),
        DirectoryBackend::Ad => Arc::new(plank_broker::ad::AdDirectory::new(cfg)?),
    })
}

#[cfg(feature = "system")]
async fn serve(cfg: Config) -> Result<()> {
    use plank_broker::audit::Audit;
    use plank_broker::broker::{Broker, Deps};
    use plank_broker::mit::MitKerberos;
    use plank_broker::probe::TlsProber;
    use plank_broker::relay::UnixRelay;
    use plank_broker::util::SystemClock;

    let acceptor = plank_broker::api::tls_acceptor(&cfg.tls.cert, &cfg.tls.key)?;
    let krb = Arc::new(MitKerberos::new(&cfg.kerberos));
    {
        let k = krb.clone();
        match tokio::task::spawn_blocking(move || k.refresh_armor(true)).await? {
            Ok(()) if krb.is_password_only() => {
                info!("keytab ticket for {} obtained (LDAP GSSAPI credential)", cfg.kerberos.principal)
            }
            Ok(()) => info!("FAST armour ticket obtained for {}", cfg.kerberos.principal),
            Err(e) => error!("keytab ticket for {}: {e} (logins and directory reads fail until this works)", cfg.kerberos.principal),
        }
    }
    if krb.is_password_only() {
        // The keytab TGT is also the process's LDAP credential cache: keep it fresh.
        let k = krb.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                let k2 = k.clone();
                match tokio::task::spawn_blocking(move || k2.refresh_armor(false)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!("keytab ticket refresh: {e}"),
                    Err(e) => warn!("keytab ticket refresh: {e}"),
                }
            }
        });
    }
    let deps = Deps {
        krb,
        dir: make_directory(&cfg)?,
        relay: Arc::new(UnixRelay { socket: cfg.relay.socket.clone() }),
        prober: Arc::new(TlsProber::new(Duration::from_secs(cfg.hosts.probe_timeout_secs))?),
        pins: Arc::new(PinStore::open(&cfg.hosts.pins_file)?),
        audit: Arc::new(Audit::stdout()),
        clock: Arc::new(SystemClock),
        sessions: Arc::new(SessionStore::open(&cfg.kerberos.session_dir)?),
    };
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.with_context(|| format!("bind {}", cfg.listen))?;
    let probe_every = Duration::from_secs(cfg.hosts.probe_interval_secs.max(1));
    let broker = Broker::new(cfg, deps);
    broker.audit_start();
    // Device-bound sessions survive restarts (§14.3); their leases do not.
    let restored = broker.restore_sessions();
    info!("restored {restored} device-bound session(s)");

    // Leases from a previous run are meaningless now.
    {
        let b = broker.clone();
        tokio::spawn(async move {
            loop {
                match b.reset_relay().await {
                    Ok(()) => {
                        info!("relay reset");
                        break;
                    }
                    Err(e) => {
                        warn!("relay reset: {e}; retrying");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }
    {
        let b = broker.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(probe_every);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                b.probe_all().await;
            }
        });
    }
    {
        let b = broker.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(5));
            loop {
                t.tick().await;
                b.reap().await;
            }
        });
    }
    {
        let b = broker.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(3600));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                if plank_broker::support_diagnostics::cleanup(&b).await.is_err() {
                    warn!("support diagnostics cleanup failed");
                }
            }
        });
    }
    let shutdown = async {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    };
    plank_broker::api::serve(broker.clone(), listener, acceptor, shutdown).await?;
    info!("shutting down");
    broker.shutdown().await;
    Ok(())
}

#[cfg(not(feature = "system"))]
async fn serve(_cfg: Config) -> Result<()> {
    anyhow::bail!("built without the `system` feature (no Kerberos/LDAP backends)")
}

#[cfg(feature = "system")]
async fn selftest(cfg: Config, cmd: SelftestCmd) -> Result<()> {
    use std::io::BufRead;
    use std::os::unix::fs::OpenOptionsExt;

    use base64::Engine;
    use plank_broker::hbac::assigned_hosts;
    use plank_broker::kerberos::{Kerberos, LoginOptions};
    use plank_broker::probe::{Prober, TlsProber};
    use zeroize::Zeroizing;

    if cfg.kerberos.password_only {
        // The LDAP bind uses kerberos.principal's keytab ticket: prove it works first.
        let krb = Arc::new(plank_broker::mit::MitKerberos::new(&cfg.kerberos));
        let k = krb.clone();
        tokio::task::spawn_blocking(move || k.refresh_armor(true)).await?.map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("keytab ticket ok for {}", cfg.kerberos.principal);
    }
    let dir = make_directory(&cfg)?;
    match cmd {
        SelftestCmd::Directory { user } => {
            let v = dir.view().await.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("service {} (service groups: {:?})", v.service_dn, v.service_groups);
            for r in &v.rules {
                println!(
                    "rule {:<32} counts={} enabled={} users={} hosts={} services={}",
                    r.name,
                    r.counts(),
                    r.enabled,
                    r.member_users.len(),
                    r.member_hosts.len(),
                    r.member_services.len()
                );
            }
            for h in &v.remote_hosts {
                println!("remote host {} ipv4={:?}", h.fqdn, h.ipv4);
            }
            if let Some(u) = user {
                if cfg.directory.backend == plank_broker::config::DirectoryBackend::Ad {
                    let ad = plank_broker::ad::AdDirectory::new(&cfg)?;
                    match ad.account_report(&u).await {
                        Ok(r) => println!("{r}"),
                        Err(e) => println!("account attributes: {e}"),
                    }
                }
                match dir.user(&u).await.map_err(|e| anyhow::anyhow!("{e}"))? {
                    None => println!("user {u}: not found"),
                    Some(uv) => {
                        println!("user {u}: {} groups", uv.groups.len());
                        println!("assigned: {:?}", assigned_hosts(&v, &uv));
                    }
                }
                // Enrolment gate reads as the broker principal (§16). Tokens of other
                // users are invisible without the "read OTP token ownership" permission,
                // so 0 tokens for a user who has one means that permission is missing.
                let ad = cfg.directory.backend == plank_broker::config::DirectoryBackend::Ad;
                match if ad { Ok(None) } else { dir.enrol_facts(&u).await } {
                    Err(e) => println!("enrolment facts: {e}"),
                    Ok(None) => {}
                    Ok(Some(f)) => {
                        let base = cfg.ldap.base_dn(&cfg.kerberos.realm);
                        let member = |g: &str| {
                            let dn = plank_broker::util::norm_dn(&format!("cn={g},cn=groups,cn=accounts,{base}"));
                            f.groups.iter().any(|x| plank_broker::util::norm_dn(x) == dn)
                        };
                        println!(
                            "enrolment: member of {}={} excluded={:?} disabled={} last_password_change={:?} \
                             password_expiration={:?} tokens={} passkeys={} auth_types={:?} policy={:?}",
                            cfg.enrol.group,
                            member(&cfg.enrol.group),
                            cfg.enrol.excluded_groups.iter().filter(|g| member(g)).collect::<Vec<_>>(),
                            f.disabled,
                            f.last_password_change,
                            f.password_expiration,
                            f.tokens,
                            f.passkeys,
                            f.auth_types,
                            f.policy
                        );
                    }
                }
            }
        }
        SelftestCmd::Kerberos { user, host, password_only, cert_sha256, token_out } => {
            let cert: [u8; 32] = match cert_sha256 {
                Some(h) => {
                    hex::decode(h.trim())?.try_into().map_err(|_| anyhow::anyhow!("--cert-sha256: 32 bytes hex"))?
                }
                None => {
                    let v = dir.view().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                    let ip = v
                        .remote_hosts
                        .iter()
                        .find(|h| h.fqdn == host)
                        .and_then(|h| h.ipv4)
                        .ok_or_else(|| anyhow::anyhow!("{host} is not a remote host with an A record"))?;
                    TlsProber::new(Duration::from_secs(cfg.hosts.probe_timeout_secs))?
                        .probe(&host, ip, cfg.hosts.port)
                        .await
                        .map_err(|e| anyhow::anyhow!("probe {host}: {e}"))?
                }
            };
            println!("host {host} cert sha256 {}", hex::encode(cert));
            let stdin = std::io::stdin();
            let mut lines = stdin.lock().lines();
            let mut secret = Zeroizing::new(lines.next().transpose()?.unwrap_or_default());
            if !password_only {
                let otp = Zeroizing::new(lines.next().transpose()?.unwrap_or_default());
                secret.push_str(otp.trim());
            }
            let krb = Arc::new(plank_broker::mit::MitKerberos::new(&cfg.kerberos));
            let k = krb.clone();
            tokio::task::spawn_blocking(move || k.refresh_armor(true)).await?.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("armour ticket ok");
            let k = krb.clone();
            let u = user.clone();
            let t = tokio::task::spawn_blocking(move || k.login(&u, &secret, LoginOptions::default())).await?;
            let t = match t {
                Ok(t) => t,
                Err(e) => {
                    println!("login: {e}");
                    return Ok(());
                }
            };
            println!("login ok, TGT ends in {} s", t.end_unix.saturating_sub(plank_broker::util::unix_now()));
            let k = krb.clone();
            let cc = t.ccache.clone();
            let h = host.clone();
            let r = tokio::task::spawn_blocking(move || k.ap_req(&cc, &h, &cert)).await?;
            match r {
                Ok(tok) => {
                    println!("AP-REQ ok: {} bytes", tok.len());
                    if let Some(p) = token_out {
                        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p)?;
                        use std::io::Write;
                        writeln!(f, "{}", base64::engine::general_purpose::STANDARD.encode(&tok))?;
                        writeln!(f, "{}", hex::encode(cert))?;
                        println!("token written to {}", p.display());
                    }
                }
                Err(e) => println!("AP-REQ: {e}"),
            }
            krb.destroy(&t.ccache);
        }
    }
    Ok(())
}
