//! MIT Kerberos implementation of [`Kerberos`] (libkrb5 + libgssapi_krb5 FFI).
//!
//! * Armour: a TGT for the broker principal from its keytab in `MEMORY:` ccache,
//!   refreshed before it expires.
//! * Login: `krb5_get_init_creds_password` with FAST (`set_fast_ccache_name`) and a
//!   prompter that answers the KDC's OTP prompt with password‖otp; the resulting
//!   TGT is written to a fresh per-session `MEMORY:` ccache (`set_out_ccache`).
//! * Passkey login: the same exchange with a responder for the SSSD passkey
//!   plugin's `passkey` question (challenge out, phase-2 answer in) and a prompter
//!   that refuses everything. The plugin insists on a prompter being set.
//!
//! Preauth lists: MIT uses `set_preauth_list` only for the *optimistic* first
//! request (empty padata of those types); it does not filter what the KDC offers
//! later. The password path lists OTP (141) and never 153, and sets no responder;
//! its prompter refuses the passkey plugin's prompts. The passkey path lists 153.
//! Which mechanism a user gets is decided by the KDC: IPA offers OTP or passkey,
//! never both, to one principal.
//! * Connect: `gss_acquire_cred_from(ccache=…)` + `gss_init_sec_context` for
//!   `<service>@<fqdn>` (host-based) with `tls-server-end-point` channel bindings,
//!   no mutual auth, so a single AP-REQ token is produced.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use std::sync::RwLock;

use zeroize::Zeroizing;

use crate::enrol::{PwChangeError, PwReject};
use crate::kerberos::LoginOptions;
use crate::kerberos::{channel_binding_data, Kerberos, KrbError, PasskeyAsk, UserTicket};
use crate::passkey::{Challenge, PA_TYPE as PA_REDHAT_PASSKEY};
use crate::util::{random_hex, unix_now};

type KrbCtx = *mut c_void;
type KrbPrincipal = *mut c_void;
type KrbCcache = *mut c_void;
type KrbKeytab = *mut c_void;
type KrbOpt = *mut c_void;

#[repr(C)]
struct KrbData {
    magic: i32,
    length: u32,
    data: *mut c_char,
}

#[repr(C)]
struct KrbKeyblock {
    magic: i32,
    enctype: i32,
    length: u32,
    contents: *mut u8,
}

#[repr(C)]
struct KrbTimes {
    authtime: i32,
    starttime: i32,
    endtime: i32,
    renew_till: i32,
}

#[repr(C)]
struct KrbCreds {
    magic: i32,
    client: KrbPrincipal,
    server: KrbPrincipal,
    keyblock: KrbKeyblock,
    times: KrbTimes,
    is_skey: u32,
    ticket_flags: i32,
    addresses: *mut *mut c_void,
    ticket: KrbData,
    second_ticket: KrbData,
    authdata: *mut *mut c_void,
}

/// `krb5_verify_init_creds_opt` (krb5.h): flags + ap_req_nofail.
#[repr(C)]
struct VerifyOpt {
    flags: i32,
    ap_req_nofail: c_int,
}

#[repr(C)]
struct KrbPrompt {
    prompt: *mut c_char,
    hidden: c_int,
    reply: *mut KrbData,
}

type Prompter = unsafe extern "C" fn(KrbCtx, *mut c_void, *const c_char, *const c_char, c_int, *mut KrbPrompt) -> i32;
type KrbResponderCtx = *mut c_void;
type Responder = unsafe extern "C" fn(KrbCtx, *mut c_void, KrbResponderCtx) -> i32;

#[link(name = "krb5")]
extern "C" {
    fn krb5_init_context(ctx: *mut KrbCtx) -> i32;
    fn krb5_free_context(ctx: KrbCtx);
    fn krb5_parse_name(ctx: KrbCtx, name: *const c_char, out: *mut KrbPrincipal) -> i32;
    fn krb5_free_principal(ctx: KrbCtx, p: KrbPrincipal);
    fn krb5_cc_resolve(ctx: KrbCtx, name: *const c_char, out: *mut KrbCcache) -> i32;
    fn krb5_cc_close(ctx: KrbCtx, cc: KrbCcache) -> i32;
    fn krb5_cc_destroy(ctx: KrbCtx, cc: KrbCcache) -> i32;
    fn krb5_kt_resolve(ctx: KrbCtx, name: *const c_char, out: *mut KrbKeytab) -> i32;
    fn krb5_kt_close(ctx: KrbCtx, kt: KrbKeytab) -> i32;
    fn krb5_get_init_creds_opt_alloc(ctx: KrbCtx, out: *mut KrbOpt) -> i32;
    fn krb5_get_init_creds_opt_free(ctx: KrbCtx, opt: KrbOpt);
    fn krb5_get_init_creds_opt_set_tkt_life(opt: KrbOpt, life: i32);
    fn krb5_get_init_creds_opt_set_renew_life(opt: KrbOpt, life: i32);
    fn krb5_get_renewed_creds(
        ctx: KrbCtx,
        creds: *mut KrbCreds,
        client: KrbPrincipal,
        cc: KrbCcache,
        in_tkt_service: *const c_char,
    ) -> i32;
    fn krb5_cc_get_principal(ctx: KrbCtx, cc: KrbCcache, out: *mut KrbPrincipal) -> i32;
    fn krb5_cc_initialize(ctx: KrbCtx, cc: KrbCcache, principal: KrbPrincipal) -> i32;
    fn krb5_cc_store_cred(ctx: KrbCtx, cc: KrbCcache, creds: *mut KrbCreds) -> i32;
    fn krb5_get_init_creds_opt_set_forwardable(opt: KrbOpt, v: c_int);
    fn krb5_get_init_creds_opt_set_proxiable(opt: KrbOpt, v: c_int);
    fn krb5_get_init_creds_opt_set_fast_ccache_name(ctx: KrbCtx, opt: KrbOpt, name: *const c_char) -> i32;
    fn krb5_get_init_creds_opt_set_out_ccache(ctx: KrbCtx, opt: KrbOpt, cc: KrbCcache) -> i32;
    fn krb5_get_init_creds_opt_set_preauth_list(opt: KrbOpt, list: *mut i32, len: c_int);
    fn krb5_get_init_creds_opt_set_responder(ctx: KrbCtx, opt: KrbOpt, f: Option<Responder>, data: *mut c_void) -> i32;
    fn krb5_responder_get_challenge(ctx: KrbCtx, rctx: KrbResponderCtx, question: *const c_char) -> *const c_char;
    fn krb5_responder_set_answer(
        ctx: KrbCtx,
        rctx: KrbResponderCtx,
        question: *const c_char,
        answer: *const c_char,
    ) -> i32;
    fn krb5_get_init_creds_password(
        ctx: KrbCtx,
        creds: *mut KrbCreds,
        client: KrbPrincipal,
        password: *const c_char,
        prompter: Option<Prompter>,
        data: *mut c_void,
        start_time: i32,
        in_tkt_service: *const c_char,
        opt: KrbOpt,
    ) -> i32;
    fn krb5_get_init_creds_keytab(
        ctx: KrbCtx,
        creds: *mut KrbCreds,
        client: KrbPrincipal,
        keytab: KrbKeytab,
        start_time: i32,
        in_tkt_service: *const c_char,
        opt: KrbOpt,
    ) -> i32;
    fn krb5_free_cred_contents(ctx: KrbCtx, creds: *mut KrbCreds);
    fn krb5_verify_init_creds_opt_init(opt: *mut VerifyOpt);
    fn krb5_verify_init_creds_opt_set_ap_req_nofail(opt: *mut VerifyOpt, ap_req_nofail: c_int);
    fn krb5_verify_init_creds(
        ctx: KrbCtx,
        creds: *mut KrbCreds,
        server: KrbPrincipal,
        keytab: KrbKeytab,
        ccache: *mut KrbCcache,
        opt: *mut VerifyOpt,
    ) -> i32;
    fn krb5_get_error_message(ctx: KrbCtx, code: i32) -> *const c_char;
    fn krb5_free_error_message(ctx: KrbCtx, msg: *const c_char);
    fn krb5_get_prompt_types(ctx: KrbCtx) -> *mut i32;
    fn krb5_change_password(
        ctx: KrbCtx,
        creds: *mut KrbCreds,
        newpw: *const c_char,
        result_code: *mut c_int,
        result_code_string: *mut KrbData,
        result_string: *mut KrbData,
    ) -> i32;
    fn krb5_free_data_contents(ctx: KrbCtx, data: *mut KrbData);
}

type OmUint32 = u32;
type GssName = *mut c_void;
type GssCred = *mut c_void;
type GssCtx = *mut c_void;

#[repr(C)]
struct GssBuffer {
    length: usize,
    value: *mut c_void,
}

#[repr(C)]
struct GssOidDesc {
    length: OmUint32,
    elements: *mut c_void,
}
type GssOid = *mut GssOidDesc;

#[repr(C)]
struct GssChannelBindings {
    initiator_addrtype: OmUint32,
    initiator_address: GssBuffer,
    acceptor_addrtype: OmUint32,
    acceptor_address: GssBuffer,
    application_data: GssBuffer,
}

#[repr(C)]
struct GssKeyValueElement {
    key: *const c_char,
    value: *const c_char,
}

#[repr(C)]
struct GssKeyValueSet {
    count: OmUint32,
    elements: *mut GssKeyValueElement,
}

#[link(name = "gssapi_krb5")]
extern "C" {
    static GSS_C_NT_HOSTBASED_SERVICE: GssOid;
    static gss_mech_krb5: GssOid;
    fn gss_import_name(minor: *mut OmUint32, input: *mut GssBuffer, ntype: GssOid, out: *mut GssName) -> OmUint32;
    fn gss_release_name(minor: *mut OmUint32, name: *mut GssName) -> OmUint32;
    fn gss_acquire_cred_from(
        minor: *mut OmUint32,
        desired_name: GssName,
        time_req: OmUint32,
        desired_mechs: *mut c_void,
        usage: c_int,
        cred_store: *const GssKeyValueSet,
        out_cred: *mut GssCred,
        actual_mechs: *mut *mut c_void,
        time_rec: *mut OmUint32,
    ) -> OmUint32;
    fn gss_release_cred(minor: *mut OmUint32, cred: *mut GssCred) -> OmUint32;
    fn gss_init_sec_context(
        minor: *mut OmUint32,
        cred: GssCred,
        ctx: *mut GssCtx,
        target: GssName,
        mech: GssOid,
        req_flags: OmUint32,
        time_req: OmUint32,
        cb: *mut GssChannelBindings,
        input: *mut GssBuffer,
        actual_mech: *mut GssOid,
        output: *mut GssBuffer,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
    ) -> OmUint32;
    fn gss_delete_sec_context(minor: *mut OmUint32, ctx: *mut GssCtx, out: *mut GssBuffer) -> OmUint32;
    fn gss_release_buffer(minor: *mut OmUint32, buf: *mut GssBuffer) -> OmUint32;
    fn gss_display_status(
        minor: *mut OmUint32,
        status: OmUint32,
        status_type: c_int,
        mech: GssOid,
        msg_ctx: *mut OmUint32,
        out: *mut GssBuffer,
    ) -> OmUint32;
}

const GSS_C_INITIATE: c_int = 1;
const GSS_C_INDEFINITE: OmUint32 = 0xffff_ffff;
const GSS_C_GSS_CODE: c_int = 1;
const GSS_C_MECH_CODE: c_int = 2;
const GSS_S_COMPLETE: OmUint32 = 0;
const GSS_C_AF_UNSPEC: OmUint32 = 0;

const KRB5_KDC_UNREACH: i32 = -1765328228;
const KRB5_REALM_CANT_RESOLVE: i32 = -1765328164;
// "Cannot find KDC for realm": no kdc/kpasswd_server configured or resolvable for the realm.
const KRB5_REALM_UNKNOWN: i32 = -1765328230;
/// Infrastructure failures (no reachable or configured KDC/kpasswd server). They must never
/// count as a user's failed credential: that would feed the broker's per-user limiter and
/// lock people out over a configuration error.
fn is_unavailable(code: i32) -> bool {
    matches!(
        code,
        KRB5_KDC_UNREACH
            | KRB5_REALM_CANT_RESOLVE
            | KRB5_REALM_UNKNOWN
            | KRB5KDC_ERR_ETYPE_NOSUPP
            | KRB5_PROG_ETYPE_NOSUPP
            | KRB5KRB_AP_ERR_SKEW
            | KRB5KDC_ERR_SVC_UNAVAILABLE
    )
}

/// Clock skew between this host and the KDC, or a KDC that says it is unavailable: our
/// problem, never the user's wrong password.
const KRB5KRB_AP_ERR_SKEW: i32 = -1765328347;
const KRB5KDC_ERR_SVC_UNAVAILABLE: i32 = -1765328355;
/// The client principal is not in the database: nothing for the lockout counter to count.
const KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = -1765328378;

/// The account (or KDC) has no encryption type we support, e.g. an AD account that only has
/// RC4 keys. A configuration problem of that account, not a wrong password: it is reported as
/// "unavailable" so it never counts toward the per-user block.
const KRB5KDC_ERR_ETYPE_NOSUPP: i32 = -1765328370;
const KRB5_PROG_ETYPE_NOSUPP: i32 = -1765328234;

const KRB5_PROMPT_TYPE_PASSWORD: i32 = 1;
const KRB5_PROMPT_TYPE_PREAUTH: i32 = 4;
/// Returned from the prompter to abort the exchange (maps to "denied").
const PROMPT_ABORT: i32 = libc::ECANCELED;
/// `PA-OTP-CHALLENGE`.
const KRB5_PADATA_OTP_CHALLENGE: i32 = 141;
/// kpasswd result codes (RFC 3244).
const KRB5_KPASSWD_SUCCESS: c_int = 0;
const KRB5_KPASSWD_AUTHERROR: c_int = 3;
const KRB5_KPASSWD_SOFTERROR: c_int = 4;
const KRB5_KPASSWD_ACCESSDENIED: c_int = 5;
/// Service of the password-change ticket (enrolment proof, kpasswd).
const CHANGEPW_SERVICE: &CStr = c"kadmin/changepw";

/// RAII krb5 context.
struct Ctx(KrbCtx);
impl Ctx {
    fn new() -> Result<Ctx, KrbError> {
        let mut c = ptr::null_mut();
        let rc = unsafe { krb5_init_context(&mut c) };
        if rc != 0 {
            return Err(KrbError::Unavailable(format!("krb5_init_context failed ({rc})")));
        }
        Ok(Ctx(c))
    }
    fn msg(&self, code: i32) -> String {
        unsafe {
            let m = krb5_get_error_message(self.0, code);
            if m.is_null() {
                return format!("krb5 error {code}");
            }
            let s = CStr::from_ptr(m).to_string_lossy().into_owned();
            krb5_free_error_message(self.0, m);
            s
        }
    }
    fn err(&self, code: i32, what: &str) -> KrbError {
        let mut m = format!("{what}: {}", self.msg(code));
        if code == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN {
            m = format!("unknown principal: {m}");
        }
        if is_unavailable(code) {
            KrbError::Unavailable(m)
        } else {
            KrbError::Denied(m)
        }
    }
}
impl Drop for Ctx {
    fn drop(&mut self) {
        unsafe { krb5_free_context(self.0) }
    }
}

struct Opt<'a>(&'a Ctx, KrbOpt);
impl<'a> Opt<'a> {
    fn new(ctx: &'a Ctx) -> Result<Opt<'a>, KrbError> {
        let mut o = ptr::null_mut();
        let rc = unsafe { krb5_get_init_creds_opt_alloc(ctx.0, &mut o) };
        if rc != 0 {
            return Err(KrbError::Unavailable(ctx.msg(rc)));
        }
        Ok(Opt(ctx, o))
    }
}
impl Drop for Opt<'_> {
    fn drop(&mut self) {
        unsafe { krb5_get_init_creds_opt_free(self.0 .0, self.1) }
    }
}

struct Princ<'a>(&'a Ctx, KrbPrincipal);
impl<'a> Princ<'a> {
    fn parse(ctx: &'a Ctx, name: &str) -> Result<Princ<'a>, KrbError> {
        let c = CString::new(name).map_err(|_| KrbError::Denied("bad principal".into()))?;
        let mut p = ptr::null_mut();
        let rc = unsafe { krb5_parse_name(ctx.0, c.as_ptr(), &mut p) };
        if rc != 0 {
            return Err(ctx.err(rc, "parse principal"));
        }
        Ok(Princ(ctx, p))
    }
}
impl Drop for Princ<'_> {
    fn drop(&mut self) {
        unsafe { krb5_free_principal(self.0 .0, self.1) }
    }
}

struct Cc<'a>(&'a Ctx, KrbCcache);
impl<'a> Cc<'a> {
    fn resolve(ctx: &'a Ctx, name: &str) -> Result<Cc<'a>, KrbError> {
        let c = CString::new(name).map_err(|_| KrbError::Unavailable("bad ccache name".into()))?;
        let mut cc = ptr::null_mut();
        let rc = unsafe { krb5_cc_resolve(ctx.0, c.as_ptr(), &mut cc) };
        if rc != 0 {
            return Err(KrbError::Unavailable(ctx.msg(rc)));
        }
        Ok(Cc(ctx, cc))
    }
    fn destroy(mut self) {
        unsafe { krb5_cc_destroy(self.0 .0, self.1) };
        self.1 = ptr::null_mut();
    }
}
impl Drop for Cc<'_> {
    fn drop(&mut self) {
        if !self.1.is_null() {
            unsafe { krb5_cc_close(self.0 .0, self.1) };
        }
    }
}

fn zero_creds() -> KrbCreds {
    // SAFETY: plain C struct, all-zero is the documented initial state.
    unsafe { std::mem::zeroed() }
}

struct PromptState<'a> {
    secret: &'a [u8],
    calls: u32,
}

/// Answers password / pre-auth (OTP) prompts with password‖otp, once per prompt,
/// at most twice per exchange. Refuses anything else (new-password prompts on an
/// expired password, token selection menus) so a login can never change a password.
unsafe extern "C" fn prompter(
    ctx: KrbCtx,
    data: *mut c_void,
    _name: *const c_char,
    _banner: *const c_char,
    num: c_int,
    prompts: *mut KrbPrompt,
) -> i32 {
    let st = &mut *(data as *mut PromptState);
    st.calls += 1;
    if st.calls > 2 || num <= 0 || prompts.is_null() {
        return PROMPT_ABORT;
    }
    let types = krb5_get_prompt_types(ctx);
    for i in 0..num as usize {
        let p = &mut *prompts.add(i);
        let ty = if types.is_null() { 0 } else { *types.add(i) };
        let text = if p.prompt.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p.prompt).to_string_lossy().to_ascii_lowercase()
        };
        // The SSSD passkey plugin's own prompts ("Insert your passkey device…",
        // "Enter PIN") are never answered with the password.
        if text.contains("passkey") || text.trim() == "enter pin" {
            return PROMPT_ABORT;
        }
        let ok_type = ty == KRB5_PROMPT_TYPE_PASSWORD
            || ty == KRB5_PROMPT_TYPE_PREAUTH
            || (ty == 0
                && p.hidden != 0
                && (text.contains("otp") || text.contains("password") || text.contains("factor")));
        if !ok_type || text.contains("new password") || p.reply.is_null() {
            return PROMPT_ABORT;
        }
        let r = &mut *p.reply;
        if (r.length as usize) < st.secret.len() || r.data.is_null() {
            return PROMPT_ABORT;
        }
        ptr::copy_nonoverlapping(st.secret.as_ptr(), r.data as *mut u8, st.secret.len());
        r.length = st.secret.len() as u32;
    }
    0
}

/// Passkey exchanges refuse every prompt; only the responder answers.
unsafe extern "C" fn refuse_prompter(
    _ctx: KrbCtx,
    _data: *mut c_void,
    _name: *const c_char,
    _banner: *const c_char,
    _num: c_int,
    _prompts: *mut KrbPrompt,
) -> i32 {
    PROMPT_ABORT
}

struct PasskeyState<'a, 'b> {
    ask: &'a mut PasskeyAsk<'b>,
    /// Armour read lock: held until the KDC challenge arrives (the armour has been
    /// turned into the exchange's FAST state by then), released before waiting
    /// for the client so a slow user never blocks an armour refresh.
    armor: Option<std::sync::RwLockReadGuard<'a, u64>>,
    asked: bool,
}

/// Responder for the SSSD passkey plugin: hand the KDC challenge to `ask`, turn
/// the assertion into the phase-2 answer. Any other question set aborts.
unsafe extern "C" fn passkey_responder(ctx: KrbCtx, data: *mut c_void, rctx: KrbResponderCtx) -> i32 {
    let st = &mut *(data as *mut PasskeyState);
    let q = krb5_responder_get_challenge(ctx, rctx, PASSKEY_QUESTION.as_ptr());
    if q.is_null() || st.asked {
        return PROMPT_ABORT;
    }
    st.asked = true;
    let Ok(text) = CStr::from_ptr(q).to_str() else { return PROMPT_ABORT };
    let Some(ch) = Challenge::parse_question(text) else { return PROMPT_ABORT };
    st.armor = None;
    let Some(a) = (st.ask)(&ch) else { return PROMPT_ABORT };
    let Some(answer) = ch.answer(&a).and_then(|s| CString::new(s).ok()) else { return PROMPT_ABORT };
    // libkrb5 copies the answer.
    krb5_responder_set_answer(ctx, rctx, PASSKEY_QUESTION.as_ptr(), answer.as_ptr())
}

const PASSKEY_QUESTION: &CStr = c"passkey";

pub struct MitKerberos {
    realm: String,
    principal: String,
    keytab: String,
    host_service: String,
    ticket_lifetime: i32,
    /// Directory for `FILE:` ccaches of device-bound sessions (§14).
    session_dir: std::path::PathBuf,
    armor_ccache: String,
    /// End time of the current armour TGT (0 = none). Logins hold the read lock.
    armor: RwLock<u64>,
    /// Active Directory: plain password AS exchange, no OTP list, no FAST.
    password_only: bool,
    /// Service principal whose keytab key authenticates the KDC's answer (AD mode).
    verify_principal: Option<String>,
}

impl MitKerberos {
    pub fn new(cfg: &crate::config::KerberosConfig) -> MitKerberos {
        MitKerberos {
            realm: cfg.realm.clone(),
            principal: cfg.principal.clone(),
            keytab: format!("FILE:{}", cfg.keytab.display()),
            host_service: cfg.host_service.clone(),
            ticket_lifetime: cfg.ticket_lifetime_secs as i32,
            session_dir: cfg.session_dir.clone(),
            // AD mode: this keytab TGT doubles as the LDAP GSSAPI credential cache of the
            // process (`KRB5CCNAME`, see `kerberos_env` in the binary), so the LDAP bind uses
            // exactly `kerberos.principal`.
            armor_ccache: if cfg.password_only {
                format!("MEMORY:plank-broker-ldap-{}", std::process::id())
            } else {
                format!("MEMORY:plank-broker-armor-{}", std::process::id())
            },
            armor: RwLock::new(0),
            password_only: cfg.password_only,
            verify_principal: cfg.verify_principal.clone(),
        }
    }

    /// True for the password-only (Active Directory) mode, which needs no FAST armour.
    pub fn is_password_only(&self) -> bool {
        self.password_only
    }

    /// Obtain / refresh the FAST armour TGT from the keytab.
    pub fn refresh_armor(&self, force: bool) -> Result<(), KrbError> {
        {
            let end = *self.armor.read().unwrap();
            if !force && end > unix_now() + 600 {
                return Ok(());
            }
        }
        let mut end = self.armor.write().unwrap();
        if !force && *end > unix_now() + 600 {
            return Ok(());
        }
        let ctx = Ctx::new()?;
        let princ = Princ::parse(&ctx, &self.principal)?;
        let ktname = CString::new(self.keytab.clone()).unwrap();
        let mut kt = ptr::null_mut();
        let rc = unsafe { krb5_kt_resolve(ctx.0, ktname.as_ptr(), &mut kt) };
        if rc != 0 {
            return Err(KrbError::Unavailable(format!("keytab: {}", ctx.msg(rc))));
        }
        let cc = Cc::resolve(&ctx, &self.armor_ccache)?;
        let opt = Opt::new(&ctx)?;
        let mut creds = zero_creds();
        let rc = unsafe {
            krb5_get_init_creds_opt_set_forwardable(opt.1, 0);
            krb5_get_init_creds_opt_set_proxiable(opt.1, 0);
            let rc = krb5_get_init_creds_opt_set_out_ccache(ctx.0, opt.1, cc.1);
            if rc != 0 {
                rc
            } else {
                krb5_get_init_creds_keytab(ctx.0, &mut creds, princ.1, kt, 0, ptr::null(), opt.1)
            }
        };
        unsafe { krb5_kt_close(ctx.0, kt) };
        if rc != 0 {
            let m = format!("armour TGT from keytab: {}", ctx.msg(rc));
            return Err(KrbError::Unavailable(m));
        }
        *end = creds.times.endtime as u32 as u64;
        unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
        Ok(())
    }

    fn gss_error(major: OmUint32, minor: OmUint32) -> String {
        let mut out = String::new();
        for (code, ty) in [(major, GSS_C_GSS_CODE), (minor, GSS_C_MECH_CODE)] {
            if code == 0 {
                continue;
            }
            let mut ctx_id: OmUint32 = 0;
            loop {
                let mut min = 0;
                let mut buf = GssBuffer { length: 0, value: ptr::null_mut() };
                let maj = unsafe { gss_display_status(&mut min, code, ty, ptr::null_mut(), &mut ctx_id, &mut buf) };
                if maj != GSS_S_COMPLETE {
                    break;
                }
                if !buf.value.is_null() {
                    let s = unsafe { std::slice::from_raw_parts(buf.value as *const u8, buf.length) };
                    if !out.is_empty() {
                        out.push_str("; ");
                    }
                    out.push_str(&String::from_utf8_lossy(s));
                }
                unsafe { gss_release_buffer(&mut min, &mut buf) };
                if ctx_id == 0 {
                    break;
                }
            }
        }
        out
    }
}

/// NUL-terminated copy of a secret for the C API, wiped on drop.
fn c_secret(s: &str) -> Result<Zeroizing<Vec<u8>>, KrbError> {
    if s.as_bytes().contains(&0) {
        return Err(KrbError::Denied("NUL in secret".into()));
    }
    let mut v = Zeroizing::new(Vec::with_capacity(s.len() + 1));
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    Ok(v)
}

fn data_text(d: &KrbData) -> String {
    if d.data.is_null() || d.length == 0 {
        return String::new();
    }
    let raw = unsafe { std::slice::from_raw_parts(d.data as *const u8, d.length as usize) };
    String::from_utf8_lossy(raw).chars().filter(|c| !c.is_control()).collect()
}

impl MitKerberos {
    /// FAST-armoured AS exchange for `kadmin/changepw` answered with `password`
    /// alone (enrolment proof, kpasswd). Every prompt is refused, so an OTP challenge
    /// (enabled token: FAST makes the KDC insist) fails the exchange. An expired
    /// password works: the KDC issues changepw tickets for it. `creds` must be freed.
    fn changepw_creds(
        &self,
        ctx: &Ctx,
        username: &str,
        password: &Zeroizing<String>,
        creds: &mut KrbCreds,
    ) -> Result<(), KrbError> {
        self.refresh_armor(false)?;
        let _armor = self.armor.read().unwrap();
        let princ = Princ::parse(ctx, &format!("{username}@{}", self.realm))?;
        let opt = Opt::new(ctx)?;
        let armor = CString::new(self.armor_ccache.clone()).unwrap();
        let pw = c_secret(password)?;
        let rc = unsafe {
            krb5_get_init_creds_opt_set_forwardable(opt.1, 0);
            krb5_get_init_creds_opt_set_proxiable(opt.1, 0);
            krb5_get_init_creds_opt_set_tkt_life(opt.1, 300);
            let mut rc = krb5_get_init_creds_opt_set_fast_ccache_name(ctx.0, opt.1, armor.as_ptr());
            if rc == 0 {
                rc = krb5_get_init_creds_password(
                    ctx.0,
                    creds,
                    princ.1,
                    pw.as_ptr() as *const c_char,
                    Some(refuse_prompter),
                    ptr::null_mut(),
                    0,
                    CHANGEPW_SERVICE.as_ptr(),
                    opt.1,
                );
            }
            rc
        };
        if rc != 0 {
            return Err(ctx.err(rc, "AS exchange (kadmin/changepw)"));
        }
        Ok(())
    }

    /// `krb5_verify_init_creds` against the broker keytab with `ap_req_nofail`.
    fn verify_creds(&self, ctx: &Ctx, creds: &mut KrbCreds) -> Result<(), KrbError> {
        let Some(name) = &self.verify_principal else {
            return Err(KrbError::Unavailable("kerberos.verify_principal is not configured".into()));
        };
        let server = Princ::parse(ctx, name)?;
        let ktname = CString::new(self.keytab.clone()).unwrap();
        let mut kt = ptr::null_mut();
        let rc = unsafe { krb5_kt_resolve(ctx.0, ktname.as_ptr(), &mut kt) };
        if rc != 0 {
            return Err(KrbError::Unavailable(format!("keytab: {}", ctx.msg(rc))));
        }
        let mut vopt = VerifyOpt { flags: 0, ap_req_nofail: 0 };
        let rc = unsafe {
            krb5_verify_init_creds_opt_init(&mut vopt);
            krb5_verify_init_creds_opt_set_ap_req_nofail(&mut vopt, 1);
            krb5_verify_init_creds(ctx.0, creds, server.1, kt, ptr::null_mut(), &mut vopt)
        };
        unsafe { krb5_kt_close(ctx.0, kt) };
        if rc != 0 {
            // Never a password failure: the user's password was already accepted.
            return Err(KrbError::Unavailable(format!("TGT verification failed: {}", ctx.msg(rc))));
        }
        Ok(())
    }

    fn user_ccache(&self, opts: LoginOptions) -> String {
        if opts.persistent {
            format!("FILE:{}/pb-{}.ccache", self.session_dir.display(), random_hex(16))
        } else {
            format!("MEMORY:pb-{}", random_hex(16))
        }
    }
}

/// Ticket options shared by both login paths.
unsafe fn set_ticket_opts(opt: KrbOpt, lifetime: i32, opts: LoginOptions) {
    krb5_get_init_creds_opt_set_forwardable(opt, 0);
    krb5_get_init_creds_opt_set_proxiable(opt, 0);
    krb5_get_init_creds_opt_set_tkt_life(opt, lifetime);
    if let Some(renew) = opts.renew_life_secs {
        krb5_get_init_creds_opt_set_renew_life(opt, renew.min(i32::MAX as u32) as i32);
    }
}

fn ticket_of(ccache: String, creds: &KrbCreds) -> UserTicket {
    UserTicket {
        ccache,
        end_unix: creds.times.endtime as u32 as u64,
        renew_till_unix: creds.times.renew_till as u32 as u64,
    }
}

impl Kerberos for MitKerberos {
    fn login(&self, username: &str, secret: &Zeroizing<String>, opts: LoginOptions) -> Result<UserTicket, KrbError> {
        self.refresh_armor(false)?;
        let _armor = self.armor.read().unwrap();
        let ctx = Ctx::new()?;
        let princ = Princ::parse(&ctx, &format!("{username}@{}", self.realm))?;
        let ccname = self.user_ccache(opts);
        let cc = Cc::resolve(&ctx, &ccname)?;
        let opt = Opt::new(&ctx)?;
        let armor = CString::new(self.armor_ccache.clone()).unwrap();
        let mut st = PromptState { secret: secret.as_bytes(), calls: 0 };
        let mut creds = zero_creds();
        let rc = unsafe {
            set_ticket_opts(opt.1, self.ticket_lifetime, opts);
            let mut preauth = [KRB5_PADATA_OTP_CHALLENGE];
            let mut rc = 0;
            if !self.password_only {
                // FreeIPA: OTP pre-auth under FAST. Active Directory: a plain
                // password AS-REQ (PA-ENC-TIMESTAMP); the prompter answers its
                // single password prompt.
                krb5_get_init_creds_opt_set_preauth_list(opt.1, preauth.as_mut_ptr(), preauth.len() as c_int);
                rc = krb5_get_init_creds_opt_set_fast_ccache_name(ctx.0, opt.1, armor.as_ptr());
            }
            if rc == 0 {
                rc = krb5_get_init_creds_opt_set_out_ccache(ctx.0, opt.1, cc.1);
            }
            if rc == 0 {
                rc = krb5_get_init_creds_password(
                    ctx.0,
                    &mut creds,
                    princ.1,
                    ptr::null(),
                    Some(prompter),
                    &mut st as *mut PromptState as *mut c_void,
                    0,
                    ptr::null(),
                    opt.1,
                );
            }
            rc
        };
        if rc != 0 {
            cc.destroy();
            return Err(ctx.err(rc, "AS exchange"));
        }
        if self.password_only {
            // A spoofed KDC (or a poisoned DNS answer) could accept any password: check the
            // TGT by getting a service ticket for our own keytab principal and decrypting
            // it with the keytab key. Fails the login when that does not work.
            if let Err(e) = self.verify_creds(&ctx, &mut creds) {
                unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
                cc.destroy();
                return Err(e);
            }
        }
        let ticket = ticket_of(ccname, &creds);
        unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
        Ok(ticket)
    }

    fn login_passkey(
        &self,
        username: &str,
        ask: &mut PasskeyAsk<'_>,
        opts: LoginOptions,
    ) -> Result<UserTicket, KrbError> {
        self.refresh_armor(false)?;
        let ctx = Ctx::new()?;
        let princ = Princ::parse(&ctx, &format!("{username}@{}", self.realm))?;
        let ccname = self.user_ccache(opts);
        let cc = Cc::resolve(&ctx, &ccname)?;
        let opt = Opt::new(&ctx)?;
        let armor = CString::new(self.armor_ccache.clone()).unwrap();
        let mut st = PasskeyState { ask, armor: Some(self.armor.read().unwrap()), asked: false };
        let mut creds = zero_creds();
        let rc = unsafe {
            set_ticket_opts(opt.1, self.ticket_lifetime, opts);
            let mut preauth = [PA_REDHAT_PASSKEY];
            krb5_get_init_creds_opt_set_preauth_list(opt.1, preauth.as_mut_ptr(), preauth.len() as c_int);
            let mut rc = krb5_get_init_creds_opt_set_fast_ccache_name(ctx.0, opt.1, armor.as_ptr());
            if rc == 0 {
                rc = krb5_get_init_creds_opt_set_out_ccache(ctx.0, opt.1, cc.1);
            }
            if rc == 0 {
                rc = krb5_get_init_creds_opt_set_responder(
                    ctx.0,
                    opt.1,
                    Some(passkey_responder),
                    &mut st as *mut PasskeyState as *mut c_void,
                );
            }
            if rc == 0 {
                rc = krb5_get_init_creds_password(
                    ctx.0,
                    &mut creds,
                    princ.1,
                    ptr::null(),
                    Some(refuse_prompter),
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                    opt.1,
                );
            }
            rc
        };
        drop(st);
        if rc != 0 {
            cc.destroy();
            return Err(ctx.err(rc, "AS exchange (passkey)"));
        }
        let ticket = ticket_of(ccname, &creds);
        unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
        Ok(ticket)
    }

    fn renew(&self, ccache: &str) -> Result<UserTicket, KrbError> {
        let ctx = Ctx::new()?;
        let cc = Cc::resolve(&ctx, ccache)?;
        let mut client = ptr::null_mut();
        let rc = unsafe { krb5_cc_get_principal(ctx.0, cc.1, &mut client) };
        if rc != 0 {
            return Err(ctx.err(rc, "renew: ccache principal"));
        }
        let client = Princ(&ctx, client);
        let mut creds = zero_creds();
        // Same as `kinit -R`: TGS renewal of the TGT, then replace the cache content.
        let mut rc = unsafe { krb5_get_renewed_creds(ctx.0, &mut creds, client.1, cc.1, ptr::null()) };
        if rc == 0 {
            rc = unsafe { krb5_cc_initialize(ctx.0, cc.1, client.1) };
        }
        if rc == 0 {
            rc = unsafe { krb5_cc_store_cred(ctx.0, cc.1, &mut creds) };
        }
        let ticket = ticket_of(ccache.to_string(), &creds);
        unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
        if rc != 0 {
            return Err(ctx.err(rc, "renew"));
        }
        Ok(ticket)
    }

    fn ap_req(&self, ccache: &str, fqdn: &str, cert_sha256: &[u8; 32]) -> Result<Vec<u8>, KrbError> {
        let key = CString::new("ccache").unwrap();
        let val = CString::new(ccache).map_err(|_| KrbError::Unavailable("bad ccache".into()))?;
        let mut elem = GssKeyValueElement { key: key.as_ptr(), value: val.as_ptr() };
        let store = GssKeyValueSet { count: 1, elements: &mut elem };
        let target = format!("{}@{}", self.host_service, fqdn);
        let mut minor: OmUint32 = 0;
        let mut name: GssName = ptr::null_mut();
        let mut cred: GssCred = ptr::null_mut();
        let mut ctx: GssCtx = ptr::null_mut();
        let mut cb_data = channel_binding_data(cert_sha256);
        let mut out = GssBuffer { length: 0, value: ptr::null_mut() };
        let result = unsafe {
            let mut nbuf = GssBuffer { length: target.len(), value: target.as_ptr() as *mut c_void };
            let maj = gss_import_name(&mut minor, &mut nbuf, GSS_C_NT_HOSTBASED_SERVICE, &mut name);
            if maj != GSS_S_COMPLETE {
                Err(KrbError::Unavailable(format!("import name: {}", Self::gss_error(maj, minor))))
            } else {
                let maj = gss_acquire_cred_from(
                    &mut minor,
                    ptr::null_mut(),
                    GSS_C_INDEFINITE,
                    ptr::null_mut(),
                    GSS_C_INITIATE,
                    &store,
                    &mut cred,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                if maj != GSS_S_COMPLETE {
                    Err(KrbError::Denied(format!("acquire cred: {}", Self::gss_error(maj, minor))))
                } else {
                    let mut cb = GssChannelBindings {
                        initiator_addrtype: GSS_C_AF_UNSPEC,
                        initiator_address: GssBuffer { length: 0, value: ptr::null_mut() },
                        acceptor_addrtype: GSS_C_AF_UNSPEC,
                        acceptor_address: GssBuffer { length: 0, value: ptr::null_mut() },
                        application_data: GssBuffer {
                            length: cb_data.len(),
                            value: cb_data.as_mut_ptr() as *mut c_void,
                        },
                    };
                    let maj = gss_init_sec_context(
                        &mut minor,
                        cred,
                        &mut ctx,
                        name,
                        gss_mech_krb5,
                        0,
                        0,
                        &mut cb,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut out,
                        ptr::null_mut(),
                        ptr::null_mut(),
                    );
                    if maj != GSS_S_COMPLETE {
                        let m = Self::gss_error(maj, minor);
                        if minor as i32 == KRB5_KDC_UNREACH {
                            Err(KrbError::Unavailable(format!("init_sec_context: {m}")))
                        } else {
                            Err(KrbError::Denied(format!("init_sec_context: {m}")))
                        }
                    } else if out.value.is_null() || out.length == 0 {
                        Err(KrbError::Unavailable("empty AP-REQ".into()))
                    } else {
                        Ok(std::slice::from_raw_parts(out.value as *const u8, out.length).to_vec())
                    }
                }
            }
        };
        unsafe {
            let mut m = 0;
            if !out.value.is_null() {
                gss_release_buffer(&mut m, &mut out);
            }
            if !ctx.is_null() {
                gss_delete_sec_context(&mut m, &mut ctx, ptr::null_mut());
            }
            if !cred.is_null() {
                gss_release_cred(&mut m, &mut cred);
            }
            if !name.is_null() {
                gss_release_name(&mut m, &mut name);
            }
        }
        result
    }

    fn destroy(&self, ccache: &str) {
        if let Ok(ctx) = Ctx::new() {
            if let Ok(cc) = Cc::resolve(&ctx, ccache) {
                cc.destroy();
            }
        }
    }

    fn prove_password(&self, username: &str, password: &Zeroizing<String>) -> Result<(), KrbError> {
        let ctx = Ctx::new()?;
        let mut creds = zero_creds();
        let r = self.changepw_creds(&ctx, username, password, &mut creds);
        unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
        r
    }

    fn change_password(
        &self,
        username: &str,
        old: &Zeroizing<String>,
        new: &Zeroizing<String>,
    ) -> Result<(), PwChangeError> {
        let ctx = Ctx::new().map_err(PwChangeError::Krb)?;
        let mut creds = zero_creds();
        if let Err(e) = self.changepw_creds(&ctx, username, old, &mut creds) {
            unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
            return Err(PwChangeError::Krb(e));
        }
        let new = match c_secret(new) {
            Ok(n) => n,
            Err(e) => {
                unsafe { krb5_free_cred_contents(ctx.0, &mut creds) };
                return Err(PwChangeError::Krb(e));
            }
        };
        let mut code: c_int = 0;
        let mut code_string = KrbData { magic: 0, length: 0, data: ptr::null_mut() };
        let mut result_string = KrbData { magic: 0, length: 0, data: ptr::null_mut() };
        let rc = unsafe {
            krb5_change_password(
                ctx.0,
                &mut creds,
                new.as_ptr() as *const c_char,
                &mut code,
                &mut code_string,
                &mut result_string,
            )
        };
        let text = data_text(&result_string);
        unsafe {
            krb5_free_data_contents(ctx.0, &mut code_string);
            krb5_free_data_contents(ctx.0, &mut result_string);
            krb5_free_cred_contents(ctx.0, &mut creds);
        }
        if rc != 0 {
            return Err(PwChangeError::Krb(ctx.err(rc, "kpasswd")));
        }
        match code {
            KRB5_KPASSWD_SUCCESS => Ok(()),
            // IPA reports policy violations as soft errors with its policy text.
            KRB5_KPASSWD_SOFTERROR => Err(PwChangeError::Rejected(PwReject::from_ipa_text(&text))),
            KRB5_KPASSWD_AUTHERROR | KRB5_KPASSWD_ACCESSDENIED => {
                Err(PwChangeError::Krb(KrbError::Denied(format!("kpasswd result {code}: {text}"))))
            }
            _ => Err(PwChangeError::Krb(KrbError::Unavailable(format!("kpasswd result {code}: {text}")))),
        }
    }
}

#[cfg(test)]
mod unavailable_tests {
    use super::*;

    #[test]
    fn locating_the_kdc_or_kpasswd_server_is_not_a_credential_failure() {
        assert!(is_unavailable(KRB5_KDC_UNREACH));
        assert!(is_unavailable(KRB5_REALM_CANT_RESOLVE));
        assert!(is_unavailable(KRB5_REALM_UNKNOWN));
        // KRB5KDC_ERR_PREAUTH_FAILED: a wrong password stays a denial.
        assert!(!is_unavailable(-1765328360));
    }
}
