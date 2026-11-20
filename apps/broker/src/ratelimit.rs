//! Broker-side brute-force limits, applied before anything reaches the KDC so
//! internet noise never trips the directory's account lockout:
//!
//! * `auth/start`: at most N per minute per client IP.
//! * failed `auth/respond`: after N failures per (user, IP) that pair is blocked;
//!   after M failures per IP the whole IP is blocked; both for `block_secs`.
//! * per-user attempts from ANY address (`failures_per_user` = N, 0 = off). This models the
//!   directory's own counter: Active Directory's `badPwdCount` resets only after a quiet
//!   period W since the LAST failure, so failures chain. Per user the limiter keeps
//!   `(count, last)`: the attempt is counted *before* the KDC is asked and stamped again
//!   when it answered; the count resets only when `now - last >= W + margin`; once
//!   `count >= N` the user is refused until `last + W + margin`. Wrong passwords reaching the
//!   directory therefore never exceed N per quiet period, whatever the spacing. One attempt
//!   per user is in flight at a time. Right passwords and infrastructure errors are refunded;
//!   unknown principals are never tracked.
//! * global failures per minute above a threshold are reported (audit burst).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::Limits;

const MINUTE: Duration = Duration::from_secs(60);
/// Soft bound of per-user counters kept; beyond it already-reset entries are evicted first.
const MAX_TRACKED_USERS: usize = 50_000;

/// Directory-side failure count of one user.
struct UserCount {
    count: u32,
    last: Instant,
}

/// A reserved per-user attempt (see [`RateLimiter::begin_attempt`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Attempt {
    /// `last` before this attempt, restored on a refund.
    prev_last: Option<Instant>,
}

#[derive(Default)]
struct Window(VecDeque<Instant>);

impl Window {
    fn prune(&mut self, now: Instant, span: Duration) {
        while let Some(f) = self.0.front() {
            if now.duration_since(*f) >= span {
                self.0.pop_front();
            } else {
                break;
            }
        }
    }
}

pub struct RateLimiter {
    starts_per_min: u32,
    fail_user_ip: u32,
    fail_ip: u32,
    fail_user: u32,
    /// Quiet period after which the directory's counter is back to 0 (W + margin).
    user_reset: Duration,
    block: Duration,
    burst: u32,
    starts: HashMap<IpAddr, Window>,
    fails_user_ip: HashMap<(String, IpAddr), Window>,
    fails_ip: HashMap<IpAddr, Window>,
    users: HashMap<String, UserCount>,
    inflight: HashSet<String>,
    blocked: HashMap<(Option<String>, IpAddr), Instant>,
    global: Window,
    burst_reported_at: Option<Instant>,
}

impl RateLimiter {
    pub fn new(l: &Limits) -> RateLimiter {
        RateLimiter {
            starts_per_min: l.starts_per_minute_per_ip,
            fail_user_ip: l.failures_per_user_ip,
            fail_ip: l.failures_per_ip,
            fail_user: l.failures_per_user,
            user_reset: Duration::from_secs(l.user_window_secs),
            block: Duration::from_secs(l.block_secs),
            burst: l.global_failure_burst_per_minute,
            starts: HashMap::new(),
            fails_user_ip: HashMap::new(),
            fails_ip: HashMap::new(),
            users: HashMap::new(),
            inflight: HashSet::new(),
            blocked: HashMap::new(),
            global: Window::default(),
            burst_reported_at: None,
        }
    }

    /// The directory's quiet period (lockout observation window plus a safety margin) after
    /// which a user's counter is considered reset. Default: `limits.user_window_secs`.
    pub fn with_user_reset(mut self, reset: Duration) -> RateLimiter {
        self.user_reset = reset;
        self
    }

    /// Seconds until `(user, ip)` or `ip` may try again, if blocked. The per-user rule
    /// (`failures_per_user`) is deliberately NOT part of this: it must not be visible as a
    /// 429 (that would tell real from unknown names); it answers like a wrong password.
    pub fn blocked(&mut self, user: Option<&str>, ip: IpAddr, now: Instant) -> Option<u64> {
        let mut worst: Option<u64> = None;
        for key in [(None, ip), (user.map(str::to_string), ip)] {
            if let Some(until) = self.blocked.get(&key).copied() {
                if until > now {
                    let s = until.duration_since(now).as_secs().max(1);
                    worst = Some(worst.map_or(s, |w| w.max(s)));
                } else {
                    self.blocked.remove(&key);
                }
            }
        }
        worst
    }

    /// Count an `auth/start`; returns `Err(retry_after)` when over the limit.
    pub fn start(&mut self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let w = self.starts.entry(ip).or_default();
        w.prune(now, MINUTE);
        if w.0.len() as u32 >= self.starts_per_min {
            let oldest = *w.0.front().unwrap();
            return Err((MINUTE - now.duration_since(oldest)).as_secs().max(1));
        }
        w.0.push_back(now);
        Ok(())
    }

    /// Record a failed respond. Returns true when a global burst should be reported.
    pub fn failure(&mut self, user: &str, ip: IpAddr, now: Instant) -> bool {
        let span = self.block;
        let w = self.fails_user_ip.entry((user.to_string(), ip)).or_default();
        w.prune(now, span);
        w.0.push_back(now);
        if w.0.len() as u32 >= self.fail_user_ip {
            self.blocked.insert((Some(user.to_string()), ip), now + self.block);
            w.0.clear();
        }
        let w = self.fails_ip.entry(ip).or_default();
        w.prune(now, span);
        w.0.push_back(now);
        if w.0.len() as u32 >= self.fail_ip {
            self.blocked.insert((None, ip), now + self.block);
            w.0.clear();
        }
        self.global.prune(now, MINUTE);
        self.global.0.push_back(now);
        if self.global.0.len() as u32 >= self.burst {
            let due = self.burst_reported_at.is_none_or(|t| now.duration_since(t) >= MINUTE);
            if due {
                self.burst_reported_at = Some(now);
                return true;
            }
        }
        false
    }

    /// A success clears the (user, IP) failure count.
    pub fn success(&mut self, user: &str, ip: IpAddr) {
        self.fails_user_ip.remove(&(user.to_string(), ip));
    }

    /// Seconds until `user` may try again when N counted failures are still fresh.
    pub fn user_blocked_secs(&self, user: &str, now: Instant) -> Option<u64> {
        if self.fail_user == 0 {
            return None;
        }
        let u = self.users.get(user)?;
        let until = u.last + self.user_reset;
        (u.count >= self.fail_user && until > now).then(|| until.duration_since(now).as_secs().max(1))
    }

    /// Reserve one KDC attempt for `user` (any address). `Err(retry_after)` when the user has
    /// used its N attempts in the current quiet period or another attempt is in flight.
    /// Pair with [`RateLimiter::end_attempt`]. `Ok(None)` (nothing to end) when
    /// `failures_per_user` is 0.
    pub fn begin_attempt(&mut self, user: &str, now: Instant) -> Result<Option<Attempt>, u64> {
        if self.fail_user == 0 {
            return Ok(None);
        }
        if let Some(s) = self.user_blocked_secs(user, now) {
            return Err(s);
        }
        if self.inflight.contains(user) {
            return Err(1);
        }
        if !self.users.contains_key(user) && self.users.len() >= MAX_TRACKED_USERS {
            self.evict(now);
        }
        let reset = self.user_reset;
        let u = self.users.entry(user.to_string()).or_insert(UserCount { count: 0, last: now });
        if u.count > 0 && now.duration_since(u.last) >= reset {
            u.count = 0; // the directory's counter has reset
        }
        let prev_last = (u.count > 0).then_some(u.last);
        u.count += 1;
        u.last = now;
        self.inflight.insert(user.to_string());
        Ok(Some(Attempt { prev_last }))
    }

    /// Finish an attempt. `counted = false` refunds it (right password, unknown principal, or
    /// the KDC could not answer). A counted attempt is stamped with `now`, when the KDC
    /// answered, so a slow KDC cannot make the quiet period start too early.
    pub fn end_attempt(&mut self, user: &str, attempt: Option<Attempt>, counted: bool, now: Instant) {
        let Some(a) = attempt else { return };
        self.inflight.remove(user);
        let Some(u) = self.users.get_mut(user) else { return };
        if counted {
            u.last = u.last.max(now);
            return;
        }
        u.count = u.count.saturating_sub(1);
        match a.prev_last {
            Some(p) if u.count > 0 => u.last = p,
            _ => {
                self.users.remove(user);
            }
        }
    }

    /// Make room: drop counters that are already reset; failing that the oldest idle one.
    /// A new user is never refused because the table is full.
    fn evict(&mut self, now: Instant) {
        let reset = self.user_reset;
        let inflight = &self.inflight;
        self.users.retain(|k, u| inflight.contains(k) || now.duration_since(u.last) < reset);
        if self.users.len() >= MAX_TRACKED_USERS {
            let oldest = self
                .users
                .iter()
                .filter(|(k, u)| !inflight.contains(*k) && u.count < self.fail_user)
                .min_by_key(|(_, u)| u.last)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.users.remove(&k);
            }
        }
    }

    /// Drop stale bookkeeping (called by the reaper).
    pub fn gc(&mut self, now: Instant) {
        let span = self.block.max(MINUTE);
        self.starts.retain(|_, w| {
            w.prune(now, MINUTE);
            !w.0.is_empty()
        });
        self.fails_user_ip.retain(|_, w| {
            w.prune(now, span);
            !w.0.is_empty()
        });
        self.fails_ip.retain(|_, w| {
            w.prune(now, span);
            !w.0.is_empty()
        });
        let (reset, inflight) = (self.user_reset, &self.inflight);
        self.users.retain(|k, u| inflight.contains(k) || now.duration_since(u.last) < reset);
        self.blocked.retain(|_, until| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl() -> RateLimiter {
        RateLimiter::new(&Limits::default())
    }
    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));
    const IP2: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));

    #[test]
    fn five_starts_per_minute() {
        let mut r = rl();
        let t = Instant::now();
        for _ in 0..5 {
            r.start(IP, t).unwrap();
        }
        let retry = r.start(IP, t + Duration::from_secs(10)).unwrap_err();
        assert_eq!(retry, 50);
        assert!(r.start(IP2, t).is_ok());
        assert!(r.start(IP, t + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn three_failures_block_user_ip_for_15_min() {
        let mut r = rl();
        let t = Instant::now();
        r.failure("anna", IP, t);
        r.failure("anna", IP, t);
        assert_eq!(r.blocked(Some("anna"), IP, t), None);
        r.failure("anna", IP, t);
        assert_eq!(r.blocked(Some("anna"), IP, t), Some(900));
        assert_eq!(r.blocked(Some("anna"), IP2, t), None);
        assert_eq!(r.blocked(Some("bob"), IP, t), None);
        assert_eq!(r.blocked(Some("anna"), IP, t + Duration::from_secs(900)), None);
    }

    fn user_rl(n: u32, reset: u64) -> RateLimiter {
        RateLimiter::new(&Limits { failures_per_user: n, ..Limits::default() })
            .with_user_reset(Duration::from_secs(reset))
    }

    #[test]
    fn disabled_unless_failures_per_user_is_set() {
        let t = Instant::now();
        let mut r = rl();
        for _ in 0..20 {
            assert!(r.begin_attempt("anna", t).unwrap().is_none());
        }
        assert_eq!(r.user_blocked_secs("anna", t), None);
    }

    #[test]
    fn spaced_failures_cannot_chain_past_n() {
        // N = 3, AD window 1800 + margin 60. Failures 901 s apart used to slip through a
        // sliding window while AD's counter kept chaining up to its lockout.
        let t = Instant::now();
        let at = |s: u64| t + Duration::from_secs(s);
        let mut r = user_rl(3, 1860);
        for s in [0u64, 901, 1802] {
            let a = r.begin_attempt("anna", at(s)).unwrap();
            r.end_attempt("anna", a, true, at(s));
        }
        assert!(r.begin_attempt("anna", at(2703)).is_err(), "the 4th is refused");
        assert!(r.begin_attempt("anna", at(3661)).is_err(), "still within W+margin of the last failure");
        assert_eq!(r.user_blocked_secs("anna", at(2703)), Some(959), "1802 + 1860 - 2703");
        // Only after a quiet W+margin since the LAST failure is the counter back to 0.
        assert!(r.begin_attempt("anna", at(1802 + 1859)).is_err());
        assert!(r.begin_attempt("anna", at(1802 + 1860)).is_ok());
    }

    #[test]
    fn slow_kdc_answer_moves_the_quiet_period_forward() {
        let t = Instant::now();
        let mut r = user_rl(1, 100);
        let a = r.begin_attempt("anna", t).unwrap();
        r.end_attempt("anna", a, true, t + Duration::from_secs(30));
        assert!(r.begin_attempt("anna", t + Duration::from_secs(129)).is_err());
        assert!(r.begin_attempt("anna", t + Duration::from_secs(130)).is_ok());
    }

    #[test]
    fn one_attempt_in_flight_and_users_are_independent() {
        let t = Instant::now();
        let mut r = user_rl(3, 100);
        let a = r.begin_attempt("anna", t).unwrap();
        assert_eq!(r.begin_attempt("anna", t), Err(1));
        assert!(r.begin_attempt("bob", t).is_ok());
        r.end_attempt("anna", a, true, t);
        assert!(r.begin_attempt("anna", t).is_ok());
    }

    #[test]
    fn refunds_restore_the_previous_state() {
        let t = Instant::now();
        let at = |s: u64| t + Duration::from_secs(s);
        let mut r = user_rl(2, 100);
        for i in 0..10 {
            let a = r.begin_attempt("anna", at(i)).unwrap();
            r.end_attempt("anna", a, false, at(i));
        }
        assert_eq!(r.users.len(), 0, "refunded (unknown principal, success, outage) leaves nothing tracked");
        let a = r.begin_attempt("anna", at(0)).unwrap();
        r.end_attempt("anna", a, true, at(0));
        let a = r.begin_attempt("anna", at(50)).unwrap();
        r.end_attempt("anna", a, false, at(50));
        // The refund restored `last` = 0, so the counter resets at 100, not 150.
        let a = r.begin_attempt("anna", at(100)).unwrap();
        assert_eq!(r.users["anna"].count, 1, "reset happened at 100");
        r.end_attempt("anna", a, true, at(100));
    }

    #[test]
    fn a_full_table_never_refuses_a_user() {
        let t = Instant::now();
        let mut r = user_rl(3, 100);
        for i in 0..MAX_TRACKED_USERS {
            r.users.insert(format!("u{i}"), UserCount { count: 1, last: t + Duration::from_secs(i as u64 % 50) });
        }
        // Everything is fresh: the oldest idle entry makes room.
        let a = r.begin_attempt("newcomer", t + Duration::from_secs(60)).unwrap();
        assert!(a.is_some());
        assert!(r.users.len() <= MAX_TRACKED_USERS);
        // Everything is stale: they are all dropped.
        r.end_attempt("newcomer", a, true, t + Duration::from_secs(60));
        assert!(r.begin_attempt("another", t + Duration::from_secs(10_000)).is_ok());
        assert_eq!(r.users.len(), 1, "stale entries evicted");
    }

    #[test]
    fn many_users_from_one_ip_block_the_ip() {
        let mut r = rl();
        let t = Instant::now();
        for i in 0..10 {
            r.failure(&format!("u{i}"), IP, t);
        }
        assert!(r.blocked(Some("zed"), IP, t).is_some());
        assert!(r.blocked(None, IP2, t).is_none());
    }

    #[test]
    fn burst_reported_once_per_minute() {
        let mut r = rl();
        let t = Instant::now();
        let mut reports = 0;
        for i in 0..40u8 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, i));
            if r.failure("x", ip, t) {
                reports += 1;
            }
        }
        assert_eq!(reports, 1);
    }
}
