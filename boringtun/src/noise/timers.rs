// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use crate::amnezia::{OsRandom, RandomSource, TimingRanges};
use crate::noise::{Tunn, TunnResult};
use std::mem;
use std::ops::{Index, IndexMut};

use std::time::Duration;

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
// These double as the fallbacks for unset AWG 3.0 timing ranges.
const REKEY_AFTER_TIME_SECS: u32 = 120;
const REJECT_AFTER_TIME_SECS: u32 = 180;
const REKEY_TIMEOUT_SECS: u32 = 5;
const KEEPALIVE_TIMEOUT_SECS: u32 = 10;
const MAX_TIMER_HANDSHAKES: u32 = 18;

#[allow(dead_code)] // used by the mock-instant test suite
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(REKEY_AFTER_TIME_SECS as u64);
#[allow(dead_code)] // superseded by Timers::reject_after_time, kept for tests
const REJECT_AFTER_TIME: Duration = Duration::from_secs(REJECT_AFTER_TIME_SECS as u64);
/// The classic 90 s give-up deadline is exactly the default retransmit timeout
/// times the default attempt budget, which is how AWG 3.0 generalizes it.
const REKEY_ATTEMPT_TIME: Duration =
    Duration::from_secs((REKEY_TIMEOUT_SECS * MAX_TIMER_HANDSHAKES) as u64);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(REKEY_TIMEOUT_SECS as u64);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum TimerName {
    /// Current time, updated each call to `update_timers`
    TimeCurrent,
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last received a cookie
    TimeCookieReceived,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    /// Start time of the tunnel
    time_started: Instant,
    timers: [Duration; TimerName::Top as usize],
    pub(super) session_timers: [Duration; super::N_SESSIONS],
    /// Did we receive data without sending anything back?
    want_keepalive: bool,
    /// Did we send data without hearing back?
    want_handshake: bool,
    persistent_keepalive: usize,
    /// AWG 3.0 randomized timing ranges. An all-zero range falls back to the
    /// classic WireGuard constant, so a default `TimingRanges` preserves stock
    /// behavior exactly.
    timing_ranges: TimingRanges,
    /// AWG 3.0: retransmit timeout picked for the in-flight handshake
    rekey_timeout_current: Duration,
    /// AWG 3.0: give-up deadline picked for the in-flight handshake
    rekey_attempt_deadline: Duration,
    /// AWG 3.0: current persistent-keepalive interval, re-picked on every fire
    persistent_keepalive_next: Duration,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: bool,
}

impl Timers {
    pub(super) fn new(
        persistent_keepalive: Option<u16>,
        reset_rr: bool,
        timing_ranges: TimingRanges,
    ) -> Timers {
        Timers {
            is_initiator: false,
            time_started: Instant::now(),
            timers: Default::default(),
            session_timers: Default::default(),
            want_keepalive: Default::default(),
            want_handshake: Default::default(),
            persistent_keepalive: usize::from(persistent_keepalive.unwrap_or(0)),
            timing_ranges,
            rekey_timeout_current: REKEY_TIMEOUT,
            rekey_attempt_deadline: REKEY_ATTEMPT_TIME,
            persistent_keepalive_next: Duration::from_secs(u64::from(
                timing_ranges.persistent_keepalive.pick_or(&mut OsRandom, 0),
            )),
            should_reset_rr: reset_rr,
        }
    }

    /// AWG 3.0: pick fresh handshake timings. The retransmit timeout is
    /// re-picked for every initiation, including retries, mirroring
    /// amneziawg-go's `timersHandshakeInitiated`. The attempt budget is picked
    /// once per handshake (`SendHandshakeInitiation` only re-rolls
    /// `maxHandshakeAttempts` when `!isRetry`) and is expressed here as a
    /// deadline, since boringtun bounds retries by time rather than by count —
    /// with default ranges `5 s * 18` is exactly `REKEY_ATTEMPT_TIME`.
    ///
    /// With all-zero ranges this yields the classic WireGuard constants.
    pub(super) fn roll_handshake_timings(
        &mut self,
        rng: &mut dyn RandomSource,
        starting_new_handshake: bool,
    ) {
        let rekey_timeout = self
            .timing_ranges
            .rekey_timeout
            .pick_or(rng, REKEY_TIMEOUT_SECS);
        self.rekey_timeout_current = Duration::from_secs(u64::from(rekey_timeout));

        if starting_new_handshake {
            let max_attempts = self
                .timing_ranges
                .max_handshake_attempts
                .pick_or(rng, MAX_TIMER_HANDSHAKES);
            self.rekey_attempt_deadline =
                Duration::from_secs(u64::from(rekey_timeout) * u64::from(max_attempts));
        }
    }

    /// AWG 3.0: keypair expiry, `Hi` of the reject-after range
    /// (`keychainExpireTime`).
    fn reject_after_time(&self) -> Duration {
        Duration::from_secs(u64::from(
            self.timing_ranges
                .reject_after_time
                .hi_or(REJECT_AFTER_TIME_SECS),
        ))
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self) {
        let now = Instant::now().duration_since(self.time_started);
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.want_handshake = false;
        self.want_keepalive = false;
    }
}

impl Index<TimerName> for Timers {
    type Output = Duration;
    fn index(&self, index: TimerName) -> &Duration {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Duration {
        &mut self.timers[index as usize]
    }
}

impl Tunn {
    pub(super) fn timer_tick(&mut self, timer_name: TimerName) {
        match timer_name {
            TimeLastPacketReceived => {
                self.timers.want_keepalive = true;
                self.timers.want_handshake = false;
            }
            TimeLastPacketSent => {
                self.timers.want_handshake = true;
                self.timers.want_keepalive = false;
            }
            _ => {}
        }

        let time = self.timers[TimeCurrent];
        self.timers[timer_name] = time;
    }

    pub(super) fn timer_tick_session_established(
        &mut self,
        is_initiator: bool,
        session_idx: usize,
    ) {
        self.timer_tick(TimeSessionEstablished);
        self.timers.session_timers[session_idx % crate::noise::N_SESSIONS] =
            self.timers[TimeCurrent];
        self.timers.is_initiator = is_initiator;
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&mut self) {
        for session in &mut self.sessions {
            *session = None;
        }

        self.packet_queue.clear();
        self.network_outgoing.clear();

        self.timers.clear();
    }

    fn update_session_timers(&mut self, time_now: Duration) {
        let timers = &mut self.timers;
        let reject_after_time = timers.reject_after_time();

        for (i, t) in timers.session_timers.iter_mut().enumerate() {
            if time_now - *t > reject_after_time {
                if let Some(session) = self.sessions[i].take() {
                    tracing::debug!(
                        message = "SESSION_EXPIRED(REJECT_AFTER_TIME)",
                        session = session.receiving_index
                    );
                }
                *t = time_now;
            }
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        let time = Instant::now();

        if self.timers.should_reset_rr {
            self.rate_limiter.reset_count();
        }

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, as there is no real benefit to having highly accurate timers.
        let now = time.duration_since(self.timers.time_started);
        self.timers[TimeCurrent] = now;

        self.update_session_timers(now);

        // Load timers only once:
        let session_established = self.timers[TimeSessionEstablished];
        let handshake_started = self.timers[TimeLastHandshakeStarted];
        let aut_packet_received = self.timers[TimeLastPacketReceived];
        let aut_packet_sent = self.timers[TimeLastPacketSent];
        let data_packet_received = self.timers[TimeLastDataPacketReceived];
        let data_packet_sent = self.timers[TimeLastDataPacketSent];
        let persistent_keepalive = self.timers.persistent_keepalive;
        let reject_after_time = self.timers.reject_after_time();

        {
            if self.handshake.is_expired() {
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            // Clear cookie after COOKIE_EXPIRATION_TIME
            if self.handshake.has_cookie()
                && now - self.timers[TimeCookieReceived] >= COOKIE_EXPIRATION_TIME
            {
                self.handshake.clear_cookie();
            }

            // All ephemeral private keys and symmetric session keys are zeroed out after
            // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
            if now - session_established >= reject_after_time * 3 {
                tracing::error!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
                self.handshake.set_expired();
                self.clear_all();
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if let Some(time_init_sent) = self.handshake.timer() {
                // Handshake Initiation Retransmission
                if now - handshake_started >= self.timers.rekey_attempt_deadline {
                    // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                    // the retries give up and cease, and clear all existing packets queued
                    // up to be sent. If a packet is explicitly queued up to be sent, then
                    // this timer is reset.
                    tracing::error!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                    self.handshake.set_expired();
                    self.clear_all();
                    return TunnResult::Err(WireGuardError::ConnectionExpired);
                }

                if time_init_sent.elapsed() >= self.timers.rekey_timeout_current {
                    // We avoid using `time` here, because it can be earlier than `time_init_sent`.
                    // Once `checked_duration_since` is stable we can use that.
                    // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                    // if a response has not been received, where jitter is some random
                    // value between 0 and 333 ms.
                    tracing::warn!("HANDSHAKE(REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }
            } else {
                if self.timers.is_initiator() {
                    // After sending a packet, if the sender was the original initiator
                    // of the handshake and if the current session key is REKEY_AFTER_TIME
                    // ms old, we initiate a new handshake. If the sender was the original
                    // responder of the handshake, it does not re-initiate a new handshake
                    // after REKEY_AFTER_TIME ms like the original initiator does.
                    // AWG 3.0: `keyRefreshTimeoutSending` — a fresh pick per check
                    let rekey_after_time = Duration::from_secs(u64::from(
                        self.timers
                            .timing_ranges
                            .rekey_after_time
                            .pick_or(&mut OsRandom, REKEY_AFTER_TIME_SECS),
                    ));
                    if session_established < data_packet_sent
                        && now - session_established >= rekey_after_time
                    {
                        tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                        handshake_initiation_required = true;
                    }

                    // After receiving a packet, if the receiver was the original initiator
                    // of the handshake and if the current session key is REJECT_AFTER_TIME
                    // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
                    // handshake.
                    // AWG 3.0: `keyRefreshTimeoutReceiving` — a fresh pick of the
                    // reject-after range, less the `Lo` of the two margins
                    let receiver_rekey_after = {
                        let ranges = &self.timers.timing_ranges;
                        let reject = ranges
                            .reject_after_time
                            .pick_or(&mut OsRandom, REJECT_AFTER_TIME_SECS);
                        let margin = ranges.keepalive_timeout.lo_or(KEEPALIVE_TIMEOUT_SECS)
                            + ranges.rekey_timeout.lo_or(REKEY_TIMEOUT_SECS);
                        Duration::from_secs(u64::from(reject.saturating_sub(margin)))
                    };
                    if session_established < data_packet_received
                        && now - session_established >= receiver_rekey_after
                    {
                        tracing::warn!(
                            "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - \
                        REKEY_TIMEOUT \
                        (on receive))"
                        );
                        handshake_initiation_required = true;
                    }
                }

                // If we have sent a packet to a given peer but have not received a
                // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
                // we initiate a new handshake.
                // AWG 3.0: `newHandshakeTimeout` — `Hi` of the keepalive range
                // plus a fresh pick of the rekey range
                let new_handshake_after = {
                    let ranges = &self.timers.timing_ranges;
                    Duration::from_secs(u64::from(
                        ranges.keepalive_timeout.hi_or(KEEPALIVE_TIMEOUT_SECS)
                            + ranges.rekey_timeout.pick_or(&mut OsRandom, REKEY_TIMEOUT_SECS),
                    ))
                };
                if data_packet_sent > aut_packet_received
                    && now - aut_packet_received >= new_handshake_after
                    && mem::replace(&mut self.timers.want_handshake, false)
                {
                    tracing::warn!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }

                if !handshake_initiation_required {
                    // If a packet has been received from a given peer, but we have not sent one back
                    // to the given peer in KEEPALIVE ms, we send an empty packet.
                    // AWG 3.0: `sendKeepaliveTimeout` — a fresh pick per check
                    let keepalive_timeout = Duration::from_secs(u64::from(
                        self.timers
                            .timing_ranges
                            .keepalive_timeout
                            .pick_or(&mut OsRandom, KEEPALIVE_TIMEOUT_SECS),
                    ));
                    if data_packet_received > aut_packet_sent
                        && now - aut_packet_sent >= keepalive_timeout
                        && mem::replace(&mut self.timers.want_keepalive, false)
                    {
                        tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                        keepalive_required = true;
                    }

                    // Persistent KEEPALIVE: a fixed interval, or an AWG 3.0
                    // range re-picked on every fire
                    // (`timersAnyAuthenticatedPacketTraversal`).
                    let keepalive_range = self.timers.timing_ranges.persistent_keepalive;
                    if !keepalive_range.is_zero() {
                        if now - self.timers[TimePersistentKeepalive]
                            >= self.timers.persistent_keepalive_next
                        {
                            self.timers.persistent_keepalive_next = Duration::from_secs(u64::from(
                                keepalive_range.generate(&mut OsRandom),
                            ));
                            tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                            self.timer_tick(TimePersistentKeepalive);
                            keepalive_required = true;
                        }
                    } else if persistent_keepalive > 0
                        && (now - self.timers[TimePersistentKeepalive]
                            >= Duration::from_secs(persistent_keepalive as _))
                    {
                        tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                        self.timer_tick(TimePersistentKeepalive);
                        keepalive_required = true;
                    }
                }
            }
        }

        if handshake_initiation_required {
            return self.format_handshake_initiation(dst, true);
        }

        if keepalive_required {
            return self.encapsulate(&[], dst);
        }

        TunnResult::Done
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let current_session = self.current;
        if self.sessions[current_session % super::N_SESSIONS].is_some() {
            let duration_since_tun_start = Instant::now().duration_since(self.timers.time_started);
            let duration_since_session_established = self.timers[TimeSessionEstablished];

            Some(duration_since_tun_start - duration_since_session_established)
        } else {
            None
        }
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        let keepalive = self.timers.persistent_keepalive;

        if keepalive > 0 {
            Some(keepalive as u16)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amnezia::U32Range;

    /// Deterministic byte source, so range picks are reproducible.
    struct SeqRng {
        counter: u8,
    }

    impl SeqRng {
        fn new(seed: u8) -> Self {
            SeqRng { counter: seed }
        }
    }

    impl RandomSource for SeqRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out.iter_mut() {
                *byte = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
        }
    }

    #[test]
    fn roll_handshake_timings_defaults_to_wg_constants() {
        let mut timers = Timers::new(None, false, TimingRanges::default());
        let mut rng = SeqRng::new(0xAA);
        timers.roll_handshake_timings(&mut rng, true);
        assert_eq!(timers.rekey_timeout_current, REKEY_TIMEOUT);
        assert_eq!(timers.rekey_attempt_deadline, REKEY_ATTEMPT_TIME);
    }

    #[test]
    fn roll_handshake_timings_uses_ranges() {
        let ranges = TimingRanges {
            rekey_timeout: U32Range::single(7),
            max_handshake_attempts: U32Range::single(3),
            ..TimingRanges::default()
        };
        let mut timers = Timers::new(None, false, ranges);
        let mut rng = SeqRng::new(0xAA);
        timers.roll_handshake_timings(&mut rng, true);
        assert_eq!(timers.rekey_timeout_current, Duration::from_secs(7));
        assert_eq!(timers.rekey_attempt_deadline, Duration::from_secs(21));
    }

    #[test]
    fn retry_rerolls_the_timeout_but_keeps_the_deadline() {
        let ranges = TimingRanges {
            rekey_timeout: U32Range::new(3, 9).expect("valid range"),
            max_handshake_attempts: U32Range::single(4),
            ..TimingRanges::default()
        };
        let mut timers = Timers::new(None, false, ranges);
        let mut rng = SeqRng::new(1);
        timers.roll_handshake_timings(&mut rng, true);
        let deadline = timers.rekey_attempt_deadline;

        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            timers.roll_handshake_timings(&mut rng, false);
            let secs = timers.rekey_timeout_current.as_secs();
            assert!((3..=9).contains(&secs), "timeout {} out of range", secs);
            seen.insert(secs);
            assert_eq!(timers.rekey_attempt_deadline, deadline);
        }
        assert!(seen.len() > 1, "retransmit timeout should vary per retry");
    }

    #[test]
    fn reject_after_time_uses_range_upper_bound() {
        let timers = Timers::new(None, false, TimingRanges::default());
        assert_eq!(timers.reject_after_time(), REJECT_AFTER_TIME);

        let ranges = TimingRanges {
            reject_after_time: U32Range::new(100, 200).expect("valid range"),
            ..TimingRanges::default()
        };
        let timers = Timers::new(None, false, ranges);
        assert_eq!(timers.reject_after_time(), Duration::from_secs(200));
    }

    #[test]
    fn persistent_keepalive_range_seeds_the_first_interval() {
        let ranges = TimingRanges {
            persistent_keepalive: U32Range::new(20, 30).expect("valid range"),
            ..TimingRanges::default()
        };
        let timers = Timers::new(None, false, ranges);
        let secs = timers.persistent_keepalive_next.as_secs();
        assert!((20..=30).contains(&secs), "interval {} out of range", secs);

        // Without a range the interval stays at the fixed scalar path.
        let timers = Timers::new(Some(25), false, TimingRanges::default());
        assert_eq!(timers.persistent_keepalive_next, Duration::ZERO);
        assert_eq!(timers.persistent_keepalive, 25);
    }
}
