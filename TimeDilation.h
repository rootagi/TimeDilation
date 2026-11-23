#ifndef __TIMEDILATION_H
#define __TIMEDILATION_H

#if !defined(__bpf__) && !defined(__KERNEL__)
#include <linux/types.h>
#include <stdbool.h>
#endif

/*
 * TimeDilation - adversarial sched_ext tooling for deterministic
 * TOCTOU / UAF race amplification.
 *
 * Built on the adversarial scheduling research in this repository
 * (scx_starve):
 *
 *  - .select_cpu pins armed race threads to their dedicated per-CPU lanes.
 *  - .enqueue dispatches race threads into the lane with a finite slice
 *    (the per-thread override, the trigger slice, or the 5 ms default;
 *    see td_threads).
 *  - .dispatch on an armed lane consumes only the lane queue: every
 *    other task on the lane CPU starves, so the racing threads run in
 *    hardware lockstep. Per-CPU SLUB locality is preserved by
 *    construction: no other task runs on the lane core.
 *  - While a lane is armed or held (hold_k), kworkers (PF_KTHREAD)
 *    are routed into TD_DSQ_KPARKED and only released onto a lane
 *    when a lane is resumed (release_k).
 *
 * Upgrades (bolt-on layer):
 *  U1 - nanosecond auto-trigger: kprobes on vulnerable kernel
 *       functions (io_uring cancel path, af_unix garbage collector,
 *       the TCP SYN-ACK receive path) flip release_k on the
 *       arming thread's core inside the kernel with no userspace
 *       round-trips.
 *  U2 - drop-in userfaultfd replacement: while a lane is armed and
 *       release_k is set, the victim thread gets a finite slice
 *       (TD_TRIGGER_SLICE_NS) so it is preemptible at tick expiry
 *       and any cond_resched/mutex point; the spray threads on the
 *       lane run in lockstep without page faults.
 *  U3 - surgical kworker filtering: PF_KTHREAD parking now consults
 *       the comm filter (td_park_targets) via BPF_CORE_READ_STR_INTO;
 *       parked tasks trickle out at one per 4000ms via the
 *       td_kparked_hb heartbeat so .timeout_ms never ejects.
 *  U4 - scx_starve fusion + cgroup isolation: DSQ_STARVE targets
 *       (e.g. alerting daemons) run on the starve DSQ, and tasks in
 *       td_frozen_cgs are parked in TD_DSQ_FROZEN (never dispatched).
 */

#define TD_MAX_CORES    8
#define TD_MAX_THREADS  64
#define TD_COMM_LEN     16

/*
 * U1 trigger table.  This is the single place where probe targets are
 * listed: the BPF object expands each entry into a kprobe program, and
 * the userspace loader expands the same list into its attach table.
 * Add or remove a line here to change the set of watched functions.
 */
#define TD_TRIGGER_LIST(X)              \
    X(unix_gc)                          \
    X(unix_release_sock)                \
    X(io_uring_try_cancel_requests)     \
    X(tcp_v4_syn_recv_sock)

/* Lane DSQs: 100..100+TD_MAX_CORES-1; control queues: 900+. */
#define TD_DSQ_ID(i)    (100ULL + (i))
#define TD_DSQ_NORMAL   900ULL
#define TD_DSQ_KPARKED  901ULL
#define TD_DSQ_FROZEN   902ULL   /* U4: cgroup-frozen tasks */
/* U3: per-CPU keepalive queues for unmatched kthreads. */
#define TD_DSQ_KOTHER(i) (910ULL + (i))

/* U4: starve DSQs, kept identical to scx_starve.h so the fused
 * scheduler is wire-compatible with scx_starve's userspace. */
#define TD_DSQ_STARVE   2001ULL

/* Default slice for normal-queue tasks (5ms, as in scx_starve). */
#define TD_SLICE_DEFAULT_NS   (5ULL * 1000 * 1000)

/* U1/U2: finite slice applied to a thread when the auto-trigger
 * freezes it (tick-expiry preemption). */
#define TD_TRIGGER_SLICE_NS      (50ULL * 1000)

/* U3: heartbeat constants (period stays under .timeout_ms=5000). */
#define TD_HB_PERIOD_NS   (4000ULL * 1000 * 1000) /* 4 s between trickles */
#define TD_HB_SLICE_NS    (10ULL * 1000)          /* 10 µs trickle slice */
#define TD_HB_WINDOW_NS   (20ULL * 1000 * 1000)   /* 20 ms > 5ms lane slice */
#define TD_MAX_TRICKLE_SCANS  4
#define TD_MAX_PARK_TARGETS   8

/* U4: cap on frozen cgroup ids. */
#define TD_MAX_FROZEN_CGS  16

struct td_thread {
    __u32 core;         /* lane this thread is pinned to */
    __u32 slice_ns;     /* lane slice; 0 = default 5ms lane slice */
};

struct td_core {
    __u64 lane_dsq;     /* DSQ id of this race lane */
    __u32 armed;        /* 1 = lane active: only lane tasks run here */
    __u32 hold_k;       /* 1 = park kworkers into TD_DSQ_KPARKED */
    __u32 release_k;    /* 1 = release parked kworkers onto the lane */
    __u32 frozen;       /* U1/U2: set by the auto-trigger */
};

/* U3: per-task heartbeat for the trickle release of TD_DSQ_KPARKED. */
struct td_hb {
    __u64 next_ns;          /* next 4s heartbeat gate for this CPU */
    __u64 window_end_ns;    /* end of the release window opened by the gate */
};

/* U3: comm filter entry — park a PF_KTHREAD whose comm matches. */
struct td_park_target {
    char  comm[TD_COMM_LEN];
    __u32 active;
};

struct td_stats {
    __u32 nr_race_enqueued;     /* race threads routed to a lane */
    __u32 nr_held_kthreads;     /* kworkers parked into TD_DSQ_KPARKED */
    __u32 nr_lane_dispatched;   /* race tasks moved to local on a lane */
    __u32 nr_kresumed;          /* parked kworkers released onto a lane */
    __u64 nr_auto_triggered;    /* U1: auto-triggers fired by kprobes */
    __u64 nr_hb_trickles;       /* U3: trickle releases from the HB */
    __u64 nr_frozen_enqueued;   /* U4: cgroup-frozen tasks parked */
    __u64 nr_starved_enqueued;  /* U4: tasks routed to DSQ_STARVE */
};

#endif /* __TIMEDILATION_H */
