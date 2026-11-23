/*
 * TimeDilation - userspace control tool (loader + lane commands).
 *
 * Mirrors the style of scx_starve (skeleton-based libbpf tool).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "TimeDilation.h"
#include "scx_starve.h"
#include "TimeDilation.skel.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xCAFE4A11
#endif

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s ACTION [ARGS]\n\n", prog);
    printf("TimeDilation - adversarial TOCTOU / UAF race amplification\n");
    printf("(sched_ext lane tooling; load requires root).\n\n");
    printf("Actions:\n");
    printf("  load [ACTION...]                    Load and attach the scheduler;\n");
    printf("                                      holds until Ctrl+C. Optional\n");
    printf("                                      follow-up action is run right\n");
    printf("                                      after attach.\n");
    printf("  arm [-n] CORE PID[,PID...]          Register race threads on lane CORE\n");
    printf("  arm [-n] CORE NAME[,NAME...]        (use '-n' to resolve names via /proc)\n");
    printf("  disarm                              Disarm all lanes; clear the map\n");
    printf("  park CORE                           Park kworkers (hold_k) on lane CORE\n");
    printf("  resume CORE                         Release parked kworkers onto lane CORE\n");
    printf("  slice PID:NS[,PID:NS...]            Set per-thread slice (NS=0 => 5ms default)\n");
    printf("  status                              Print lane state and registered threads\n");
    printf("  unload                              Note: exit the load process to detach\n");
    printf("  starve PID[,PID...]                    U4: starve targets onto DSQ_STARVE\n");
    printf("  starve-off PID[,PID...]                Deactivate starve targets\n");
    printf("  starve-set N (0-4)                     Set starve intensity\n");
    printf("  cg-freeze CID[,CID...]                 U4: freeze tasks in cgroups (TD_DSQ_FROZEN)\n");
    printf("  cg-unfreeze CID[,CID...]               Unfreeze cgroups\n");
    printf("  park-comm COMM[,COMM...]               U3: park only these kworkers\n");
    printf("  unpark-comm COMM[,COMM...]             U3: deactivate park targets\n");
    printf("  help\n\n");
    printf("Environment: TIMEDILATION_BPF_DIR overrides the pin directory\n");
    printf("             (default /sys/fs/bpf/timedilation).\n\n");
}

#define TD_BPF_DIR_DEFAULT "/sys/fs/bpf/timedilation"
#define TD_PIN_PATH_MAX    512
#define TD_MAX_PIN_PATHS   16

static const char *td_bpf_dir = TD_BPF_DIR_DEFAULT;
static char td_pin_store[TD_MAX_PIN_PATHS][TD_PIN_PATH_MAX];
static int td_pin_next;

/* Build one pin path under the configured pin directory. */
static const char *td_pin_path(const char *name)
{
    char *buf = td_pin_store[td_pin_next++ % TD_MAX_PIN_PATHS];

    snprintf(buf, TD_PIN_PATH_MAX, "%s/%s", td_bpf_dir, name);
    return buf;
}

/* mkdir -p for the pin directory. */
static int td_mkdir_p(const char *path)
{
    char tmp[TD_PIN_PATH_MAX];
    size_t len = strlen(path);
    char *p;

    if (!len || len >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, len + 1);
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/*
 * Pin the maps so other processes can inspect them.  The pin directory
 * must live on a bpffs mount; elsewhere libbpf refuses pin paths, so
 * loading continues unpinned with a warning instead of failing.
 */
static void td_pin_maps(struct TimeDilation_bpf *skel)
{
    struct statfs st;

    if (td_mkdir_p(td_bpf_dir) != 0) {
        fprintf(stderr, "TimeDilation: cannot create %s; maps will not be pinned\n",
                td_bpf_dir);
        return;
    }
    if (statfs(td_bpf_dir, &st) != 0 || st.f_type != BPF_FS_MAGIC) {
        fprintf(stderr, "TimeDilation: %s is not on bpffs; maps will not be pinned\n",
                td_bpf_dir);
        return;
    }

    bpf_map__set_pin_path(skel->maps.td_threads, td_pin_path("td_threads"));
    bpf_map__set_pin_path(skel->maps.td_cores, td_pin_path("td_cores"));
    bpf_map__set_pin_path(skel->maps.td_stats_map, td_pin_path("td_stats_map"));
    bpf_map__set_pin_path(skel->maps.td_active, td_pin_path("td_active"));
    bpf_map__set_pin_path(skel->maps.td_park_targets, td_pin_path("td_park_targets"));
    bpf_map__set_pin_path(skel->maps.td_kparked_hb, td_pin_path("td_kparked_hb"));
    bpf_map__set_pin_path(skel->maps.td_frozen_cgs, td_pin_path("td_frozen_cgs"));
    /* scx_starve fusion maps: pinned for co-process access. */
    bpf_map__set_pin_path(skel->maps.target_pids, td_pin_path("target_pids"));
    bpf_map__set_pin_path(skel->maps.config_map, td_pin_path("config_map"));
}

/*
 * Cross-process map access: use the live fd; if this process has not
 * loaded the object but the map is pinned, open the pin and reuse it.
 */
static int td_map_fd(struct bpf_map *map)
{
    const char *pin;
    int fd;

    fd = bpf_map__fd(map);
    if (fd >= 0)
        return fd;
    pin = bpf_map__pin_path(map);
    if (!pin)
        return -1;
    fd = bpf_obj_get(pin);
    if (fd >= 0)
        bpf_map__reuse_fd(map, fd);
    return bpf_map__fd(map);
}

/* Mirror the "any lane armed or held" flag used by the BPF side. */
static int td_set_active(struct TimeDilation_bpf *skel, int active)
{
    __u32 zero = 0, v = active ? 1 : 0;

    return bpf_map_update_elem(td_map_fd(skel->maps.td_active),
                                &zero, &v, BPF_ANY);
}

/*
 * Lane cpus must be online and inside the lane array.  Reading the
 * online list (rather than just counting cpus) also handles sparse
 * cpu ids such as "0-1,4-7".
 */
static int td_cpu_online(int cpu)
{
    FILE *f;
    char buf[512], *p;
    int lo, hi;
    long n;

    f = fopen("/sys/devices/system/cpu/online", "r");
    if (!f) {
        n = sysconf(_SC_NPROCESSORS_ONLN);
        return n > 0 && cpu < (int)n;
    }
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    for (p = buf; *p; ) {
        if (sscanf(p, "%d-%d", &lo, &hi) == 2) {
            if (cpu >= lo && cpu <= hi)
                return 1;
        } else if (sscanf(p, "%d", &lo) == 1) {
            if (cpu == lo)
                return 1;
        } else {
            break;
        }
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    return 0;
}

static int td_check_core(const char *action, int core)
{
    if (core < 0 || core >= TD_MAX_CORES) {
        fprintf(stderr, "%s: core %d is outside the lane range 0-%d\n",
                action, core, TD_MAX_CORES - 1);
        return -1;
    }
    if (!td_cpu_online(core)) {
        fprintf(stderr, "%s: core %d is not online on this system\n",
                action, core);
        return -1;
    }
    return 0;
}

static void td_read_comm(const char *path, char *buf, size_t len)
{
    FILE *f = fopen(path, "r");
    char *nl;

    buf[0] = '\0';
    if (!f)
        return;
    if (fgets(buf, (int)len, f)) {
        if ((nl = strchr(buf, '\n')))
            *nl = '\0';
    }
    fclose(f);
}

static void td_get_pid_comm(__u32 pid, char *comm, size_t max_len)
{
    char path[256];

    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    td_read_comm(path, comm, max_len);
    if (!comm[0])
        snprintf(comm, max_len, "?");
}

static int td_add_pid(__u32 *pids, int max, int *count, __u32 pid)
{
    int i;

    for (i = 0; i < *count; i++)
        if (pids[i] == pid)
            return 0;
    if (*count >= max)
        return -1;
    pids[(*count)++] = pid;
    return 0;
}

static int td_find_pids_by_name(const char *name, __u32 *pids, int max_pids)
{
    DIR *dir = opendir("/proc");
    struct dirent *ent;
    int count = 0;

    if (!dir)
        return -1;

    while ((ent = readdir(dir)) != NULL && count < max_pids) {
        char path[256], comm[TD_COMM_LEN];
        DIR *tasks;
        struct dirent *tent;
        __u32 pid;

        if (!isdigit((unsigned char)ent->d_name[0]))
            continue;
        pid = (__u32)atoi(ent->d_name);

        snprintf(path, sizeof(path), "/proc/%u/comm", pid);
        td_read_comm(path, comm, sizeof(comm));
        if (comm[0] && !strcmp(comm, name))
            td_add_pid(pids, max_pids, &count, pid);

        snprintf(path, sizeof(path), "/proc/%u/task", pid);
        tasks = opendir(path);
        if (!tasks)
            continue;
        while ((tent = readdir(tasks)) != NULL && count < max_pids) {
            __u32 tid;

            if (!isdigit((unsigned char)tent->d_name[0]))
                continue;
            tid = (__u32)atoi(tent->d_name);
            snprintf(path, sizeof(path), "/proc/%u/task/%u/comm", pid, tid);
            td_read_comm(path, comm, sizeof(comm));
            if (comm[0] && !strcmp(comm, name))
                td_add_pid(pids, max_pids, &count, tid);
        }
        closedir(tasks);
    }
    closedir(dir);
    return count;
}

/* Parse "a,b,c"; by_name resolves each item via td_find_pids_by_name. */
static int td_parse_id_list(struct TimeDilation_bpf *skel, const char *spec,
                            bool by_name, __u32 *out, int max_out)
{
    char *copy, *tok, *save;
    int n = 0, i;

    copy = strdup(spec);
    if (!copy)
        return -1;

    for (tok = strtok_r(copy, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (n >= max_out)
            break;
        if (by_name) {
            __u32 found[TD_MAX_THREADS];
            int nf = td_find_pids_by_name(tok, found, TD_MAX_THREADS);

            for (i = 0; i < nf && n < max_out; i++)
                out[n++] = found[i];
        } else {
            if (n < max_out)
                out[n++] = (__u32)strtoul(tok, NULL, 0);
        }
    }
    free(copy);
    return n;
}

static int td_action_arm(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    __u32 tids[TD_MAX_THREADS];
    bool by_name = false;
    const char *spec;
    int core, nr, i, tfd, cfd, err;
    struct td_core c;
    __u32 k;

    tfd = td_map_fd(skel->maps.td_threads);
    cfd = td_map_fd(skel->maps.td_cores);

    if (argc < 3)
        goto usage;

    if (!strcmp(argv[1], "-n")) {
        if (argc < 4)
            goto usage;
        by_name = true;
        core = atoi(argv[2]);
        spec = argv[3];
    } else {
        core = atoi(argv[1]);
        spec = argv[2];
    }
    if (td_check_core("arm", core))
        return 1;

    nr = td_parse_id_list(skel, spec, by_name, tids, TD_MAX_THREADS);
    if (nr <= 0) {
        fprintf(stderr, "arm: no threads resolved\n");
        return 1;
    }

    for (i = 0; i < nr; i++) {
        struct td_thread t = { .core = (__u32)core, .slice_ns = 0 };

        err = bpf_map_update_elem(tfd, &tids[i], &t, BPF_ANY);
        if (err) {
            fprintf(stderr, "arm: pid %u: %s\n", tids[i], strerror(-err));
            return 1;
        }
        printf("  [arm] pid %u -> lane %d\n", tids[i], core);
    }

    c = (struct td_core){ .lane_dsq = TD_DSQ_ID((__u32)core), .armed = 1 };
    k = (__u32)core;
    err = bpf_map_update_elem(cfd, &k, &c, BPF_ANY);
    if (err) {
        fprintf(stderr, "arm: core %d: %s\n", core, strerror(-err));
        return 1;
    }
    td_set_active(skel, 1);
    printf("TimeDilation: armed lane %d with %d thread(s).\n", core, nr);
    return 0;

usage:
    fprintf(stderr, "usage: TimeDilation arm [-n] CORE PIDS|NAMES\n");
    return 1;
}

static int td_action_disarm(struct TimeDilation_bpf *skel)
{
    int tfd = td_map_fd(skel->maps.td_threads);
    int cfd = td_map_fd(skel->maps.td_cores);
    __u32 cur_key = 0, next_key = 0;
    int n = 0;

    while (bpf_map_get_next_key(tfd, &cur_key, &next_key) == 0) {
        bpf_map_delete_elem(tfd, &next_key);
        cur_key = next_key;
        n++;
    }
    for (int i = 0; i < TD_MAX_CORES; i++) {
        struct td_core c = {
            .lane_dsq = TD_DSQ_ID((__u32)i),
            .armed = 0,
            .hold_k = 0,
            .release_k = 0,
        };

        if (bpf_map_update_elem(cfd, &i, &c, BPF_ANY))
            break;
    }
    td_set_active(skel, 0);
    printf("TimeDilation: disarmed all lanes; cleared %d thread registration(s).\n", n);
    return 0;
}

static int td_action_park(struct TimeDilation_bpf *skel, int argc, char **argv, int release)
{
    int cfd = td_map_fd(skel->maps.td_cores);
    struct td_core c;
    __u32 core;
    int err;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation %s CORE\n", release ? "resume" : "park");
        return 1;
    }
    core = (__u32)atoi(argv[1]);
    if (td_check_core(release ? "resume" : "park", (int)core))
        return 1;
    if (bpf_map_lookup_elem(cfd, &core, &c) != 0) {
        fprintf(stderr, "park: lane %u has no state entry\n", core);
        return 1;
    }
    c.hold_k = release ? 0 : 1;
    c.release_k = release ? 1 : c.release_k;
    err = bpf_map_update_elem(cfd, &core, &c, BPF_ANY);
    if (err) {
        fprintf(stderr, "park: %s\n", strerror(-err));
        return 1;
    }
    td_set_active(skel, 1);
    printf("TimeDilation: lane %u %s\n", core,
           release ? "release requested (parked kworkers onto lane)"
                   : "kworkers parked (hold_k=1)");
    return 0;
}

static int td_action_slice(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    int tfd = td_map_fd(skel->maps.td_threads);
    char *copy, *tok, *save;
    int nr = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation slice PID:NS[,PID:NS...] (NS=0 => 5ms default)\n");
        return 1;
    }

    copy = strdup(argv[1]);
    if (!copy)
        return 1;

    for (tok = strtok_r(copy, ",", &save); tok && nr < TD_MAX_THREADS;
         tok = strtok_r(NULL, ",", &save)) {
        char *colon = strchr(tok, ':');
        __u32 pid, ns = 0;
        struct td_thread t;
        int err;

        if (!colon)
            continue;
        *colon = '\0';
        pid = (__u32)strtoul(tok, NULL, 0);
        ns = (__u32)strtoul(colon + 1, NULL, 0);
        if (bpf_map_lookup_elem(tfd, &pid, &t) != 0) {
            fprintf(stderr, "slice: pid %u not registered; arm it first\n", pid);
            free(copy);
            return 1;
        }
        t.slice_ns = ns;
        err = bpf_map_update_elem(tfd, &pid, &t, BPF_ANY);
        if (err) {
            fprintf(stderr, "slice: pid %u: %s\n", pid, strerror(-err));
            free(copy);
            return 1;
        }
        printf("  [slice] pid %u -> %u ns%s\n", pid, ns,
               ns ? "" : " (5ms default)");
        nr++;
    }
    free(copy);
    printf("TimeDilation: set slices on %d thread(s).\n", nr);
    return 0;
}

/* Set lane_dsq in the core map so armed lanes have a queue to dispatch. */
static int td_init_cores(struct TimeDilation_bpf *skel)
{
    int cfd = td_map_fd(skel->maps.td_cores);
    int i;

    for (i = 0; i < TD_MAX_CORES; i++) {
        struct td_core c = { .lane_dsq = TD_DSQ_ID((__u32)i) };

        if (bpf_map_update_elem(cfd, &i, &c, BPF_ANY))
            return -1;
    }
    return 0;
}

static void td_action_status(struct TimeDilation_bpf *skel)
{
    int cfd = td_map_fd(skel->maps.td_cores);
    int tfd = td_map_fd(skel->maps.td_threads);
    int tfd2 = td_map_fd(skel->maps.target_pids);
    int cfd2 = td_map_fd(skel->maps.td_frozen_cgs);
    int tfd3 = td_map_fd(skel->maps.td_park_targets);
    __u32 i;
    __u64 cur = 0, next = 0;
    struct td_core c;
    int n_threads = 0;

    printf("TimeDilation status\n");
    printf("%-6s | %-12s | %-6s | %-9s | %-9s | %-6s\n",
           "core", "lane_dsq", "armed", "hold_k", "release_k", "frozen");
    for (i = 0; i < TD_MAX_CORES; i++) {
        if (bpf_map_lookup_elem(cfd, &i, &c) == 0)
            printf("%-6u | %-12llu | %-6u | %-9u | %-9u | %-6u\n",
                   i, (unsigned long long)c.lane_dsq,
                   c.armed, c.hold_k, c.release_k, c.frozen);
    }
    {
        int ncpus = libbpf_num_possible_cpus();
        struct td_stats agg = {0};
        struct td_stats *percpu = calloc((size_t)ncpus, sizeof(*percpu));
        __u32 z = 0;
        int j;

        if (percpu && bpf_map_lookup_elem(td_map_fd(skel->maps.td_stats_map), &z, percpu) == 0)
            for (j = 0; j < ncpus; j++) {
                agg.nr_auto_triggered += percpu[j].nr_auto_triggered;
                agg.nr_hb_trickles += percpu[j].nr_hb_trickles;
                agg.nr_frozen_enqueued += percpu[j].nr_frozen_enqueued;
                agg.nr_starved_enqueued += percpu[j].nr_starved_enqueued;
                agg.nr_held_kthreads += percpu[j].nr_held_kthreads;
                agg.nr_kresumed += percpu[j].nr_kresumed;
            }
        free(percpu);
        printf("auto_triggered=%llu hb_trickles=%llu held_kthreads=%u kresumed=%u frozen_enqueued=%llu starved_enqueued=%llu\n",
               (unsigned long long)agg.nr_auto_triggered,
               (unsigned long long)agg.nr_hb_trickles,
               agg.nr_held_kthreads,
               agg.nr_kresumed,
               (unsigned long long)agg.nr_frozen_enqueued,
               (unsigned long long)agg.nr_starved_enqueued);
    }
    printf("starve targets:\n");
    cur = 0;
    while (bpf_map_get_next_key(tfd2, &cur, &next) == 0) {
        struct starve_target t;

        if (bpf_map_lookup_elem(tfd2, &next, &t) == 0 && t.active)
            printf("  pid %u (%s)\n", next, t.comm);
        cur = next;
    }
    printf("frozen cgroups:\n");
    cur = 0;
    while (bpf_map_get_next_key(cfd2, &cur, &next) == 0) {
        __u32 active = 1;

        bpf_map_lookup_elem(cfd2, &next, &active);
        if (active)
            printf("  cg_id %llu\n", (unsigned long long)next);
        cur = next;
    }
    printf("park targets:\n");
    for (i = 0; i < TD_MAX_PARK_TARGETS; i++) {
        struct td_park_target e;

        if (bpf_map_lookup_elem(tfd3, &i, &e) == 0 && e.active)
            printf("  td_park_targets[%u] = %s\n", i, e.comm);
    }

    printf("race threads (pid -> lane, comm):\n");
    cur = 0;
    while (bpf_map_get_next_key(tfd, &cur, &next) == 0) {
        struct td_thread t;
        char comm[TD_COMM_LEN] = {0};

        if (bpf_map_lookup_elem(tfd, &next, &t) == 0) {
            td_get_pid_comm(next, comm, sizeof(comm));
            if (t.slice_ns)
                printf("  pid %-6u | lane %u | slice %u ns | %s\n",
                       next, t.core, t.slice_ns, comm);
            else
                printf("  pid %-6u | lane %u | slice default | %s\n",
                       next, t.core, comm);
            n_threads++;
        }
        cur = next;
    }
    if (!n_threads)
        printf("  (none)\n");
    printf("\n");
}


/* ------------------------------------------------------------------
 * U4: scx_starve fusion -- starve targets by pid.
 * ------------------------------------------------------------------ */
static int td_action_starve(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    int tfd = td_map_fd(skel->maps.target_pids);
    __u32 pids[TD_MAX_THREADS];
    int nr, i;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation starve PID[,PID...]\n");
        return 1;
    }
    nr = td_parse_id_list(skel, argv[1], false, pids, TD_MAX_THREADS);
    for (i = 0; i < nr; i++) {
        struct starve_target t;

        memset(&t, 0, sizeof(t));
        t.active = 1;
        td_get_pid_comm(pids[i], t.comm, TD_COMM_LEN);
        if (bpf_map_update_elem(tfd, &pids[i], &t, BPF_ANY)) {
            fprintf(stderr, "starve: pid %u: %s\n", pids[i], strerror(errno));
            return 1;
        }
        printf("  [starve] pid %u (%s)\n", pids[i], t.comm);
    }
    printf("TimeDilation: starved %d target(s).\n", nr);
    return 0;
}

static int td_action_starve_off(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    int tfd = td_map_fd(skel->maps.target_pids);
    __u32 pids[TD_MAX_THREADS];
    int nr, i;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation starve-off PID[,PID...]\n");
        return 1;
    }
    nr = td_parse_id_list(skel, argv[1], false, pids, TD_MAX_THREADS);
    for (i = 0; i < nr; i++) {
        struct starve_target t;

        if (bpf_map_lookup_elem(tfd, &pids[i], &t) != 0) {
            fprintf(stderr, "starve-off: pid %u not active\n", pids[i]);
            continue;
        }
        t.active = 0;
        if (bpf_map_update_elem(tfd, &pids[i], &t, BPF_ANY)) {
            fprintf(stderr, "starve-off: pid %u: %s\n", pids[i], strerror(errno));
            return 1;
        }
        printf("  [starve-off] pid %u\n", pids[i]);
    }
    return 0;
}

static int td_action_starve_set(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    struct starve_config cfg;
    __u32 zero = 0;
    int v;

    if (argc < 2 || (v = atoi(argv[1])) < 0 || v > 4) {
        fprintf(stderr, "usage: TimeDilation starve-set N (0-4)\n");
        return 1;
    }
    memset(&cfg, 0, sizeof(cfg));
    cfg.intensity = (__u32)v;
    if (bpf_map_update_elem(td_map_fd(skel->maps.config_map), &zero, &cfg, BPF_ANY)) {
        fprintf(stderr, "starve-set: %s\n", strerror(errno));
        return 1;
    }
    printf("TimeDilation: starve intensity = %d\n", v);
    return 0;
}

/* ------------------------------------------------------------------
 * U4: cgroup isolation.
 * ------------------------------------------------------------------ */
static int td_action_cg_freeze(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    int cfd = td_map_fd(skel->maps.td_frozen_cgs);
    __u64 one = 1;
    int n = 0;
    char *copy, *tok, *save;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation cg-freeze CID[,CID...]\n");
        return 1;
    }
    copy = strdup(argv[1]);
    if (!copy)
        return 1;
    for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        __u64 cg = strtoull(tok, NULL, 0);

        if (bpf_map_update_elem(cfd, &cg, &one, BPF_ANY)) {
            fprintf(stderr, "cg-freeze: %s\n", strerror(errno));
            free(copy);
            return 1;
        }
        printf("  [cg-freeze] cg_id %llu\n", (unsigned long long)cg);
        n++;
    }
    free(copy);
    printf("TimeDilation: froze %d cgroup(s).\n", n);
    return 0;
}

static int td_action_cg_unfreeze(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    int cfd = td_map_fd(skel->maps.td_frozen_cgs);
    __u64 zero = 0;
    int n = 0;
    char *copy, *tok, *save;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation cg-unfreeze CID[,CID...]\n");
        return 1;
    }
    copy = strdup(argv[1]);
    if (!copy)
        return 1;
    for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        __u64 cg = strtoull(tok, NULL, 0);

        if (bpf_map_update_elem(cfd, &cg, &zero, BPF_ANY)) {
            fprintf(stderr, "cg-unfreeze: %s\n", strerror(errno));
            free(copy);
            return 1;
        }
        printf("  [cg-unfreeze] cg_id %llu\n", (unsigned long long)cg);
        n++;
    }
    free(copy);
    printf("TimeDilation: unfroze %d cgroup(s).\n", n);
    return 0;
}

/* ------------------------------------------------------------------
 * U3: surgical kworker parking (comm filter).
 * ------------------------------------------------------------------ */
static int td_action_park_comm(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    int tfd = td_map_fd(skel->maps.td_park_targets);
    char *copy, *tok, *save;
    int added = 0;
    __u32 i;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation park-comm COMM[,COMM...]\n");
        return 1;
    }
    copy = strdup(argv[1]);
    if (!copy)
        return 1;
    for (tok = strtok_r(copy, ",", &save); tok && added < TD_MAX_PARK_TARGETS;
         tok = strtok_r(NULL, ",", &save)) {
        for (i = 0; i < TD_MAX_PARK_TARGETS; i++) {
            struct td_park_target e;

            if (bpf_map_lookup_elem(tfd, &i, &e) != 0 || e.active)
                continue;
            memset(&e, 0, sizeof(e));
            e.active = 1;
            snprintf(e.comm, sizeof(e.comm), "%s", tok);
            if (bpf_map_update_elem(tfd, &i, &e, BPF_ANY)) {
                fprintf(stderr, "park-comm: %s: %s\n", tok, strerror(errno));
                free(copy);
                return 1;
            }
            printf("  [park-comm] td_park_targets[%u] = %s\n", i, e.comm);
            added++;
            break;
        }
    }
    free(copy);
    printf("TimeDilation: %d park target(s).\n", added);
    return 0;
}

static int td_name_matches(const char *comm, const char *list)
{
    char *copy, *tok, *save = NULL;
    int m = 0;

    copy = strdup(list);
    if (!copy)
        return 0;
    for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (!strcmp(tok, comm)) {
            m = 1;
            break;
        }
    }
    free(copy);
    return m;
}

static int td_action_unpark_comm(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    int tfd = td_map_fd(skel->maps.td_park_targets);
    int removed = 0;
    __u32 i;

    if (argc < 2) {
        fprintf(stderr, "usage: TimeDilation unpark-comm COMM[,COMM...]\n");
        return 1;
    }
    for (i = 0; i < TD_MAX_PARK_TARGETS; i++) {
        struct td_park_target e;

        if (bpf_map_lookup_elem(tfd, &i, &e) != 0 || !e.active)
            continue;
        if (td_name_matches(e.comm, argv[1])) {
            e.active = 0;
            if (bpf_map_update_elem(tfd, &i, &e, BPF_ANY))
                fprintf(stderr, "unpark-comm: %s\n", strerror(errno));
            else
                removed++;
        }
    }
    printf("TimeDilation: deactivated %d park target(s).\n", removed);
    return 0;
}

static int td_dispatch_action(struct TimeDilation_bpf *skel, int argc, char **argv)
{
    const char *a = argv[0];

    if (td_map_fd(skel->maps.td_threads) < 0 ||
        td_map_fd(skel->maps.td_cores) < 0) {
        fprintf(stderr, "%s: maps unavailable (is TimeDilation loaded?)\n",
                a);
        return 1;
    }

    if (!strcmp(a, "arm"))
        return td_action_arm(skel, argc, argv);
    if (!strcmp(a, "disarm"))
        return td_action_disarm(skel);
    if (!strcmp(a, "park"))
        return td_action_park(skel, argc, argv, 0);
    if (!strcmp(a, "resume"))
        return td_action_park(skel, argc, argv, 1);
    if (!strcmp(a, "slice"))
        return td_action_slice(skel, argc, argv);
    if (!strcmp(a, "status")) {
        td_action_status(skel);
        return 0;
    }
    if (!strcmp(a, "starve"))
        return td_action_starve(skel, argc, argv);
    if (!strcmp(a, "starve-off"))
        return td_action_starve_off(skel, argc, argv);
    if (!strcmp(a, "starve-set"))
        return td_action_starve_set(skel, argc, argv);
    if (!strcmp(a, "cg-freeze"))
        return td_action_cg_freeze(skel, argc, argv);
    if (!strcmp(a, "cg-unfreeze"))
        return td_action_cg_unfreeze(skel, argc, argv);
    if (!strcmp(a, "park-comm"))
        return td_action_park_comm(skel, argc, argv);
    if (!strcmp(a, "unpark-comm"))
        return td_action_unpark_comm(skel, argc, argv);
    if (!strcmp(a, "unload")) {
        printf("To detach: exit the 'TimeDilation load' process (Ctrl+C).\n");
        return 0;
    }
    if (!strcmp(a, "help")) {
        print_usage("TimeDilation");
        return 0;
    }
    fprintf(stderr, "unknown action: %s\n", a);
    print_usage("TimeDilation");
    return 1;
}

/* U1: expanded from the shared TD_TRIGGER_LIST in TimeDilation.h. */
static const char *td_trigger_syms[] = {
#define TD_TRIGGER_NAME(sym) #sym,
    TD_TRIGGER_LIST(TD_TRIGGER_NAME)
#undef TD_TRIGGER_NAME
};
#define TD_NR_TRIGGERS (sizeof(td_trigger_syms) / sizeof(td_trigger_syms[0]))

static struct bpf_link *td_trig_links[TD_NR_TRIGGERS];

static struct bpf_program *td_find_prog(struct TimeDilation_bpf *skel, const char *sym)
{
    char sec[64];
    struct bpf_program *p = NULL;

    /* Programs are named after their C functions; the attach target lives
     * in the section name ("kprobe/<sym>"). Match on the latter. */
    snprintf(sec, sizeof(sec), "kprobe/%s", sym);
    while ((p = bpf_object__next_program(skel->obj, p)) != NULL) {
        const char *sname = bpf_program__section_name(p);

        if (sname && !strcmp(sname, sec))
            return p;
    }
    return NULL;
}

static int td_attach_triggers(struct TimeDilation_bpf *skel)
{
    /* U1: attach the kprobes that flip release_k/frozen for the arming
     * thread when it enters a vulnerable kernel function. */
    int i, ok = 0;

    for (i = 0; i < (int)TD_NR_TRIGGERS; i++) {
        const char *sym = td_trigger_syms[i];
        struct bpf_program *prog = td_find_prog(skel, sym);

        if (!prog) {
            fprintf(stderr, "TimeDilation: trigger program missing: %s\n", sym);
            continue;
        }
        td_trig_links[i] = bpf_program__attach(prog);
        if (td_trig_links[i]) {
            ok++;
        } else {
            fprintf(stderr, "TimeDilation: attach trigger %s: %s\n",
                    sym, strerror(errno));
        }
    }
    return ok;
}

int main(int argc, char **argv)
{
    struct TimeDilation_bpf *skel;
    struct bpf_link *link = NULL;
    const char *action;
    int err = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    action = argv[1];

    {
        const char *dir = getenv("TIMEDILATION_BPF_DIR");

        if (dir && *dir)
            td_bpf_dir = dir;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (!strcmp(action, "help") || !strcmp(action, "--help") || !strcmp(action, "-h")) {
        print_usage(argv[0]);
        return 0;
    }

    skel = TimeDilation_bpf__open();
    if (!skel) {
        fprintf(stderr, "TimeDilation: failed to open skeleton\n");
        return 1;
    }
    td_pin_maps(skel);

    if (!strcmp(action, "load")) {
        err = TimeDilation_bpf__load(skel);
        if (err) {
            fprintf(stderr, "TimeDilation: load: %d (%s)\n",
                    err, strerror(-err));
            goto cleanup;
        }
        td_attach_triggers(skel);
        link = bpf_map__attach_struct_ops(skel->maps.td_ops);
        if (!link) {
            fprintf(stderr, "TimeDilation: attach_struct_ops: %s\n",
                    strerror(errno));
            err = 1;
            goto cleanup;
        }
        if (td_init_cores(skel))
            fprintf(stderr, "TimeDilation: warning: core map init failed\n");
        printf("TimeDilation scheduler loaded and attached.\n");

        /* Optional follow-up action, run in this process. */
        if (argc > 2) {
            err = td_dispatch_action(skel, argc - 2, argv + 2);
            if (err)
                goto cleanup;
        }
        printf("TimeDilation: holding; Ctrl+C to detach.\n");
        while (!exiting)
            sleep(1);
        goto cleanup;
    }

    err = td_dispatch_action(skel, argc - 1, argv + 1);

cleanup:
    { int i; for (i = 0; i < 4; i++) if (td_trig_links[i]) bpf_link__destroy(td_trig_links[i]); }
    if (link)
        bpf_link__destroy(link);
    TimeDilation_bpf__destroy(skel);
    return err;
}
