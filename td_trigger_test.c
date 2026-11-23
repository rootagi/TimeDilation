/*
 * td_trigger_test - exercise TimeDilation's U1 auto-trigger.
 *
 * Assumes the upgraded scheduler is loaded and the process is armed
 * (e.g. `sudo ./TimeDilation arm -n 0 td_trigger_test`).  The pin
 * directory defaults to /sys/fs/bpf/timedilation and can be overridden
 * with TIMEDILATION_BPF_DIR.
 *
 * Spray threads churn AF_UNIX socket pairs (with in-flight fds passed
 * via SCM_RIGHTS) and shutdown/close them -- driving `unix_gc` entries
 * through the kprobe. The main thread polls the pinned td_cores[0]
 * entry and reports the U1 state (frozen/release_k).
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "TimeDilation.h"

#define TD_BPDIR_DEFAULT "/sys/fs/bpf/timedilation"
#define TD_PATH_MAX 512
#define TD_POLL_NS (3ULL * 1000 * 1000 * 1000)
#define NR_SPRAY 4

static void *spray(void *unused) {
  prctl(PR_SET_NAME, "td_trigger_test", 0, 0, 0);
  for (;;) {
    char b[1] = {'x'};
    struct msghdr msg;
    struct iovec iov;
    char cbuf[128];
    struct cmsghdr *c;
    int sv[2], inflight;
    ssize_t sz;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
      usleep(5000);
      continue;
    }
    inflight = dup(0);
    if (inflight >= 0) {
      memset(&msg, 0, sizeof(msg));
      memset(cbuf, 0, sizeof(cbuf));
      iov.iov_base = b;
      iov.iov_len = sizeof(b);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = cbuf;
      msg.msg_controllen = sizeof(cbuf);
      c = CMSG_FIRSTHDR(&msg);
      c->cmsg_level = SOL_SOCKET;
      c->cmsg_type = SCM_RIGHTS;
      c->cmsg_len = CMSG_LEN(sizeof(int));
      memcpy(CMSG_DATA(c), &inflight, sizeof(int));
      sz = sendmsg(sv[0], &msg, MSG_NOSIGNAL);
      if (sz < 0)
        close(inflight);
    }
    shutdown(sv[0], SHUT_RDWR);
    shutdown(sv[1], SHUT_RDWR);
    close(sv[0]);
    close(sv[1]);
    usleep(2000);
  }
  return NULL;
}

static __u64 now_ns(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(void) {
  int cores_fd, stats_fd, nr_cpus, i, seen = 0;
  const char *dir = getenv("TIMEDILATION_BPF_DIR");
  char cores_path[TD_PATH_MAX], stats_path[TD_PATH_MAX];
  struct td_core c;
  struct td_stats *all;
  __u32 k = 0;
  __u64 t0, n;
  pthread_t t[NR_SPRAY];

  if (!dir || !*dir)
    dir = TD_BPDIR_DEFAULT;
  snprintf(cores_path, sizeof(cores_path), "%s/td_cores", dir);
  snprintf(stats_path, sizeof(stats_path), "%s/td_stats_map", dir);

  cores_fd = bpf_obj_get(cores_path);
  if (cores_fd < 0) {
    perror("bpf_obj_get td_cores");
    return 1;
  }
  stats_fd = bpf_obj_get(stats_path);
  if (stats_fd < 0) {
    perror("bpf_obj_get td_stats_map");
    return 1;
  }

  nr_cpus = libbpf_num_possible_cpus();
  all = calloc((size_t)nr_cpus, sizeof(*all));
  if (!all) {
    perror("calloc");
    return 1;
  }

  for (i = 0; i < NR_SPRAY; i++)
    pthread_create(&t[i], NULL, spray, NULL);

  t0 = now_ns();
  while (now_ns() - t0 < TD_POLL_NS) {
    usleep(100000);
    if (bpf_map_lookup_elem(cores_fd, &k, &c) == 0) {
      printf("[poll] core%u armed=%u hold_k=%u release_k=%u frozen=%u\n", k,
             c.armed, c.hold_k, c.release_k, c.frozen);
      if (c.frozen || c.release_k)
        seen = 1;
    }
    if (bpf_map_lookup_elem(stats_fd, &k, all) == 0) {
      n = 0;
      for (i = 0; i < nr_cpus; i++)
        n += all[i].nr_auto_triggered;
      printf("[stats] nr_auto_triggered=%llu\n", (unsigned long long)n);
    }
  }
  printf(seen ? "RESULT: auto-trigger observed\n"
              : "RESULT: no trigger observed\n");
  free(all);
  return seen ? 0 : 1;
}
