// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include "trace_uring.h"
#include "trace_uring.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>

int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                    va_list args) {
  /* Ignore debug-level libbpf logs */
  if (level > LIBBPF_INFO)
    return 0;
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

int run(int (*handle_event)(void*, void*, size_t)) {
  struct ring_buffer *rb = NULL;
  struct trace_uring_bpf *skel;
  int err;

  /* Set up libbpf logging callback */
  libbpf_set_print(libbpf_print_fn);

  /* Implicitly bump RLIMIT_MEMLOCK to create BPF maps */
  libbpf_set_strict_mode(LIBBPF_STRICT_DIRECT_ERRS | LIBBPF_STRICT_CLEAN_PTRS);

  /* Clean handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  skel = trace_uring_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Attach tracepoint */
  err = trace_uring_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Process events */
  /* printf("%-8s %-5s %-7s %-16s\n", "TIME", "EVENT", "PID", "COMM"); */
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling ring buffer: %d\n", err);
      break;
    }
  }

cleanup:
  ring_buffer__free(rb);
  trace_uring_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
