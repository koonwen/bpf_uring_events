// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include "common.h"
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct event);
} heap SEC(".maps");

SEC("tp/io_uring/io_uring_create")
int handle_register(struct trace_event_io_uring_create *ctx) {
  bpf_printk("Triggered");
  struct event *e;
  int zero = 0;

  e = bpf_map_lookup_elem(&heap, &zero);
  if (!e) /* can't happen */
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
  return 0;
}
