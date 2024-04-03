// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include "common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

static inline int handle_event(tracepoint_t probe) {
  struct event *e;

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->probe = probe;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/io_uring/io_uring_complete")
int handle_complete(struct trace_event_io_uring_complete *ctx) {
    bpf_printk("io_uring_complete");
    return handle_event(IO_URING_COMPLETE);
}

SEC("tp/io_uring/io_uring_cqe_overflow")
int handle_cqe_overflow(struct trace_event_io_uring_cqe_overflow *ctx) {
    bpf_printk("io_uring_cqe_overflow");
    return handle_event(IO_URING_CQE_OVERFLOW);
}

SEC("tp/io_uring/io_uring_fail_link")
int handle_fail_link(struct trace_event_io_uring_fail_link *ctx) {
    bpf_printk("io_uring_fail_link");
    return handle_event(IO_URING_FAIL_LINK);
}

SEC("tp/io_uring/io_uring_file_get")
int handle_file_get(struct trace_event_io_uring_file_get *ctx) {
    bpf_printk("io_uring_file_get");
    return handle_event(IO_URING_FILE_GET);
}

SEC("tp/io_uring/io_uring_link")
int handle_link(struct trace_event_io_uring_link *ctx) {
    bpf_printk("io_uring_link");
    return handle_event(IO_URING_LINK);
}

SEC("tp/io_uring/io_uring_local_work_run")
int handle_local_work_run(struct trace_event_io_uring_local_work_run *ctx) {
    bpf_printk("io_uring_local_work_run");
    return handle_event(IO_URING_LOCAL_WORK_RUN);
}

SEC("tp/io_uring/io_uring_poll_arm")
int handle_poll_arm(struct trace_event_io_uring_poll_arm *ctx) {
    bpf_printk("io_uring_poll_arm");
    return handle_event(IO_URING_POLL_ARM);
}

SEC("tp/io_uring/io_uring_queue_async_work")
int handle_queue_async_work(struct trace_event_io_uring_queue_async_work *ctx) {
    bpf_printk("io_uring_queue_async_work");
    return handle_event(IO_URING_QUEUE_ASYNC_WORK);
}

SEC("tp/io_uring/io_uring_register")
int handle_register(struct trace_event_io_uring_register *ctx) {
    bpf_printk("io_uring_register");
    return handle_event(IO_URING_REGISTER);
}

SEC("tp/io_uring/io_uring_req_failed")
int handle_req_failed(struct trace_event_io_uring_req_failed *ctx) {
    bpf_printk("io_uring_req_failed");
    return handle_event(IO_URING_REQ_FAILED);
}

SEC("tp/io_uring/io_uring_short_write")
int handle_short_write(struct trace_event_io_uring_short_write *ctx) {
    bpf_printk("io_uring_short_write");
    return handle_event(IO_URING_SHORT_WRITE);
}

SEC("tp/io_uring/io_uring_submit_sqe")
int handle_sumbit_sqe(struct trace_event_io_uring_submit_sqe *ctx) {
    bpf_printk("io_uring_submit_sqe");
    return handle_event(IO_URING_SUBMIT_SQE);
}
SEC("tp/io_uring/io_uring_task_add")
int handle_task_add(struct trace_event_io_uring_task_add *ctx) {
    bpf_printk("io_uring_task_add");
    return handle_event(IO_URING_TASK_ADD);
}
SEC("tp/io_uring/io_uring_task_work_run")
int handle_task_work_run(struct trace_event_io_uring_task_work_run *ctx) {
    bpf_printk("io_uring_task_work_run");
    return handle_event(IO_URING_TASK_WORK_RUN);
}
