/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Andrii Nakryiko */
#ifndef __COMMON_H
#define __COMMON_H

struct trace_entry {
  short unsigned int type;
  unsigned char flags;
  unsigned char preempt_count;
  int pid;
};

/* sched_process_exec tracepoint context */
struct trace_event_raw_sched_process_exec {
  struct trace_entry ent;
  unsigned int __data_loc_filename;
  int pid;
  int old_pid;
  char __data[0];
};

/* io_uring_create tracepoint context */
struct trace_event_io_uring_create {
  struct trace_entry ent;
  int fd;
  void *ctx;
  unsigned int sq_entries;
  unsigned int cq_entries;
  unsigned int flags;
};
/* print fmt: "ring %p, fd %d sq size %d, cq size %d, flags 0x%x", REC->ctx,
 * REC->fd, REC->sq_entries, REC->cq_entries, REC->flags */

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512

/* definition of a sample sent to user-space from BPF program */
struct event {
  int pid;
  char comm[TASK_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
};

#endif /* __COMMON_H */
