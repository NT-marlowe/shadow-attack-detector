//go:build ignore

#include "./headers/common.h"

#include "./headers/bpf_endian.h"
#include "./headers/bpf_tracing.h"

#define TASK_COMM_LEN 16
#define SYS_OPEN 0
#define SYS_CLOSE 1

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

struct event {
	u8 sys_type;
	u8 comm[TASK_COMM_LEN];
	u32 fd;
};
struct event *unused __attribute__((unused));

SEC("fexit/do_sys_openat2")
int BPF_PROG(do_sys_oepnat_exit, int dfd, const char *filename,
	struct open_how *how, long ret) {
	if (ret < 0) {
		// little confidence: do_sys_openat2 returns `-errno` when it fails to
		// open a file. so if you see e.g. `sys_open failed, ret = -2`, it means
		// this funciton fails with error 2.
		bpf_printk("sys_open failed, ret = %ld\n", ret);
		return 0;
	}

	struct event *open_event;
	open_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!open_event) {
		return 0;
	}
	__u32 fd = ret;

	open_event->sys_type = SYS_OPEN;
	open_event->fd       = fd;
	bpf_get_current_comm(&open_event->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(open_event, 0);
	return 0;
}

// Needs to be architecture-specific kernel function
SEC("fentry/close_fd")
int BPF_PROG(close_fd, unsigned int fd) {
	struct event *close_event;
	close_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!close_event) {
		bpf_printk("sys_open failed, ret = %ld\n", fd);
		return 0;
	}

	close_event->sys_type = SYS_CLOSE;
	close_event->fd       = fd;
	bpf_get_current_comm(&close_event->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(close_event, 0);

	return 0;
}
