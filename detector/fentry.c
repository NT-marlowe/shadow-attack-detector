//go:build ignore

#include "./headers/common.h"

#include "./headers/bpf_endian.h"
#include "./headers/bpf_tracing.h"

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

struct event {
	u8 comm[TASK_COMM_LEN];
	__u32 fd;
};
struct event *unused __attribute__((unused));

SEC("fexit/__x64_sys_openat")
int BPF_PROG(sys_openat, long ret) {
	if (ret < 0) {
		bpf_printk("sys_open failed, ret = %ld\n", ret);
		return 0;
	}

	struct event *open_event;
	open_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!open_event) {
		return 0;
	}
	__u32 fd = ret;

	open_event->fd = fd;
	bpf_get_current_comm(&open_event->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(open_event, 0);
	return 0;
}

// Needs to be architecture-specific kernel function
// SEC("fentry/__x64_sys_close")
// int BPF_PROG(sys_close, unsigned int fd) {
// 	struct event *close_event;
// 	close_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
// 	if (!close_event) {
// 		return 0;
// 	}

// 	close_event->fd = fd;
// 	bpf_get_current_comm(&close_event->comm, TASK_COMM_LEN);

// 	bpf_ringbuf_submit(close_event, 0);

// 	return 0;
// }
