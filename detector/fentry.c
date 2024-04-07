//go:build ignore

#include "./headers/common.h"

#include "./headers/bpf_endian.h"
#include "./headers/bpf_tracing.h"

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event {
	u8 comm[TASK_COMM_LEN];
	__u32 fd;
};
struct event *unused __attribute__((unused));

SEC("fentry/sys_close")
int BPF_PROG(sys_close, unsigned int fd) {
	struct event *close_event;
	close_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!close_event) {
		return 0;
	}

	close_event->fd = fd;
	bpf_get_current_comm(&close_event->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(close_event, 0);

	return 0;
}
