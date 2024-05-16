//go:build ignore

#include <bpf/bpf_core_read.h>

#include "./headers/common.h"

#include "./headers/bpf_endian.h"
#include "./headers/bpf_tracing.h"

#include "./headers/vmlinux.h"

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16
#define SYS_OPEN 0
#define SYS_CLOSE 1

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");
struct event {
	u8 comm[TASK_COMM_LEN];
	u8 sys_call_enum;
	u32 fd;
	u32 pid;
};
struct event *unused __attribute__((unused));

// SEC("fexit/do_sys_openat2")
// int BPF_PROG(do_sys_oepnat_exit, int dfd, const char *filename,
// 	struct open_how *how, long ret) {
// 	if (ret < 0) {
// 		bpf_printk("sys_open failed, ret = %ld\n", ret);
// 		return 0;
// 	}

// 	struct event *open_event;
// 	open_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
// 	if (!open_event) {
// 		return 0;
// 	}
// 	u32 fd = ret;

// 	bpf_get_current_comm(&open_event->comm, TASK_COMM_LEN);

// 	open_event->sys_call_enum = SYS_OPEN;
// 	open_event->fd            = fd;
// 	open_event->pid           = bpf_get_current_pid_tgid() >> 32;

// 	bpf_ringbuf_submit(open_event, 0);
// 	return 0;
// }

SEC("fentry/close_fd")
int BPF_PROG(close_fd, unsigned int fd) {
	struct event *close_event;
	close_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!close_event) {
		bpf_printk("sys_open failed, ret = %ld\n", fd);
		return 0;
	}

	char buf_path[MAX_PATH_LEN];
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	// struct file **fds        = task->files->fdt->fd;
	struct file **fds = BPF_CORE_READ(task, files, fdt, fd);
	struct file *f    = NULL;
	bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]);
	const unsigned char *dname = BPF_CORE_READ(f, f_path.dentry, d_name.name);
	bpf_printk("dname: %s", dname);

	bpf_get_current_comm(&close_event->comm, TASK_COMM_LEN);

	close_event->sys_call_enum = SYS_CLOSE;
	close_event->fd            = fd;
	close_event->pid           = bpf_get_current_pid_tgid() >> 32;

	bpf_ringbuf_submit(close_event, 0);

	return 0;
}
