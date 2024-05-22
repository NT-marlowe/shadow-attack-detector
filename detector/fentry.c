//go:build ignore

#include <bpf/bpf_core_read.h>

#include "./headers/common.h"

#include "./headers/bpf_endian.h"
#include "./headers/bpf_tracing.h"

#include "./headers/vmlinux.h"

#define MAX_PATH_LEN 512
#define TASK_COMM_LEN 16
#define DNAME_LEN 64

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

struct event {
	unsigned char comm[TASK_COMM_LEN];
	u8 path[MAX_PATH_LEN];
	u8 syscall_id;
	u32 pid;
};
struct event *unused __attribute__((unused));

static inline void read_path_and_write_buf(const u32 fd, enum syscall_id id) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct file **fds        = BPF_CORE_READ(task, files, fdt, fd);
	struct file *f           = NULL;
	bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]);
	struct dentry *dentry = BPF_CORE_READ(f, f_path.dentry);
	struct dentry *parent = NULL;

	struct event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!event) {
		bpf_printk("sys_open failed, fd = %ld\n", fd);
	} else {
		bpf_get_current_comm(&event->comm, TASK_COMM_LEN);
		event->syscall_id = id;
		event->pid        = bpf_get_current_pid_tgid() >> 32;

		u16 length = 0;
		for (uint i = 0; i < 10; i++) {
			const unsigned char *dname = BPF_CORE_READ(dentry, d_name.name);
			const u32 hash             = BPF_CORE_READ(dentry, d_name.hash);
			bpf_printk("dname: %s, hash: %u", dname, hash);

			if (length < MAX_PATH_LEN - DNAME_LEN - 1) {
				int tmp_len = bpf_probe_read_kernel_str(
					event->path + length, DNAME_LEN, dname);
				if (tmp_len > 0) {
					length += tmp_len;
				}
			}

			parent = BPF_CORE_READ(dentry, d_parent);
			if (parent == dentry) {
				break;
			}
			dentry = parent;
		}
		bpf_printk("--------------------------------");

		bpf_ringbuf_submit(event, 0);
	}
}

SEC("fexit/do_sys_openat2")
int BPF_PROG(do_sys_oepnat_exit, int dfd, const char *filename,
	struct open_how *how, long ret) {
	if (ret < 0) {
		bpf_printk("sys_open failed, ret = %ld\n", ret);
		return 0;
	}

	const u32 fd = ret;

	read_path_and_write_buf(fd, OPEN);
	return 0;
}

// SEC("fentry/close_fd")
// int BPF_PROG(close_fd, unsigned int fd) {
// 	struct event *close_event;
// 	close_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
// 	if (!close_event) {
// 		bpf_printk("sys_open failed, ret = %ld\n", fd);
// 		return 0;
// 	}

// 	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
// 	struct file **fds        = BPF_CORE_READ(task, files, fdt, fd);
// 	struct file *f           = NULL;
// 	bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]);
// 	// const unsigned char *dname = BPF_CORE_READ(f, f_path.dentry,
// 	// d_name.name); bpf_printk("dname: %s", dname);
// 	struct dentry *dentry = BPF_CORE_READ(f, f_path.dentry);

// 	uint length = 0;
// 	for (uint i = 0; i < 10; i++) {
// 		const unsigned char *dname = BPF_CORE_READ(dentry, d_name.name);
// 		const u32 hash             = BPF_CORE_READ(dentry, d_name.hash);
// 		// char tmp[10];
// 		// uint tmp_len = bpf_probe_read_kernel_str(tmp, sizeof(tmp), dname);
// 		// if (length + tmp_len >= MAX_PATH_LEN) {
// 		// 	break;
// 		// }
// 		bpf_printk("dname: %s, hash: %u", dname, hash);
// 		// if (buf > 0 && tmp > 0) {
// 		// bpf_probe_read_kernel(buf + length, tmp_len, tmp);
// 		// length += tmp_len;
// 		// }
// 		struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
// 		if (parent == dentry) {
// 			break;
// 		}
// 		dentry = parent;
// 	}

// 	bpf_get_current_comm(&close_event->comm, TASK_COMM_LEN);

// close_event->syscall_id = CLOSE;
// 	close_event->fd            = fd;
// 	close_event->pid           = bpf_get_current_pid_tgid() >> 32;

// 	bpf_ringbuf_submit(close_event, 0);

// 	return 0;
// }
