TARGET=detector

.PHONY: all
all: bpf_bpfel.go
	go build

bpf_bpfel.go: fentry.c
	go generate

fentry.o: fentry.c
	clang -O2 -g -target bpf -c -o fentry.o fentry.c

.PHONY: run
run: all
	sudo ./${TARGET}

.PHONY: dump
dump: fentry.o
	llvm-objdump -S fentry.o

.PHONY: load
load: fentry.o
	sudo bpftool prog load fentry.o /sys/fs/bpf/my_program -d

.PHONY: cat
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
