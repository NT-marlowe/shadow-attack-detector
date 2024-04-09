TARGET=detector

.PHONY: all
all: bpf_bpfel.go
	go build

bpf_bpfel.go: fentry.c
	go generate

.PHONY: run
run: all
	sudo ./${TARGET}
