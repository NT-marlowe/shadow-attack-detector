package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf fentry.c -- -I../headers
