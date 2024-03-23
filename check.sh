#!/bin/bash

# Linux kernel version 5.7 or later, for bpf_link support
uname -r

# LLVM 11 or later 1 (clang and llvm-strip)
clang --version
llvm-strip --version


# libbpf headers
dpkg -l | grep libbpf

# Linux kernel headers 3
dpkg -l | grep linux-headers-$(uname -r)

# Go compiler version supported by ebpf-go's Go module
go version
