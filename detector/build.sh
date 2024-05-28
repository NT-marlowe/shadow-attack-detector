#!/bin/sh

sudo docker run --rm -v $(pwd):/workspace -w /workspace my-ebpf-go make all
