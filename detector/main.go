package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// AttachTracing links a tracing (fentry/fexit/fmod_ret) BPF program or a
	// BTF-powered raw tracepoint (tp_btf) BPF Program to a BPF hook defined in kernel modules.
	link, err := link.AttachTracing(link.TracingOptions{Program: objs.bpfPrograms.SysOpenat})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("Closing ringbuff reader: %v", err)
		}
	}()

	log.Printf("%-16s %-15s",
		"Comm",
		"Fd",
	)

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				return
			}
			log.Printf("Reading from ringbuff: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		log.Printf("%-16s %-15v",
			event.Comm,
			event.Fd,
		)
	}

}
