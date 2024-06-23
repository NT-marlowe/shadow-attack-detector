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

	// linkClose, err := link.AttachTracing(link.TracingOptions{Program: objs.bpfPrograms.CloseFdEntry})
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer linkClose.Close()

	linkOpen, err := link.AttachTracing(link.TracingOptions{Program: objs.bpfPrograms.DoSysOepnatExit})
	if err != nil {
		log.Fatal(err)
	}
	defer linkOpen.Close()

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

	log.Printf("%-16s %-16s %-16s %-10s",
		"Comm",
		"Sys",
		"Pid",
		"Path",
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

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		path := reconstructPath(event.Path[:])
		pid := event.Pid

		log.Printf("%-16s %-16s %-16d %-16s",
			convertBytesToString(event.Comm[:]),
			getSysCallName(event.SyscallId),
			pid,
			path,
		)
	}
}
