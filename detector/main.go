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
	// link1, err := link.AttachTracing(link.TracingOptions{Program: objs.bpfPrograms.CloseFd})
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer link1.Close()

	link2, err := link.AttachTracing(link.TracingOptions{Program: objs.bpfPrograms.DoSysOepnatExit})
	if err != nil {
		log.Fatal(err)
	}
	defer link2.Close()

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

	mapFdPid := make(Map2Dim[uint32, uint32, bool])

	log.Printf("%-16s %-16s %-16s %-10s",
		"Comm",
		"Sys",
		"Fd",
		"Pid",
	)

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				log.Printf("Total number of fds opened: %d", len(mapFdPid))
				log.Printf("Total number of entries in map: %d", mapFdPid.CountAllElements())
				return
			}
			log.Printf("Reading from ringbuff: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		fd := event.Fd
		pid := event.Pid

		if _, ok := mapFdPid[fd]; !ok {
			mapFdPid[fd] = make(map[uint32]bool)
			mapFdPid[fd][pid] = true
			log.Printf("New fd opened, num of fds: %d", len(mapFdPid))
		} else {
			log.Printf("Already opened fd, num of pids: %d", len(mapFdPid[fd]))
		}

		log.Printf("%-16s %-16s %-16d %-10d",
			convertBytesToString(event.Comm[:]),
			getSysCallName(event.SysCallEnum),
			fd,
			pid,
		)

	}

}
