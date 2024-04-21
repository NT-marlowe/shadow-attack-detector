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

	link1, err := link.AttachTracing(link.TracingOptions{Program: objs.bpfPrograms.CloseFd})
	if err != nil {
		log.Fatal(err)
	}
	defer link1.Close()

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

	log.Printf("%-16s %-16s %-16s %-10s",
		"Comm",
		"Sys",
		"Fd",
		"Pid",
	)

	mapFdPid := make(Map2Dim[uint32, uint32, bool])
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

		if !mapFdPid.HasKey1(fd) {
			mapFdPid[fd] = make(map[uint32]bool)
			mapFdPid[fd][pid] = true
			log.Printf("New fd opened, num of fds: %d", len(mapFdPid))
		} else if !mapFdPid.HasKey2(fd, pid) {
			log.Printf("Already opened fd, num of pids: %d", len(mapFdPid[fd]))
		}
		// This block means that the same pid handles the same fd.
		// Therefore that process is regarded as legitimate.

		log.Printf("%-16s %-16s %-16d %-10d",
			convertBytesToString(event.Comm[:]),
			getSysCallName(event.SysCallEnum),
			fd,
			pid,
		)

	}

}
