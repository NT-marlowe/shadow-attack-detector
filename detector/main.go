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

	// linkClose, err := link.AttachTracing(link.TracingOptions{Program: objs.bpfPrograms.CloseFd})
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
	mapFdPid := make(Map2Dim[uint32, uint32, bool])
	nonLoopEdgeCount := 0

	absolutePath := ""
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				log.Printf("Total number of fds opened: %d", len(mapFdPid))
				log.Printf("Total number of entries in map: %d", mapFdPid.CountAllElements())
				log.Printf("Total number of non-loop edges: %d", nonLoopEdgeCount)
				return
			}
			log.Printf("Reading from ringbuff: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		dname := convertBytesToString(event.Dname[:])
		log.Printf("dname = %s", dname)

		if dname == "/" {
			absolutePath = "/" + absolutePath

			log.Printf("%-16s %-16s %-16d %-s",
				convertBytesToString(event.Comm[:]),
				getSysCallName(event.SyscallId),
				event.Pid,
				absolutePath,
			)
			absolutePath = ""

		} else {
			if absolutePath == "" {
				absolutePath = dname
			} else {
				absolutePath = dname + "/" + absolutePath
			}
		}

		// fd := event.Fd
		// pid := event.Pid

		// log.Println("------------------------------------------------------------")
		// log.Printf("fd = %d, pid = %d", fd, pid)
		// if !mapFdPid.HasKey1(fd) {
		// 	mapFdPid[fd] = make(map[uint32]bool)
		// 	mapFdPid[fd][pid] = true
		// 	log.Printf("New fd opened, num of fds: %d", len(mapFdPid))

		// } else if !mapFdPid.HasKey2(fd, pid) {
		// 	mapFdPid[fd][pid] = true
		// 	nonLoopEdgeCount++
		// 	log.Printf("Already opened fd, num of pids: %d", len(mapFdPid[fd]))
		// 	log.Printf("map[%d] = %v", fd, mapFdPid[fd])
		// }
		// // This block means that the same pid handles the same fd.
		// // Therefore that process is regarded as legitimate.

		// log.Printf("%-16s %-16s %-16d %-10d",
		// 	convertBytesToString(event.Comm[:]),
		// 	getSysCallName(event.SyscallId),
		// 	fd,
		// 	pid,
		// )

	}

}
