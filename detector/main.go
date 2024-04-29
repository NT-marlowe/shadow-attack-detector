package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
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

	var event bpfEvent
	mapFdPid := make(Map2Dim[uint32, StringUintKey, bool])
	nonLoopEdgeCount := 0
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

		fd := event.Fd
		pid := event.Pid
		comm := convertBytesToString(event.Comm[:])
		tmpKey := StringUintKey{comm, pid}

		if comm != "open_server" && comm != "close_server" {
			continue
		}

		// log.Println("------------------------------------------------------------")
		// log.Printf("fd = %d, pid = %d", fd, pid)
		if !mapFdPid.HasKey1(fd) {
			mapFdPid[fd] = make(map[StringUintKey]bool)
			mapFdPid[fd][tmpKey] = true
			// log.Printf("New fd %d %s by %s (%d)", fd, getSysCallName(event.SysCallEnum), comm, pid)
			// log.Println("------------------------------------------------------------")

		} else if !mapFdPid.HasKey2(fd, tmpKey) {
			mapFdPid[fd][tmpKey] = true
			nonLoopEdgeCount++
			// log.Printf("Already opened fd, num of pids: %d", len(mapFdPid[fd]))
			log.Printf("Already opened fd %d was %s by %s", fd, getSysCallName(event.SysCallEnum), comm)
			log.Printf("map[%d] = %v", fd, mapFdPid[fd])
			log.Println("------------------------------------------------------------")
		}
		// This block means that the same pid handles the same fd.
		// Therefore that process is regarded as legitimate.

		// log.Printf("%-16s %-16s %-16d %-10d",
		// 	comm,
		// 	getSysCallName(event.SysCallEnum),
		// 	fd,
		// 	pid,
		// )

	}

}
