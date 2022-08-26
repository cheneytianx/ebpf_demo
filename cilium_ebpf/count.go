package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate bpf2go -cc clang -cflags -O2 -target bpfel count ./count.bpf.c
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to unlock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	// defined in *_bpfel.go
	objs := countObjects{}
	if err := loadCountObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// attach to xxx
	ops := link.RawTracepointOptions{
		Name: "sys_enter",
		Program: objs.SyscallCount,
	}

	rtp, err := link.AttachRawTracepoint(ops)
	if err != nil {
		log.Fatalf("opening raw_tracepoint: %s", err)
	}

	log.Printf("Successfully started!\n")

	// Wait for a signal and close the eBPF prog
	<-stopper
	fmt.Println()
	rtp.Close()

	var key [16]byte
	var val uint32
	mapIter := objs.Counter.Iterate()

	for mapIter.Next(&key, &val) {
		fmt.Println(string(key[:]), val)
	}
}
