package main

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	xebpf "xdp_travel/kernel"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	XDP_PASS uint32 = 0
	XDP_TX   uint32 = 1
)

var (
	objs xebpf.BpfDNSObjects
	err  error
)

func main() {
	fmt.Println("hello world")

	iface, err := net.InterfaceByName("xxx")
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", "enp5s0f1", err)
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPass,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()
	if err1 := loadObjects(); err1 != nil {
		fmt.Println("load objects error, error is ", err1)
	}

	defer closeObjects()

	// set XDP_TX
	proFD := int32(objs.XdpTx.FD())
	if err = objs.ProgJumps1.Put(XDP_TX, &proFD); err != nil {
		fmt.Printf("ProgJumps1.Put; err: %s", err.Error())
	}
}

func loadObjects() error {
	if err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		return fmt.Errorf("setrlimit err: %s", err.Error())
	}

	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}

	return xebpf.LoadBpfDNSObjects(&objs, opts)
}

func closeObjects() error {
	return objs.Close()
}
