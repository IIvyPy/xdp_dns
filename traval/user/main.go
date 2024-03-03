package main

import (
	"fmt"
	"log"
	"net"
	xebpf "xdp_travel/kernel"

	"github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	XDP_PASS uint32 = 0
	XDP_TX   uint32 = 1
	XDP_TEST uint32 = 2
)

var (
	objs xebpf.BpfDNSObjects
	err  error
)

func main() {
	fmt.Println("hello world")

	iface, err := net.InterfaceByName("enp0s3")
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", "enp0s3", err)
	}

	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}

	if err1 := loadObjects(); err1 != nil {
		fmt.Println("load objects error, error is ", err1)
	}

	defer closeObjects()

	// // set XDP_PASS
	// progFD := int32(objs.XdpPass.FD())
	// if err = objs.ProgJumps1.Put(XDP_PASS, &progFD); err != nil {
	// 	fmt.Printf("ProgJumps1.Put; err: %s", err.Error())
	// }

	// set XDP_TX
	progFD := int32(objs.XdpTx.FD())
	if err = objs.ProgJumps.Put(XDP_TX, &progFD); err != nil {
		fmt.Printf("ProgJumps.Put xdp tx err: %s", err.Error())
	}

	progFD = int32(objs.XdpTest.FD())
	if err = objs.ProgJumps.Put(XDP_TEST, &progFD); err != nil {
		fmt.Printf("ProgJumps.Put xdp test err: %s", err.Error())
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPass,
		Interface: iface.Index,
	})
	if err != nil {
		fmt.Printf("link.AttachXDP; err: %s", err.Error())
	}
	fmt.Println("link.AttachXDP", iface.Index)
	defer l.Close()

	select {}
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
