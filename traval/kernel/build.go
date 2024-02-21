package xebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go BpfDNS trace.c -- -I./include
