// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package xebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfDNSA_record struct {
	IpAddr struct{ S_addr uint32 }
	Ttl    uint32
}

type BpfDNSDnsQueryHdr struct {
	Qtype  uint16
	Qclass uint16
	Name   [256]int8
}

// LoadBpfDNS returns the embedded CollectionSpec for BpfDNS.
func LoadBpfDNS() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfDNSBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load BpfDNS: %w", err)
	}

	return spec, err
}

// LoadBpfDNSObjects loads BpfDNS and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfDNSObjects
//	*BpfDNSPrograms
//	*BpfDNSMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfDNSObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpfDNS()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfDNSSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfDNSSpecs struct {
	BpfDNSProgramSpecs
	BpfDNSMapSpecs
}

// BpfDNSSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfDNSProgramSpecs struct {
	XdpPass *ebpf.ProgramSpec `ebpf:"xdp_pass"`
	XdpTx   *ebpf.ProgramSpec `ebpf:"xdp_tx"`
}

// BpfDNSMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfDNSMapSpecs struct {
	NameMaps   *ebpf.MapSpec `ebpf:"name_maps"`
	ProgJumps1 *ebpf.MapSpec `ebpf:"prog_jumps1"`
	ProgJumps2 *ebpf.MapSpec `ebpf:"prog_jumps2"`
	ProgJumps3 *ebpf.MapSpec `ebpf:"prog_jumps3"`
}

// BpfDNSObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfDNSObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfDNSObjects struct {
	BpfDNSPrograms
	BpfDNSMaps
}

func (o *BpfDNSObjects) Close() error {
	return _BpfDNSClose(
		&o.BpfDNSPrograms,
		&o.BpfDNSMaps,
	)
}

// BpfDNSMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfDNSObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfDNSMaps struct {
	NameMaps   *ebpf.Map `ebpf:"name_maps"`
	ProgJumps1 *ebpf.Map `ebpf:"prog_jumps1"`
	ProgJumps2 *ebpf.Map `ebpf:"prog_jumps2"`
	ProgJumps3 *ebpf.Map `ebpf:"prog_jumps3"`
}

func (m *BpfDNSMaps) Close() error {
	return _BpfDNSClose(
		m.NameMaps,
		m.ProgJumps1,
		m.ProgJumps2,
		m.ProgJumps3,
	)
}

// BpfDNSPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfDNSObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfDNSPrograms struct {
	XdpPass *ebpf.Program `ebpf:"xdp_pass"`
	XdpTx   *ebpf.Program `ebpf:"xdp_tx"`
}

func (p *BpfDNSPrograms) Close() error {
	return _BpfDNSClose(
		p.XdpPass,
		p.XdpTx,
	)
}

func _BpfDNSClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpfdns_bpfeb.o
var _BpfDNSBytes []byte
