package pass

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Pass ebpf/pass.c --

type PassProgram struct {
	Link link.Link
	Objs PassObjects
}

func Load(iface *net.Interface) (*PassProgram, error) {
	objs := PassObjects{}
	err := LoadPassObjects(&objs, nil)
	if err != nil {
		return nil, fmt.Errorf("loading objects: %s", err)
	}

	xdpOpts := link.XDPOptions{
		Program:   objs.PassPrograms.Pass,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	}
	l, err := link.AttachXDP(xdpOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP program")
	}
	program := &PassProgram{
		Link: l,
		Objs: objs,
	}
	return program, nil
}

func (objs PassObjects) GetBytesNumber() (uint64, error) {
	var key uint32 = 0
	var value PassDatarec
	err := objs.XdpStatsMap.Lookup(key, &value)
	if err != nil {
		return 0, fmt.Errorf("failed to lookup map: %s", err)
	}
	return value.Bytes, nil
}
