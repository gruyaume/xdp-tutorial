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
		Program:   objs.PassPrograms.Router,
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

type XDPAction uint32

const (
	XDP_ABORTED XDPAction = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

func (objs PassObjects) GetBytesNumber(action XDPAction) (uint64, error) {
	var value PassDatarec
	err := objs.XdpStatsMap.Lookup(uint32(action), &value)
	if err != nil {
		return 0, fmt.Errorf("failed to lookup map: %s", err)
	}
	return value.Bytes, nil
}

func (objs PassObjects) GetPacketsNumber(action XDPAction) (uint64, error) {
	var value PassDatarec
	err := objs.XdpStatsMap.Lookup(uint32(action), &value)
	if err != nil {
		return 0, fmt.Errorf("failed to lookup map: %s", err)
	}
	return value.Packets, nil
}
