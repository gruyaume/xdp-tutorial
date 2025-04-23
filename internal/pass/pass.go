package pass

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
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

type RouteOpts struct {
	Prefixlen uint32
	Dst       net.IP
	Ifindex   uint32
	Gateway   net.IP
}

func (objs PassObjects) UpdateRoute(opts *RouteOpts) error {
	dst4 := opts.Dst.To4()
	if dst4 == nil {
		return fmt.Errorf("destination is not IPv4: %v", opts.Dst)
	}
	gw4 := opts.Gateway.To4()
	if gw4 == nil {
		return fmt.Errorf("gateway is not IPv4: %v", opts.Gateway)
	}

	key := PassRouteKey{
		Prefixlen: opts.Prefixlen,
		Addr:      binary.BigEndian.Uint32(dst4),
	}
	value := PassNextHop{
		Ifindex: opts.Ifindex,
		Gateway: binary.BigEndian.Uint32(gw4),
	}

	if err := objs.RoutesMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update routes_map entry: %w", err)
	}
	return nil
}

type Route struct {
	Prefixlen uint32
	Dst       net.IP
	Ifindex   uint32
	Gateway   net.IP
}

func (objs PassObjects) ListRoutes() ([]Route, error) {
	routes := make([]Route, 0)
	var key PassRouteKey
	var value PassNextHop
	iterator := objs.RoutesMap.Iterate()
	for iterator.Next(&key, &value) {
		dst := net.IPv4(
			byte(key.Addr>>24),
			byte(key.Addr>>16),
			byte(key.Addr>>8),
			byte(key.Addr),
		)
		gw := net.IPv4(
			byte(value.Gateway>>24),
			byte(value.Gateway>>16),
			byte(value.Gateway>>8),
			byte(value.Gateway),
		)
		routes = append(routes, Route{
			Prefixlen: key.Prefixlen,
			Dst:       dst,
			Ifindex:   value.Ifindex,
			Gateway:   gw,
		})
	}
	return routes, nil
}
