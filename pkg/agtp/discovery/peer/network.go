// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// NetworkPolicy opts into fixed-address discovery within an explicitly allowed
// network. A nil policy permits only loopback. CIDRs restrict network reachability;
// they do not enroll peers or replace mTLS and ASB authorization.
type NetworkPolicy struct {
	AllowedCIDRs []netip.Prefix
}

func (p *NetworkPolicy) validate() error {
	if p == nil {
		return nil
	}
	if len(p.AllowedCIDRs) == 0 {
		return errors.New("agtp discovery peer: network policy requires allowed CIDRs")
	}
	for _, prefix := range p.AllowedCIDRs {
		if !prefix.IsValid() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return fmt.Errorf("agtp discovery peer: invalid allowed CIDR %q", prefix)
		}
	}
	return nil
}

func (p *NetworkPolicy) clone() *NetworkPolicy {
	if p == nil {
		return nil
	}
	return &NetworkPolicy{AllowedCIDRs: append([]netip.Prefix(nil), p.AllowedCIDRs...)}
}

// validateEndpoint performs no DNS lookup. The loopback profile also accepts
// localhost; the network profile requires canonical IP:port addresses.
func (p *NetworkPolicy) validateEndpoint(address string, allowZeroPort bool) error {
	if err := p.validate(); err != nil {
		return err
	}
	if p == nil {
		host, port, err := net.SplitHostPort(address)
		if err == nil && host == "localhost" {
			value, parseErr := strconv.ParseUint(port, 10, 16)
			if parseErr == nil && address == net.JoinHostPort(host, port) && strconv.FormatUint(value, 10) == port && (value != 0 || allowZeroPort) {
				return nil
			}
			return errors.New("agtp discovery peer: invalid loopback endpoint port")
		}
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || endpoint.String() != address || endpoint.Addr().Zone() != "" {
		return errors.New("agtp discovery peer: endpoint must be a canonical IP:port address")
	}
	if endpoint.Port() == 0 && (p != nil || !allowZeroPort) {
		return errors.New("agtp discovery peer: endpoint requires a nonzero port")
	}
	if !p.allowsIP(endpoint.Addr()) {
		return errors.New("agtp discovery peer: endpoint is outside the allowed network")
	}
	return nil
}

func (p *NetworkPolicy) allowsRemoteAddress(address string) bool {
	if p.validate() != nil {
		return false
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" {
		return false
	}
	return p.allowsIP(endpoint.Addr())
}

func (p *NetworkPolicy) allowsIP(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || !(address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast()) {
		return false
	}
	if p == nil {
		return address.IsLoopback()
	}
	for _, prefix := range p.AllowedCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
