package vproto

// VMess UDP outbound support.
//
// A VMess UDP session is a normal VMess connection whose request header uses
// CommandUDP (2) and carries the destination address. Every subsequent
// payload frame corresponds to exactly one UDP datagram, encrypted with the
// same stream cipher (and framing) as TCP. This mirrors sing-vmess's
// clientPacketConn behaviour.

import (
	"net"
)

// DialPacketConn writes a VMess UDP request header to conn and wraps the
// result as a net.PacketConn. The supplied host/port is placed in the
// handshake header; each WriteTo sends one encrypted datagram and each
// ReadFrom receives one. The address passed to WriteTo is ignored (VMess UDP
// is single-destination per session) — use the destination from this call.
func (c *VMessClient) DialPacketConn(conn net.Conn, host string, port uint16) (net.PacketConn, error) {
	nc, err := c.dial(conn, host, port, vmessCmdUDP)
	if err != nil {
		return nil, err
	}
	dest := &net.UDPAddr{Port: int(port)}
	if ip := net.ParseIP(host); ip != nil {
		dest.IP = ip
	} else {
		dest.IP = net.IPv4zero
	}
	return &vmessPacketConn{Conn: nc, dest: dest}, nil
}

type vmessPacketConn struct {
	net.Conn
	dest *net.UDPAddr
}

var _ net.PacketConn = (*vmessPacketConn)(nil)

// ReadFrom returns one decrypted UDP datagram together with the session
// destination recorded in the handshake header.
func (c *vmessPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.dest, err
}

// WriteTo sends p as a single encrypted UDP datagram. addr is ignored; the
// destination was fixed by DialPacketConn.
func (c *vmessPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.Write(p)
}
