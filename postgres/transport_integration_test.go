//go:build integration

package scimpostgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

// Adapted from the committed kernel's registration transport fixture. This
// drops only the acknowledgement of the actual SCIM domain COMMIT, never its
// earlier request mapping/reservation commits. Production SQL is unchanged.
type nativeCommitFault struct{ hit atomic.Bool }

func (f *nativeCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &nativeFaultConn{Conn: connection, fault: f}, nil
}

type nativeFaultConn struct {
	net.Conn
	fault    *nativeCommitFault
	mutation atomic.Bool
	pending  []byte
}

func (c *nativeFaultConn) Write(wire []byte) (int, error) {
	if bytes.Contains(wire, []byte("INSERT INTO scim.users(")) {
		c.mutation.Store(true)
	}
	return c.Conn.Write(wire)
}
func (c *nativeFaultConn) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16<<20 {
			return 0, io.ErrUnexpectedEOF
		}
		message := make([]byte, int(size)+1)
		copy(message, header[:])
		if _, err := io.ReadFull(c.Conn, message[5:]); err != nil {
			return 0, err
		}
		if c.mutation.Load() && header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		c.pending = message
	}
	n := copy(destination, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
