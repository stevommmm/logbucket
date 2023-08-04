package main

import (
	"bufio"
	"net"
)

type bConn struct {
	r *bufio.Reader
	net.Conn
}

func newbConn(c net.Conn) *bConn {
	return &bConn{
		bufio.NewReaderSize(c, 1),
		c,
	}
}

func (b bConn) FirstByte() ([]byte, error) {
	return b.r.Peek(1)
}

func (b bConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
