package rpc

import (
	"io"
	"regexp"
)

var (
	address0X  = regexp.MustCompile(`"0[X|x]([A-Za-z0-9]{40})"`)
	addressTIT = regexp.MustCompile(`"(?i:tit)([A-Za-z0-9]{40})"`)
)

// ReadWriteCloserWrapper automatically changes address format
type ReadWriteCloserWrapper struct {
	rwc io.ReadWriteCloser
}

func (w *ReadWriteCloserWrapper) Read(p []byte) (n int, err error) {
	n, err = w.rwc.Read(p)
	copy(p, addressTIT.ReplaceAll(p, []byte(`"0x${1}"`)))
	return
}

func (w *ReadWriteCloserWrapper) Write(p []byte) (n int, err error) {
	// p = address0X.ReplaceAll(p, []byte(`"tit${1}"`))
	return w.rwc.Write(p)
}

func (w *ReadWriteCloserWrapper) Close() error {
	return w.rwc.Close()
}
