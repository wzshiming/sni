package sni

import (
	"bufio"
	"bytes"
	"io"
	"sync"
)

// HTTPHost returns the host from the HTTP header.
func HTTPHost(r io.Reader) (string, error) {
	return getHTTPHeader(r, []byte("host"))
}

// getHTTPHeader returns the value of the first header with the given name.
func getHTTPHeader(r io.Reader, key []byte) (string, error) {
	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(r)
	defer func() {
		reader.Reset(nil)
		readerPool.Put(reader)
	}()

	_, _, err := reader.ReadLine() // skip the first line
	if err != nil {
		return "", err
	}
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		// check for the end of the headers
		if len(line) == 0 {
			return "", ErrNotFound
		}

		// check for the key
		if len(line) <= len(key) {
			continue
		}
		if line[len(key)] != ':' {
			continue
		}
		if !bytes.Equal(bytes.ToLower(line[:len(key)]), key) {
			continue
		}

		host := bytes.TrimSpace(line[len(key)+1:])
		if len(host) == 0 {
			return "", ErrNotFound
		}
		return string(host), nil
	}
}

// readerPool is a pool of bufio.Reader.
var readerPool = &sync.Pool{
	New: func() interface{} {
		return bufio.NewReader(nil)
	},
}
