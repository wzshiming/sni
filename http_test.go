package sni

import (
	"context"
	"net"
	"net/http"
	"testing"
)

func TestHTTPHost(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	want := "example.org"
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		name, err := HTTPHost(conn)
		if err != nil {
			t.Fatal(err)
		}
		if name != want {
			t.Errorf("want %q, got %q", want, name)
		}
		conn.Close()
	}()
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, listener.Addr().String())
			},
		},
	}

	cli.Get("http://" + want)
}
