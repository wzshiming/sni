package sni

import (
	"context"
	"net"
	"net/http"
	"testing"
)

func BenchmarkHTTPHost(b *testing.B) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	want := "example.org"
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			name, err := HTTPHost(conn)
			if err != nil {
				b.Fatal(err)
			}
			if name != want {
				b.Errorf("want %q, got %q", want, name)
			}
			conn.Close()
		}
	}()
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, listener.Addr().String())
			},
		},
	}

	for n := 0; n != b.N; n++ {
		cli.Get("http://" + want)
	}
}

func BenchmarkTLSHost(b *testing.B) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	want := "example.org"
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			name, err := TLSHost(conn)
			if err != nil {
				b.Fatal(err)
			}
			if name != want {
				b.Errorf("want %q, got %q", want, name)
			}
			conn.Close()
		}
	}()
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, listener.Addr().String())
			},
		},
	}

	for n := 0; n != b.N; n++ {
		cli.Get("https://" + want)
	}
}
