package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
)

// Tunnel is a running TCP proxy that forwards traffic to a remote TLS host.
type Tunnel struct {
	listener net.Listener
	remote   string
	token    string
	done     chan struct{}
}

// Start opens a TCP listener on localAddr and forwards connections to remoteURL.
func Start(localAddr, remoteURL, token string) (*Tunnel, error) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, err
	}
	t := &Tunnel{
		listener: ln,
		remote:   remoteURL,
		token:    token,
		done:     make(chan struct{}),
	}
	go t.serve()
	return t, nil
}

func (t *Tunnel) serve() {
	defer close(t.done)
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		go t.handle(conn)
	}
}

func (t *Tunnel) handle(local net.Conn) {
	defer local.Close()

	u, err := url.Parse(t.remote)
	if err != nil {
		log.Printf("proxy: bad remote URL %q: %v", t.remote, err)
		return
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var remote net.Conn
	if u.Scheme == "https" {
		remote, err = tls.Dial("tcp", host, &tls.Config{ServerName: u.Hostname()})
	} else {
		remote, err = net.Dial("tcp", host)
	}
	if err != nil {
		log.Printf("proxy: dial %s: %v", host, err)
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, local); done <- struct{}{} }()
	go func() { io.Copy(local, remote); done <- struct{}{} }()
	<-done
}

// Stop shuts down the tunnel.
func (t *Tunnel) Stop() error {
	err := t.listener.Close()
	<-t.done
	return err
}
