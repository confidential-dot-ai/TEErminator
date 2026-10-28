package verifier

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// maxBundleBytes bounds an attest-lb response body.
const maxBundleBytes = 1 << 20

// tlsDialer dials u's host, at port 443 when u names none, offering HTTP/1.1
// alone: the router binds attest-lb to one connection, so requests must ride
// connections net/http cannot multiplex onto others.
func tlsDialer(u *url.URL, cfg *tls.Config) func(context.Context) (*tls.Conn, error) {
	cfg = cfg.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	dialer := &tls.Dialer{Config: cfg}
	return func(ctx context.Context) (*tls.Conn, error) {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return conn.(*tls.Conn), nil
	}
}

// attestConn runs attest-lb on conn itself, so the router binds conn and the
// verdict covers the serving leaf conn presents. On success conn is ready to
// carry requests.
func (e *EndpointAttester) attestConn(ctx context.Context, conn *tls.Conn) (*SessionVerdict, error) {
	exchange := &connExchange{conn: conn, reader: bufio.NewReader(conn)}
	v, err := e.attest(ctx, exchange.roundTrip)
	if err != nil {
		return nil, err
	}
	if exchange.routerCloses {
		return nil, errors.New("attest-lb: the router closes the connection after the attest-lb response, so it can carry no request")
	}
	return v, nil
}

// connExchange sends requests on one connection and reads each response whole.
type connExchange struct {
	conn         *tls.Conn
	reader       *bufio.Reader
	routerCloses bool // the last response said the router closes the connection
}

func (x *connExchange) roundTrip(req *http.Request) (*http.Response, error) {
	stopInterrupting := context.AfterFunc(req.Context(), x.interrupt)
	resp, err := x.exchange(req)
	if interrupted := !stopInterrupting(); interrupted {
		return nil, context.Cause(req.Context())
	}
	return resp, err
}

// interrupt fails the connection's pending and later reads and writes.
func (x *connExchange) interrupt() {
	_ = x.conn.SetDeadline(time.Unix(1, 0))
}

func (x *connExchange) exchange(req *http.Request) (*http.Response, error) {
	if err := req.Write(x.conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(x.reader, req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > maxBundleBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxBundleBytes)
	}
	x.routerCloses = resp.Close
	state := x.conn.ConnectionState()
	resp.TLS = &state
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}
