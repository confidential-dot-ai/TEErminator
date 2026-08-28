package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// testCAPEM makes a self-signed CA usable as a stored trust anchor.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// freeAddr reserves a listening address and releases it for the daemon to
// claim.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// get fetches url and returns the response body, or an error.
func get(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); err == nil {
		err = closeErr
	}
	return string(body), err
}

// waitForBody polls url until it returns want or the deadline passes.
func waitForBody(t *testing.T, url, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if body, err := get(url); err == nil && body == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s never returned %q", url, want)
}

// TestDaemonReconcile drives the tunnel set through config changes: adding a
// remote starts its tunnel without touching running ones, a trust-store change
// restarts every tunnel, and dropping a remote stops it.
func TestDaemonReconcile(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	d := &daemon{reattest: time.Minute, out: io.Discard, tunnels: make(map[string]runningTunnel)}
	defer d.stopAll()

	local1, local2 := freeAddr(t), freeAddr(t)
	cfg := &config.Config{Remotes: []config.Remote{{Local: local1, Remote: backend.URL}}}
	if err := d.reconcile(t.Context(), cfg, true); err != nil {
		t.Fatal(err)
	}
	waitForBody(t, "http://"+local1, "ok")
	first := d.tunnels[local1].tunnel

	cfg.Remotes = append(cfg.Remotes, config.Remote{Local: local2, Remote: backend.URL})
	if err := d.reconcile(t.Context(), cfg, false); err != nil {
		t.Fatal(err)
	}
	waitForBody(t, "http://"+local2, "ok")
	if d.tunnels[local1].tunnel != first {
		t.Error("adding a remote restarted an unchanged tunnel")
	}

	cfg.Certs = []config.Cert{{Fingerprint: "00", CommonName: "anchor", PEM: testCAPEM(t)}}
	if err := d.reconcile(t.Context(), cfg, false); err != nil {
		t.Fatal(err)
	}
	if d.tunnels[local1].tunnel == first {
		t.Error("trust-store change did not restart the tunnel")
	}
	waitForBody(t, "http://"+local1, "ok")

	cfg.Remotes = cfg.Remotes[:1]
	if err := d.reconcile(t.Context(), cfg, false); err != nil {
		t.Fatal(err)
	}
	if _, err := get("http://" + local2 + "/"); err == nil {
		t.Error("removed remote still serves")
	}
	waitForBody(t, "http://"+local1, "ok")
}

// TestDaemonWatchPicksUpNewRemote covers the live-reload path end to end: a
// remote added to the config file while the daemon runs starts serving after
// a reload (triggered here via the SIGHUP channel; the mtime poll takes the
// same path).
func TestDaemonWatchPicksUpNewRemote(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "teerminator"), 0o700); err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	local1, local2 := freeAddr(t), freeAddr(t)
	cfg := &config.Config{Remotes: []config.Remote{{Local: local1, Remote: backend.URL}}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	d := &daemon{reattest: time.Minute, out: io.Discard, tunnels: make(map[string]runningTunnel)}
	if err := d.reconcile(t.Context(), cfg, true); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	hup := make(chan os.Signal, 1)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		d.watch(ctx, hup)
	}()
	defer func() {
		cancel()
		<-watchDone // watch owns d.tunnels while running
		d.stopAll()
	}()

	// `remote add` in another terminal: rewrite the config file, then reload.
	cfg.Remotes = append(cfg.Remotes, config.Remote{Local: local2, Remote: backend.URL})
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	hup <- syscall.SIGHUP

	waitForBody(t, "http://"+local2, "ok")
	waitForBody(t, "http://"+local1, "ok")
}
