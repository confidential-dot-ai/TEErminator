package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

func TestStatusExitCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	reachable := config.Remote{Local: "127.0.0.1:8080", Remote: ts.URL + "/"}
	broken := config.Remote{Local: "127.0.0.1:8081", Remote: "://bad"}

	tests := []struct {
		name    string
		remotes []config.Remote
		wantErr string
	}{
		{"no remote Failed", []config.Remote{reachable}, ""},
		{"one remote Failed", []config.Remote{reachable, broken}, "1 of 2 remotes Failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			writeConfig(t, config.Config{Remotes: tc.remotes})
			cmd := newStatusCmd()
			cmd.SetArgs([]string{"--timeout", "5s"})
			err := cmd.Execute()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("status = %v, want a zero exit", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("status = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
