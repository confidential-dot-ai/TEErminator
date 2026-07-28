package cmd

import "testing"

func TestDefaultServerName(t *testing.T) {
	tests := []struct {
		name          string
		remoteURL     string
		explicit      string
		want          string
		wantDefaulted bool
	}{
		{"IP remote, no override", "https://100.107.26.45:32123/", "", defaultC8sServerName, true},
		{"IPv6 remote, no override", "https://[2001:db8::1]:443/", "", defaultC8sServerName, true},
		{"DNS remote, no override", "https://api.example.com/v1/", "", "", false},
		{"IP remote, explicit override wins", "https://100.107.26.45:32123/", "lb.internal", "lb.internal", false},
		{"explicit IP override disables the default", "https://100.107.26.45:32123/", "100.107.26.45", "100.107.26.45", false},
		{"unparseable URL", "://bad", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, defaulted := defaultServerName(tc.remoteURL, tc.explicit)
			if got != tc.want || defaulted != tc.wantDefaulted {
				t.Errorf("defaultServerName(%q, %q) = (%q, %v), want (%q, %v)",
					tc.remoteURL, tc.explicit, got, defaulted, tc.want, tc.wantDefaulted)
			}
		})
	}
}
