// This file is not built with TEErminator. It produced allowlist.json and
// vectors.json from authored.json with C8s at commit a06b3d715:
//
//	git -C c8s archive a06b3d715 | tar -x -C /tmp/c8s
//	mkdir /tmp/c8s/cmd/componentsetfixture
//	cp generate.go /tmp/c8s/cmd/componentsetfixture/main.go
//	(cd /tmp/c8s && go run ./cmd/componentsetfixture \
//		$PWD/authored.json $PWD/allowlist.json $PWD/vectors.json)
//
// allowlist.json is allowlist.ParseJSON(authored.json).Canonical();
// vectors.json holds each set's ComponentSet.Digest and the
// armtls.MarshalComponentSetExtension value C8s stamps for it.

// Command componentsetfixture writes TEErminator's component-set fixture:
// the canonical bytes of an authored allowlist with a components section,
// and each set's digest and mesh-leaf extension as C8s computes them.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"slices"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
)

func main() {
	authored, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	al, err := allowlist.ParseJSON(authored)
	if err != nil {
		panic(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[2], canonical, 0o644); err != nil {
		panic(err)
	}
	type set struct {
		Digest       string `json:"digest"`
		ExtensionDER string `json:"extension_der"`
	}
	sum := sha256.Sum256(canonical)
	out := struct {
		AllowlistSHA256 string         `json:"allowlist_sha256"`
		Sets            map[string]set `json:"sets"`
	}{hex.EncodeToString(sum[:]), map[string]set{}}
	for _, version := range slices.Sorted(maps.Keys(al.Components)) {
		digest, err := al.Components[version].Digest()
		if err != nil {
			panic(err)
		}
		ext, err := armtls.MarshalComponentSetExtension(&armtls.ComponentSet{Version: version, Digest: digest})
		if err != nil {
			panic(err)
		}
		out.Sets[version] = set{Digest: "sha256:" + hex.EncodeToString(digest), ExtensionDER: hex.EncodeToString(ext.Value)}
	}
	vectors, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[3], append(vectors, '\n'), 0o644); err != nil {
		panic(err)
	}
}
