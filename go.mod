module github.com/confidential-dot-ai/TEErminator

go 1.25.0

require (
	github.com/confidential-dot-ai/attestation-go v0.0.0-20260618154338-31fa14f0e911
	github.com/google/go-tpm-tools v0.4.9-0.20260522205405-ed0161beaf76
	github.com/quic-go/quic-go v0.60.0
	github.com/spf13/cobra v1.10.2
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260617215616-d522e41e9e74 // indirect
	github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc // indirect
	github.com/google/go-eventlog v0.0.3-0.20260617163629-883cc5652c69 // indirect
	github.com/google/go-sev-guest v0.15.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/go-tpm v0.9.6 // indirect
	github.com/google/logger v1.1.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d => github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843

replace github.com/google/go-tpm-tools v0.4.9 => github.com/google/go-tpm-tools v0.4.5

replace github.com/confidential-dot-ai/attestation-go => github.com/confidential-dot-ai/attestation-go v0.3.1-0.20260717163132-e46e87a62db3
