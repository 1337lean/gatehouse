# Gatehouse

Gatehouse is a dependency-free Go CLI that validates release bundles at a CI or deployment boundary. It checks a versioned JSON policy, file checksums and constraints, SBOM structure, and provenance subject binding.

## Install

Requires Go 1.25.

```sh
go install github.com/1337lean/gatehouse/cmd/gatehouse@latest
```

## Quick start

```sh
gatehouse init
gatehouse policy check
gatehouse verify ./release
gatehouse verify --format json ./release
gatehouse verify --format sarif ./release
```

Commands:

- `init [--policy gatehouse.json] [--force]` writes a safe starter policy.
- `policy check [--policy ...] [--format human|json]` validates policy syntax and semantics.
- `verify [--policy ...] [--format human|json|sarif] BUNDLE` validates a directory.
- `version` prints the build version.

Exit codes are stable: `0` success, `1` policy/bundle violation, `2` command usage error, `3` operational/internal error.

## Runnable demos

From the repository root, run the checked-in valid fixture. It exercises complete checksum-manifest coverage, CycloneDX validation, provenance subject SHA-256 binding, required artifact provenance coverage, and typed repository/ref/workflow constraints:

```sh
go run ./cmd/gatehouse verify \
  --policy testdata/demo-policy.json \
  testdata/bundles/valid
```

The intentionally broken fixture produces JSON findings and exits with status `1`. It includes malformed SBOM JSON, files omitted from the checksum manifest, a mismatched provenance subject digest, and incorrect repository/ref/workflow values:

```sh
go run ./cmd/gatehouse verify \
  --policy testdata/demo-policy.json \
  --format json \
  testdata/bundles/broken
```

## Policy

Policy v1 supports `checksums` (SHA-256 manifest), `allowedExtensions`, `deniedExtensions`, `maxFileSize`, `requiredGlobs`, `sbom`, and `provenance`, including explicit `requiredSubjects` coverage. Policy files larger than 1 MiB, unknown or duplicate JSON keys, and unsupported versions are rejected. See [policy reference](docs/policy.md).

The runtime imports only the Go standard library. Gatehouse does not execute bundle content, follow symbolic links, accept other non-regular bundle files, access the network, or trust provenance without independently hashing every declared subject. Bundle access is anchored with `os.Root`; regular-file identity is checked across open operations, artifact hashes are streamed, and checksum/SBOM/provenance metadata reads are bounded.

## Development

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/gatehouse
```

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [security policy](SECURITY.md), and [contributing guide](CONTRIBUTING.md).

## License

MIT
