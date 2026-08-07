# Release process

Gatehouse releases use an explicit build, verify, attest, and publish sequence. The release workflow is triggered only by a `v*` tag and uses least-privilege permissions per job.

1. The build job runs formatting, unit, race, vet, Staticcheck, vulnerability, and one-minute fuzz gates. GoReleaser then produces candidates with publishing disabled.
2. The verification job requires exactly the Linux, macOS, and Windows `amd64` and `arm64` archive matrix. `releasecheck` verifies every checksum, rejects missing or unexpected archives, fully reads every required entry, validates each executable's platform and architecture, and runs the executable for the verifier host. ZIP reads include CRC validation. Every archive must also contain a non-empty license, README, policy reference, and example policy.
3. A regression step corrupts a non-first archive and requires validation to fail. The attestation and publication jobs depend on successful verification, so corruption necessarily prevents publication.
4. GitHub generates provenance attestations for the verified archive and checksum digests.
5. The final job creates the public release by uploading the same workflow artifact that passed verification. GoReleaser itself is configured not to publish.

For a local dry run:

```sh
go run github.com/goreleaser/goreleaser/v2@v2.17.1 release --snapshot --clean --skip=publish
go run ./cmd/releasecheck -dist dist
```

Release tags must point to a commit whose required `test`, `race`, `vet`, `staticcheck`, `vulnerability`, `fuzz-smoke`, and `release-validation` checks passed on `main`.
