# Contributing

Use Go 1.25, keep runtime code standard-library-only, add focused tests, and preserve stable rule names and exit codes. Before proposing a change, run:

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/gatehouse
```

Commits should be focused and explain why behavior changes. Security reports must follow SECURITY.md.
