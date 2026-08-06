# Policy reference

A policy is UTF-8 JSON no larger than 1 MiB. Unknown fields, trailing JSON values, unsupported versions, empty/malformed/duplicate globs, and conflicting extensions are rejected. SBOM formats or requirements need at least one `sbom.globs` selector and at least one matching document. Provenance constraints likewise require selectors and at least one matching document; required subjects independently require valid coverage. These rules prevent a configured check from silently selecting nothing.

```json
{
  "version": 1,
  "checksums": "SHA256SUMS",
  "allowedExtensions": [".json", ".md", ".txt"],
  "deniedExtensions": [],
  "maxFileSize": 104857600,
  "requiredGlobs": ["README*"],
  "sbom": {
    "required": true,
    "globs": ["*.cdx.json", "*.spdx.json"],
    "formats": ["cyclonedx", "spdx"]
  },
  "provenance": {
    "required": true,
    "globs": ["*.intoto.jsonl", "provenance.json"],
    "repository": "example/project",
    "ref": "refs/heads/main",
    "workflow": "release.yml",
    "requiredSubjects": ["artifact.json"]
  }
}
```

The checksum manifest uses `sha256sum` syntax: 64 hexadecimal characters, a space, a text/binary marker (` ` or `*`), then a bundle-relative path. Filenames may contain spaces or begin with `*`; CRLF manifests are accepted. Paths are normalized with portable slash semantics; control characters, colons, leading `..` path components, and absolute paths are rejected, while ordinary names such as `..artifact` are accepted. Two entries that normalize to the same path are rejected.

CycloneDX JSON must identify `bomFormat: CycloneDX` and a non-empty string `specVersion`. SPDX JSON must have non-empty string values for `spdxVersion` and `SPDXID`. These checks establish format identity and minimum structure, not full conformance to every revision of either specification.

Provenance is in-toto Statement/SLSA-shaped JSON. Every `subject` must name an existing bundle-relative regular file and supply a matching SHA-256 digest. Repository, ref, and workflow constraints are compared against the typed `predicate.repository`, `predicate.ref`, and `predicate.workflow` string fields; similarly named fields elsewhere do not satisfy them. Duplicate JSON object keys are rejected as ambiguous.

`provenance.requiredSubjects` is an explicit coverage policy. Every listed bundle-relative path must appear as a subject with a valid SHA-256 binding in at least one selected provenance document. `provenance.required` only requires that a selected provenance document exists; use `requiredSubjects` when particular release artifacts must be attested. The demo policy requires coverage of `artifact.json`.

Gatehouse caps bundle traversal at 100,000 filesystem entries and reads at most 16 MiB from each checksum manifest, SBOM, or provenance document. Artifact and provenance-subject SHA-256 values are computed as streams rather than by loading whole artifacts into memory, then cached so repeated provenance subjects cannot amplify hashing work. Files already over `maxFileSize` are reported without being parsed or hashed.
