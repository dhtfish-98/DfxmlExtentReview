# DfxmlExtentReview

Checks inconsistent exported forensic mappings; unsupported namespace extensions/facets/digests remain OPEN rather than being interpreted as verified evidence.

## Supported project scope

DFXML 1.x namespaced fileobject declaration checks: bounded XML elements/depth, entity/DTD rejection, singleton fields, bounded filesize/extents with overlap checks and hash declaration shapes.

This repository implements that entire selected standalone scope. It does not claim that the original upstream platform has been rewritten in full.

## Use

```sh
python -m pip install .
dfxmlextentreview examples/valid.bin
```

Supply one local regular file. No symlinks or automatic artifact discovery are accepted. The CLI prints JSON; exit 0 means supported checks completed, exit 1 means a structural failure, and exit 2 means unsupported/incomplete analysis. Each successful read includes the input SHA-256 and byte count. Paths, contents, report messages and identities are suppressed. The input is never modified.

## Explicit limits and boundaries

Input limit: 16 MiB. Record limit: 100,000. Additional format-specific limits are enforced in the source.

Excluded capabilities: Full XSD conformance, all schema features, evidence acquisition/hashing, provenance authentication and external resolution.

PASS only describes the recorded checks. It does not prove real-world safety, historical activity, authenticity, applicant contribution or CVP approval. CVP application suitability/qualification remains OPEN until the applicant supplies the real authorized work, relevant restriction evidence and identity/organization facts.

## Provenance and validation

See [ORIGIN.md](ORIGIN.md), [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json), [VALIDATION.md](VALIDATION.md) and the preserved [LICENSE](LICENSE).
