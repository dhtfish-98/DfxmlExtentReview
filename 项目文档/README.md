> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# DfxmlExtentReview

New implementation author: **dhtfish98**. Current package version: **1.0.2**.

Checks inconsistent exported forensic mappings; unsupported namespace extensions/facets/digests remain OPEN rather than being interpreted as verified evidence.

## Supported project scope

DFXML 1.x namespaced fileobject declaration checks: bounded XML elements/depth, entity/DTD rejection, singleton fields, bounded filesize/extents with overlap checks and hash declaration shapes.

This repository implements that entire selected standalone scope. It does not claim that the original upstream platform has been rewritten in full.

## Use

```sh
python -m pip install .
dfxmlextentreview examples/valid.bin
```

Supply one local regular file. The file CLI requires OS `O_NOFOLLOW` and `O_NONBLOCK` support; missing safety flags return OPEN before opening the path. This file-reader contract was verified on macOS/Linux; native Windows file reading is outside the validated profile. No symlinks or automatic artifact discovery are accepted. The CLI prints JSON; exit 0 means supported checks completed, exit 1 means a structural failure, and exit 2 means unsupported/incomplete analysis. Each successful read includes the input SHA-256 and byte count. Paths, contents, report messages and identities are suppressed. The input is never modified.

## Explicit limits and boundaries

XML transport is UTF-8 only, optionally with a UTF-8 BOM. Decoded NUL is rejected before parsing, preventing alternate UTF-16/32 transport from bypassing the DTD/entity guard. Non-UTF8 encoding declarations remain OPEN. DTD and entity declarations are forbidden.

The selected numeric profile requires declared sizes, offsets, lengths and computed exclusive extent ends to be below `2**63`, including image/filesystem coordinates. This is a tool range limit; the upstream XSD nonnegative-integer type itself is unbounded. Selected filesize/hashdigest values must be scalar leaf content. Unknown attributes and namespace extensions remain OPEN.

Input limit: 16 MiB. Record limit: 100,000. Additional format-specific limits are enforced in the source.

Excluded capabilities: Full XSD conformance, all schema features, evidence acquisition/hashing, provenance authentication and external resolution.

PASS only describes the recorded checks. It does not prove real-world safety, historical activity, authenticity, applicant contribution or CVP approval. CVP application suitability/qualification remains OPEN until the applicant supplies the real authorized work, relevant restriction evidence and identity/organization facts.

## Provenance and validation

See [ORIGIN.md](<ORIGIN.md>), [SOURCE_MANIFEST.json](<../SOURCE_MANIFEST.json>), [VALIDATION.md](<VALIDATION.md>) and the preserved [LICENSE](<LICENSE>).
