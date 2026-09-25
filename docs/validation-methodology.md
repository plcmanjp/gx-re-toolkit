# Validation methodology

[English](validation-methodology.md) | [한국어](validation-methodology-ko.md)

Keep validation layers separate rather than adding them together.

1. Public synthetic tests: regressions using small, independently generated
   inputs and error conditions.
2. Private conformance: binds fixed public-wheel hashes to original authoritative
   inputs.
3. GUI lifecycle: save, reopen, rebuild, and export evidence from separately
   approved project copies.
4. Field acceptance: equipment-specific safety and operational validation, not a
   result of this repository's tests.

Preserve original test denominators, byte oracles, failures, and reasons for SKIP.
Do not make tests pass by replacing expected results with current implementation
outputs. List packaging metadata differences separately; block regressions in
opcodes, operands, radix, ordering, unknown cases, and findings.

Use normal wheel installs and check import origins, CLIs, and resources outside
the source checkout. Do not hide installation omissions with editable installs
or PYTHONPATH. `tools/build_artifacts.py` reads only a clean commit and builds
wheels/sdists in new external staging. Parser provenance is pinned only in built
resources; the runtime does not search parent Git repositories.
Repeated builds in the same environment compare both original artifact hashes
and archive-member hashes. Do not claim bit-identical results when metadata such
as compression timestamps differs.

The CI build environment uses `requirements-build.txt` with exact versions and
hashes, including transitive tools and platform markers. This is separate from
product runtime dependencies in package metadata. Windows checks the complete
installed toolchain on Python 3.12/3.13. Linux checks installed FX5/R read-only
packages and CLIs on the same versions; Windows COM writing is not tested there.
The Python Action pins use Node 24 and require a compatible hosted runner.

Metadata XML is limited to 1 MiB, 10,000 nodes and depth 64; DTD and entity
declarations are rejected. GXW OLE inputs are limited to 512 MiB per outer
container, 10,000 streams, 256 MiB per stream and 512 MiB in declared aggregate
stream bytes. Every stream read checks actual against declared length. A limit
failure is a rejected input, not partial acceptance. See
[contract evolution](contract-evolution.md) for future schema and attestation
decisions.
