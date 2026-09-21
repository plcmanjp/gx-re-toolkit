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
