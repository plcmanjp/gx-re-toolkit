# Compatibility boundaries

[English](compatibility-matrix.md) | [한국어](compatibility-matrix-ko.md)

| Package | Specified scope | Outside scope |
|---|---|---|
| gx3-fx5-parser-toolkit 0.4.0 | Validated FX5-family GX3 carriers and Neutral IR 1.0.0 | Claims of support for all FX instructions or languages |
| gx3-r-parser-toolkit 0.2.0 | Current explicit supported profile: R04CPU Ladder with `R04/4097` | Current support claims for other iQ-R CPUs or unvalidated project formats |
| gxw-parser-toolkit 0.1.0 | Existing Q-series GXW reading and bounded candidate writer/encoder | Guaranteed official saving or execution for every CPU/instruction |
| gx-re-lab 0.1.0 | Research queries, comparison, census, and planning for fixed inputs | Official lifecycle collection and product acceptance |

The R toolkit's project scope is read-only analysis across the MELSEC iQ-R
family; the current implementation supports only the R04CPU Ladder profile
identified above. Its detector reports other explicit Unit/UnitId pairs as
`UNSUPPORTED`, and missing or ambiguous identity evidence as `AMBIGUOUS`.
The current profile identifier remains `mitsubishi.gx3.r04cpu.ladder`.
Broader iQ-R coverage is a development direction, not a current compatibility
guarantee. See [project direction](../README.md#project-direction).

The exact FX5 detector tuples are `(FX5U, 528)`, `(FX5UJ, 529)`, and
`(FX5S, 530)`. FX5UC is limited to the validated scope sharing the FX5U tuple;
a separate identity is not inferred. A matching tuple does not establish complete
decoding of a project or approval for target conversion.

FX5 and R schemas are separate resources even when their versions and embedded
identifiers match. Select the specified profile from its owning package; do not
fall back across profiles. The FX5 finding
`SOURCE_GLOBAL_ORDER_NOT_SERIALIZED` is not allowed for R.

GXW reading uses `olefile`; Windows file writing/encoding uses `pywin32`.
GXW reference IR recognizes direct `K1`..`K8` grouped bit-device operands and
lists their `4n` bit addresses. Indexed/indirect operands and grouped block
spans remain unresolved. This research projection does not approve a target
CPU address range or product conversion.
Using the Windows storage API does not authorize GX GUI execution or PLC access.
Some original CLIs return usage code 1 rather than success code 0 for help.

## GXW reader boundaries

For the recognized counted COMMENT format, `device_comment_pairs` binds declared
device ranges to length-delimited UTF-16 text, including uppercase, numeric,
empty, and multiline comments. Its typed word-bit section preserves the explicit
device family, module, word address, and bit index. Unknown device types,
duplicate addresses, and incomplete counted records are rejected.
`device_comment_map` and `COMMENT.csv` omit empty comments; use
`device_comment_pairs` when those entries matter.

The reader recognizes the observed non-pulse `DFMOV` header `05 4c 05 0e 05`
followed by exactly three complete operand frames. Malformed, truncated, or
extra-operand forms retain the unknown-instruction marker `<i:05:4c:0e>` instead
of being emitted as `DFMOV`. This describes the source-reader frame boundary;
it does not expand the writer or CPU compatibility scope.
