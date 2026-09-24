# Compatibility boundaries

[English](compatibility-matrix.md) | [한국어](compatibility-matrix-ko.md)

| Package | Specified scope | Outside scope |
|---|---|---|
| gx3-fx5-parser-toolkit 0.4.0 | Validated FX5-family GX3 carriers and Neutral IR 1.0.0 | Claims of support for all FX instructions or languages |
| gx3-r-parser-toolkit 0.2.0 | R04CPU Ladder profile with `R04/4097` | Generalization to all other R CPUs |
| gxw-parser-toolkit 0.1.0 | Existing Q-series GXW reading and bounded candidate writer/encoder | Guaranteed official saving or execution for every CPU/instruction |
| gx-re-lab 0.1.0 | Research queries, comparison, census, and planning for fixed inputs | Official lifecycle collection and product acceptance |

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
