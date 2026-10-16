# GXW operand access and range boundaries

This read-only projection adds manual-derived roles for the exact opcode
spellings below. It preserves raw operands, occurrence identities, the existing
IR schema/version and the legacy `dest_index` implementation. Opcode recognition
does not establish full CPU capability, valid parameter combinations, execution,
or complete source-project decoding. No P variants are generated automatically.

## Common instructions

Source: [MELSEC-Q/L Common Instruction manual SH-080809ENG-X](https://dl.mitsubishielectric.com/dl/fa/document/manual/plc/sh080809eng/sh080809engx.pdf).
The reviewed PDF SHA-256 supplied by the Director is
`382a11116044f96635fa3f7a210f4ccf645a7d1126e6d2db49edbb8695eaaafd`.
Pages below are physical PDF pages; printed page = PDF page minus two.
R/W/B mean read/write/both. Widths are words unless explicitly bits or strings.

| Opcode | Operands in order: role/span | PDF page |
| --- | --- | --- |
| SUM | S R/1; D W/1 | 425 |
| SEG | S R/1; D W/1 | 431 |
| SER | S1 keyword R/1; S2 array R/n; D W/2; n R/1 | 422–423 |
| UNI | S R/n; D W/1; n R/1; static n only 1..4 | 435 |
| WSUM | S R/n; D W/2; n R/1 | 452 |
| DBCD | S R/2; D W/2 | 273 |
| DXOR, two operands | S R/2; D B/2 | 373 |
| DXOR, three operands | S1 R/2; S2 R/2; D W/2 | 375 |
| DZCP | S1 R/2; S2 R/2; S3 R/2; D W/3 consecutive bits | 214 |
| $+, two operands | S R/string; D B/string | 266 |
| $+, three operands | S1 R/string; S2 R/string; D W/string | 268 |
| LEN | S R/string; D W/1 | 553 |
| SORT | S1 B/n; n R/1; S2 R/1; D1 W/1 bit; D2 unknown/2-word workspace | 448–449 |

SORT's reserved D2 footprint does not prove read/write access. Its access remains
unknown with `RESERVED_WORKSPACE_ACCESS_UNVERIFIED`. SER's keyword and array
operands are distinct; their roles must not be reversed.

Static count spans require positive plain decimal K integers. H constants,
indexed K and device counts remain dynamic. Zero/negative counts and UNI counts
outside 1..4 produce unknown counted spans: no nonempty range is inferred for
no-processing cases. Fixed footprints describe potential operands, not proof
that a no-op instruction read or wrote them. Existing address-count limits apply;
over-limit spans are not truncated into apparently complete ranges.

New fixed/count word spans require direct word devices. Bare-bit multiword,
word-bit and digit-grouped forms are unverified. Existing SUM grouped-bit source
handling is retained, including K4M expanding to 16 bit addresses. Indexed and
indirect address handling remains dynamic. String device spans are dynamic with
no address list and no invented one-word width: runtime NUL length is unknown.
Non-device literals/constants retain not-applicable memory coverage.

## Q built-in Ethernet sockets

Source: [Ethernet manual SH-080811ENG-X](https://www.mitsubishielectric.com/dl/fa/document/manual/plc/sh080811eng/sh080811engx.pdf),
sections 7.4.1/2/3/5, printed pages 108–109, 112, 115–116 and 122–123.
All socket roles/ranges require the Q profile, exact first token `U0` recognized
as the contextual dummy literal, and complete arity. Other contexts are unknown.

| Opcode | Arity | Dummy | n | Control | Payload | Completion |
| --- | --- | --- | --- | --- | --- | --- |
| SP.SOCOPEN | 4 | R | R/1 | B/unknown | — | W/2 bits |
| SP.SOCCLOSE | 4 | R | R/1 | W/unknown | — | W/2 bits |
| SP.SOCRCV | 5 | R | R/1 | W/unknown | W/dynamic | W/2 bits |
| SP.SOCSND | 5 | R | R/1 | W/unknown | R/dynamic | W/2 bits |

Control blocks remain `UNKNOWN` with `RESERVED_OR_MIXED_CONTROL_BLOCK`, including
indexed controls. Reserved/mixed words are not all projected as accessed.
Payload lengths are runtime-dependent; no one-word payload is invented.
Completion and DZCP result spans currently use only observed M-family consecutive bit addresses,
`word_width=null`, and `BIT_RESULT_SPAN`. Word, word-bit, grouped and non-device
destinations remain unknown. Other bit families, including T/ST/C, remain
`BIT_RESULT_FORM_UNVERIFIED`; this is a reader evidence limit, not a declaration
that a CPU prohibits those forms. Indexed/indirect M destinations remain dynamic.

## Reporting limits

Wrong arity for these recognized spellings yields unknown access and ranges,
without legacy destination fallback. Wrong-arity/context instruction diagnostics
include POU, source store, row locator and reason, including empty operand lists.
Non-device write/both targets yield unknown access and range with
`MINED_WRITE_TARGET_UNVERIFIED`; read constants/literals retain their previous
classification and not-applicable memory coverage.
Analysis stays PARTIAL when any range is dynamic, unknown, or limit-reached,
regardless of operand kind, even if all explicit roles are known.
Existing operand coverage counters retain their original denominator/meaning.

Only explicit operands are enumerated. Implicit flags, including SER SM702,
SORT SM703 and operation-error flags, are outside this projection. Synthetic
tests verify these boundaries; they do not replace the Director's full-manual
review, archive corpus validation, engineering-software or PLC acceptance.
