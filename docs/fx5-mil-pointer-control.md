# FX5 MIL pointer-control syntax

The read-only FX5 decoder recognizes the exact non-pulse `CALL` carrier with
one `p`-typed `d{s=#:a=<nonnegative decimal>:vt=nn}` operand and a `P` descriptor.
The matching `Pointer` carrier uses `op=m`, not a coil operation. It is projected
as an instruction row whose mnemonic is `P<ordinal>` and has no operand, matching
the source IL declaration. `FEND` and `RET` accept the complete operand-free
`mc{op=cl{op=#:ct=a}}` carrier. No schema or generic scalar-device rule changes.

These exact signatures are separate from operand-generalized opcode mappings.
The complete control record is validated before rendering. Unobserved pulse,
width, tag, arity, raw metadata, negative ordinal and extra-field variants remain
`MINING_REQUIRED`; an undecoded member still preserves the block as opaque.
`CJ`, interrupt declarations, local-label calls and LDDB pointer-control grammar
are not added. Existing END handling is unchanged.

The tests construct synthetic ZIP/SQLite carriers in disposable directories.
They check full order, StepInfo widths, continuation attachment, installed CLI
coverage and fail-closed variants. No private project or official export is
included. Stored syntax recognition does not validate pointer allocation,
CPU address limits, call-target resolution, reachable control flow, official
GX import, simulator behavior or physical PLC operation. Private conformance
and consumer adoption remain separate gates.
