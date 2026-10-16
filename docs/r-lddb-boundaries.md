# R04 empty-MIL LDDB source boundary

The existing R MIL reader remains the primary source path. A separate bounded
LDDB path applies only to an existing, readable MIL table with the required
id/pos/data columns and exactly zero rows. MIL, T_Block, T_Step and LadderBlocks
must be real SQLite tables; same-name views (including empty WHERE 0 views) are
rejected. Nonempty, partial or mismatched MIL
never selects this fallback. Existing unique-candidate and cross-POU shared-pair
guards remain in force.

The observed program shape is exactly two LadderBlocks: an LD M/OUT M or
LDI M/OUT M two-cell block, followed by one final END. The complete stored string
must match the literal grammar in `lddb.py`: V1 descriptor, contact a/b, M source,
M coil, 2x1 grid, exact cells/operators/types/positions, and no trailing or
multiline content. END must exactly equal `V1:0:end{type=end:dim=1x1}` with
blocktype 5; the contact/coil block has blocktype 0. Additional instructions,
branches, grids, families and encodings remain unmined.

M addresses are unsigned decimal values at most 0xffffffff. This lexical bound
does not assert R04 device capacity or validate the program against a PLC.

StepInfo and LDDB require a whole-block ID bijection without duplicate normalized
IDs. T_Block Pos values are unique, finite and positive; LadderBlocks Pos must
match. T_Step Pos matches its block, ElementIDMacroFB is integer zero, and MilID
is exactly 0/1 for the contact/coil block and 0 for END. Individual StepSize is
1/1 and 2 respectively. T_Block StepSize is integer 2 and equals their sum.
BodyID is a nonnegative integer shared within this POU; multiple bodies are
unobserved. These field values are validated without hardcoding observed IDs
or Pos coordinates. SQLite fields requiring integers are checked as integers.

All blocks and relations are checked before any output record is constructed.
A rejected fallback returns no records plus a source/locator-specific finding;
it cannot return a decoded prefix as successful output. Errors explicitly bind
their source entry, and the finding digest hashes that carrier rather than
always hashing LDDB.
If a source entry is absent, the required digest field is explicitly identified
as the archive digest; no nonexistent carrier SHA is invented.

The parser probes at most one MIL row before full StepInfo/LDDB/MIL payload
materialization. Empty MIL selects the bounded helper, whose table reads are
capped at 10,000 rows and LDDB payloads at 1,024 characters. Candidate discovery
streams block IDs into identity sets, without collecting whole payload rows;
those existing candidate identity sets have no new 10,000-row cap. Nonempty MIL
continues through its existing reader and existing archive limits, without the
new fallback table cap. These are fallback bounds, not a new package-wide row
limit. Connections always close.

Returned records retain the existing Neutral IR schema, sequence and step
fields. Their source_entry/source_store/source_locator identify actual LDDB
LadderBlocks, and source_digest is the archive entry SHA-256. Relation evidence
identifies the independent LDDB source path, the empty MIL entry/hash, and
StepInfo block/MilID/StepSize. A source-path finding deliberately keeps POU and
project coverage PARTIAL. Program registration, full program semantics, native
engineering validation and actual PLC execution are not established.

The bounded grammar comes from the Director's official R04 LD/LDI/OUT/END
comparisons. Synthetic boundary tests do not replace the Director's complete
source/hash/export comparisons or field acceptance.
