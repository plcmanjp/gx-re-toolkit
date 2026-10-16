# Supplemental R QPG observations

`gx3_r_parser_toolkit.pou_details.parse_pou_details(path)` returns an independent
`plcman.gx3.r-pou-details` dictionary, version `1.0.0`. It calls the actual R
parser first, requires its supported R04 profile and unchanged-input flag, then
requires a fresh bounded archive read to have the same SHA-256. It checks the
input digest again before returning. A fatal base parse or changed input raises
`ArchiveError`. It does not modify Neutral IR, the existing parser, or projects.
There is no writer, CLI, GUI or network operation.

## Census and rooted layout

Every archive member with a case-insensitive `.qpg` suffix receives a record,
including unfamiliar filenames and unsupported layouts. Every case-insensitive
`PouLinkOrder.info` basename is inventoried independently. Unmatched links and
unlinked QPG carriers remain explicit. Exact same-parent, correctly cased link
paths are required for the name-context guard.

Only the binary `Program.qpg` root form is interpreted. The reader follows
short fields from the root to an extended indexed directory; it does not search
payload bytes for names. It validates root/file lengths, short-field size/tag
sequence, the extended marker, the two directory counts, unique ordered tags,
bounded nonoverlapping gapless ranges, fixed field lengths, the root separator,
and the trailer identity mirror. All directory entries retain their offsets,
lengths and payload digests, including zero-length entries. Opaque payloads and
the tail are not decoded or treated as complete POU semantics.

The two observed directory forms are deliberately distinct:

| Counts | Name field | Interpretation |
|---|---|---|
|6/5|bounded length-prefixed UTF-16 field|name observation candidate|
|7/4|zero offset and zero length|no name field observed|

The indexed name has an even bounded byte length, a single terminal NUL,
strict UTF-16 decoding, an identifier without control/path characters, and
observed zero padding and terminal tag. Different framing is unknown. The two
variable opaque sections in the named form must have bounded positive lengths
aligned to four bytes; their contents and meanings remain unknown. Other
directory sizes are constrained to the observed form.

A candidate is exposed as `observed_name` only with a valid unique singleton
link inventory entry, no duplicate link ID anywhere in the archive, and exactly
one QPG in that parent directory. Multi-ID, malformed, missing, duplicate or
ambiguous link contexts withhold the name. The directory observation still
remains. This guard reduces ambiguity; it does not prove semantic POU binding.
The unnamed 7/4 form remains a partial structural observation even when unlinked.
Zero field length is a storage observation, not proof of semantic POU absence.

## Budgets and failure behavior

The base archive's input, expansion, member and SQLite checks run first. This
API additionally bounds both QPG and link censuses to 256 carriers each, a QPG
member to 8 MiB, aggregate QPG bytes to 32 MiB, each link to 4096 bytes, directory
entries to 32, and the observed opaque-tail count to 100000. Output is bounded
to 4000000 characters. Archive/census/byte/output budget failures raise without
truncation. Unobserved internal layout, including directory/tail count limits,
produces an unknown carrier record with its source digest and reason. It never
returns a partially decoded name from a failed layout. No opaque tail count is
used to allocate or iterate a count-sized buffer.

## Dictionary contract

Top level: `schema_name`, `schema_version`, `status`, `project_complete`, `input`,
`profile`, `records`, `link_inventory`, `counts`, `findings`. `input` copies the
base parser's digest/byte-count/unchanged evidence. `profile` contains only the
profile ID and detector status. Counts conserve `total = partial + unknown`.

Each record contains:

- `source_entry`, `source_digest`, `byte_count`: exact archive member binding.
- `status`: `PARTIAL` for a valid observed structural form, otherwise `UNKNOWN`.
- `layout_status`: `OBSERVED_FORM` or `UNKNOWN`.
- `root_framing`: directory counts/base/length, root-tail offset, whole length,
  and opaque-tail byte count, observed count, digest and unknown interpretation.
- `directory`: tag, relative/absolute member offset, byte count and digest.
- `name_field_state`: `PRESENT`, `ZERO_LENGTH`, or `UNKNOWN`.
- `observed_name`: `{status: OBSERVED, value: text}` or unknown/null.
- `link_inventory_index`: a reference to the same-parent link, or null.
- `semantic_owner`: always unknown/null.
- `pou_binding`: always unknown/null POU ID.
- `findings`: local framing or link-context reasons.

Offsets are within the uncompressed member, not absolute filesystem paths.
Link inventory items expose their source entry, digest, byte count, parsed ASCII
decimal IDs and `SINGLETON`, `AMBIGUOUS` or `INVALID` storage status. IDs are
observations and are not assigned as semantic owners. Results are deterministic
for identical input bytes and do not include runtime timestamps.

`project_complete` is always false. Top status is `PARTIAL` if any structural
form is observed, otherwise `UNKNOWN`. The reader does not claim complete QPG
grammar, CPU registration, execution type/order, full POU binding, label owner,
or independent engineering-software acceptance. The existing Neutral IR may
continue to report an unresolved name for the same input.

## Independent evidence still required

Comparing an observed field with an existing same-file UI name can corroborate
that specific specimen. A stored compiler log may be stale after later label
changes; equal log bytes do not prove current label contents or ownership. No
private UI name, project, raw carrier, ID, hash, export or path is included here.

Before extending semantic binding, future approved offline native work needs:

1. A POU-name-only A/B change with every other project value held fixed.
2. Saved/reopened copies, same-file UI names and carrier conservation for both.
3. A separate two-POU case with the same local label name and distinct comments
   to establish owner discrimination.

Those experiments are requirements for future work, not actions of this API.

Focused synthetic command from the repository root with the package installed
or `packages/gx3-r/src` on `PYTHONPATH`:

```text
python -B -m unittest discover -s packages/gx3-r/tests -p test_pou_details.py -v
```

The generated fixtures cover both layouts, all-carrier conservation, strict
range/framing/name decoding, decoy rejection, singleton ambiguity, input/IR
preservation, digest binding and budgets. They prove code behavior only.
