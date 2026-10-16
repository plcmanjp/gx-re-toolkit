# Supplemental R label details

`gx3_r_parser_toolkit.label_details.parse_label_details(path)` returns a separate
`plcman.gx3.r-label-details` dictionary, version `1.0.0`. It leaves the production
`parser.parse()` return value and Neutral IR schema unchanged. This candidate
API reads an offline disposable `.gx3` copy. It has no writer, CLI, network or
engineering-software integration.

## Input gates and conservation

The production R parser runs first. A fatal result, unsupported/ambiguous R04
profile, or failed unchanged-input flag raises `ArchiveError`. A second bounded
`SafeGx3Archive` read must have the same SHA-256. The input SHA-256 is checked
again after supplemental processing. A failed read raises rather than returning
an empty successful result.

Only real SQLite tables named `LabelTbl`, `RowTbl`, and `ColumnDataTbl` are read.
Views do not qualify. Expected columns reuse `objects.TABLES`. Missing tables or
different columns disable all semantic interpretation while available real
table rows remain visible. Queries use fixed identifiers and query-only in-memory
connections, closed on success and failure. Reads use batches of at most 256 rows,
an aggregate 100000-row budget, and a 4000000-character/raw-byte text budget.
The serialized output has the same 4000000-character budget. Exceeding a budget
raises without truncation.

`raw_tables` contains original column names and deterministically sorted row
dictionaries. A BLOB becomes `{"storage_type":"blob","hex":"..."}`; a REAL
becomes `{"storage_type":"real","hex":"..."}` using Python `float.hex()`.
These tags describe storage, not label meaning. Other SQLite scalars retain
their types. Sorting does not remove duplicate physical rows.

`records[].source_rows` lists zero-based indices into those sorted tables.
Each physical `RowTbl` row receives a record. Orphan cell groups and unreferenced
label metadata receive explicit unknown records. With an unobserved schema,
each available physical table row receives an `unmapped_storage_row` record.
The raw tables and references preserve evidence without repeating large cells
in every record. `record_id` hashes the deterministic locator and is not a POU
or semantic label identity.

## Supported observations

Only observed local type 5121 rows qualify. The guard requires unique label
metadata, a unique row key, unique cells, an integer nonnegative row ID, text
label ID, one of the two observed row-state tuples, a unique nonempty name,
and text Comment. Name/Comment require integer0 in their dual-value fields.
Duplicate semantic names remain unknown without assigning POU owners.
Only integer ColumnIDs 1/2/3/9 are eligible; additional columns disable the row's
semantic projection. Python bool, REAL, text and BLOB do not qualify as integer
guard values. SQLite itself stores a Python bool input as an INTEGER, so its
pre-storage Python origin cannot be recovered from a database.

| ColumnID | Required dual value | Supplemental attribute |
|---|---|---|
|1|text `VAR`, integer4|`class = VAR`|
|2|nonempty text, integer0|`label_name`|
|3|empty text, integer1|`data_type = BOOL`|
|9|text including empty text, integer0|`comment`|

Class and datatype are interpreted only when their respective complete observed
cell form matches and the row's name/Comment identity guard passes. An absent or
different class/datatype cell remains unknown. Integer mappings are not extended
to other label types or arbitrary cell combinations. Type 5123 remains unknown,
with its raw rows, type values and cells preserved.

## Output contract and unknown values

Top-level fields are `schema_name`, `schema_version`, `status`, `project_complete`,
`input`, `profile`, `source`, `records`, `raw_tables`, `findings`, and `counts`.
`source` binds the carrier digest, or is null when no carrier is available.
`input` copies the production parser's digest, byte count and unchanged flag.
`profile` contains only `profile_id` and `detector_status`.

Records have `record_id`, `kind`, `status`, `storage_key`, `occurrence`,
`source_rows`, `owner`, `attributes`, and `provenance`. Kinds are `label_row`,
`orphan_cells`, `label_metadata`, and `unmapped_storage_row`. Provenance binds
the source entry, carrier SHA-256 and deterministic row-reference locator.
Counts conserve `total = partial + unknown`.

Attributes follow the 27-column official export order with these canonical keys:

```text
class,label_name,data_type,constant,initial_value,assign,address,comment,
comment2,comment3,comment4,comment5,japanese,english,chinese_simplified,korean,
chinese_traditional,german,italian,reserved1,reserved2,reserved3,reserved4,
remark,system_label_relation,system_label_name,attribute
```

Every attribute is `{"status":"SUPPORTED","value":"..."}` or
`{"status":"UNKNOWN","value":null}`. Only class/name/type/Comment can be
supported. The remaining 23 attributes are always unknown, even when the official
CSV contains blanks or an internal allocation table contains a value.
`DeviceAssignTbl` is not interpreted. In particular, an internal allocation
token such as `LV:0.0` is not an official Assign or Address value.

`owner` is always `{"status":"UNKNOWN","pou_id":null}`. Neither a singleton
POU nor matching names proves label ownership. This API does not read binary
Program.qpg names or prove CPU registration, execution type, full label
attributes, absence of labels, complete project reading or field acceptance.

Record status is `PARTIAL` when at least one attribute is supported, otherwise
`UNKNOWN`. Top-level status uses the same rule across records. No status is
complete: `project_complete` is always false. Unknown is not empty, absent, or
zero. Raw storage values must not be promoted to supported attributes by a
consumer.

## Focused synthetic checks

From the repository root, using an interpreter with the package installed or
with `packages/gx3-r/src` on `PYTHONPATH`:

```text
python -B -m unittest discover -s packages/gx3-r/tests -p test_label_details.py -v
```

The disposable fixtures exercise production parser/profile gates, same-file
digest binding, deterministic raw conservation, both observed row states,
unknown attributes, dual values and types, collisions/orphans, real-table
requirements, input preservation, budgets and connection closure. Synthetic
checks establish code behavior; they do not establish independent authority
for additional mappings or private/customer acceptance.
