# Bounded R comment and label reading

The R reader projects observed SQLite object rows into the existing Neutral IR
1.0.0 schema. It does not establish complete project or PLC semantics.

## Comments

`*_DC.db` requires DEVICE_DATA and COMMENT_DATA with the declared column sets in
`objects.py`. COMMENT_DATA.DeviceSEQ joins DEVICE_DATA.SEQ uniquely. Only these
integer descriptor combinations are projected:

| DevCode | ExtCode | ExtNo | IsLocal | DevNoHigh | BitNo | Device |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | 0 | 0 | 0 | 0 | 0 | SM + decimal DevNoLow |
| 16 | 0 | 0 | 0 | 0 | 0 | X0, only DevNoLow=0 |
| 33 | 0 | 0 | 0 | 0 | 0..16 | SD + decimal DevNoLow |
| 35 | 208 | 992 | 0 | 0 | 0..16 | U3E0\\G + decimal DevNoLow |

For SD/module words, BitNo=0 has no suffix; 1..16 maps to hexadecimal .0...F.
DevNoLow must be nonnegative. No other extension or device code is inferred.
CmtNo 0 is `Comment`; 6 is `English`. Only SQL NULL DelFlag and text CmtData
are decoded. Empty text remains EMPTY_STRING. Other rows remain opaque with
raw locators and findings. Duplicate device/language identities are opaque.
Orphan device rows also remain explicit unknown observations.
Even projected identity/text rows remain PARTIAL: IsLocal=0 alone does not bind
an arbitrary carrier to a common file or a program owner. `common_device` is an
explicit schema scope placeholder, accompanied by a carrier finding; no POU
binding or general global/common-comment support is claimed.

## Labels

LabelTbl(LabelID,LabelTypeID), RowTbl(LabelID,RowID,...), and ColumnDataTbl
(LabelID,RowID,ColumnID,ColumnStrValue,ColumnIntValue) are required.
The actual object denominator is the union of RowTbl and ColumnDataTbl row
identities, retaining duplicate physical RowTbl occurrences. LabelTbl count is
not the label count; metadata without object rows receives a finding.

Only unique type 5121 rows with (VarType, BitCount, StateFlag, CheckerState)
equal to (1, '0', 0, 0) or (1, '1', 1, 0) project ColumnID 2 as label_id/name
and ColumnID 9 as Comment. These two observed combinations are storage guards;
their flag meanings are not inferred.
Both selected cells must also have integer ColumnIntValue=0. NULL, nonzero and
other storage types remain opaque, even when ColumnStrValue contains text.
All such labels remain PARTIAL: type, address, other columns and POU binding are
unmined. Type 5123 remains opaque. Duplicate names/cells/keys and orphan rows
remain opaque with findings and the original row-key locators. A comment edit
changes the value; it does not imply a label rename.

## Unknowns and limits

Opaque objects use stable MINING_REQUIRED IDs. Existing string values, including
text on unobserved delete flags, remain raw text with VALUE_PRESENT/EMPTY_STRING;
they do not establish active/deleted object semantics. The schema has no UNKNOWN
value state: when text is not available, SLOT_ABSENT/null is explicitly marked
as an undecoded placeholder in provenance, never proof of source absence. Opaque label scope uses
the existing global_label schema placeholder, explicitly without decoded scope
authority. Raw cell groups can be located by LabelID/RowID in the preserved
source; no source database is changed.

Missing/unobserved table schemas produce carrier findings and opaque raw rows
from available required tables; their denominator is raw observations rather
than decoded label/comment identities. The reader uses a 100,000 row table,
carrier and output budget; overflow fails explicitly rather than truncating.
Table source text/blob lengths and generated raw evidence/value text are also
bounded to 4,000,000 characters/bytes per table and characters per output.
SQLite connections close on every read path. Synthetic tests are separate from
official export comparisons and do not establish field acceptance.
