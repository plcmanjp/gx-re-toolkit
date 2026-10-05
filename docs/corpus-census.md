# Corpus census

[English](corpus-census.md) | [한국어](corpus-census-ko.md)

`python -m gx_re_lab.corpus_census --manifest manifest.json --manifest-sha256
<sha256> --source-root <disposable-copies> --output <new-report.json>` runs the
existing GX3-FX5 and GXW-Q censuses against retained, pinned input copies.
The manifest is UTF-8 JSON with exactly this shape:

```json
{"format":"plcman.gx-re-lab.corpus-manifest","version":1,"cases":[
  {"case_id":"C001","path":"C001.gx3","adapter":"GX3-FX5",
   "byte_count":123,"sha256":"<64 lowercase hexadecimal characters>"}
]}
```

Adapters are `GX3-FX5` and `GXW-Q`. Paths are relative to the supplied root;
links, traversal, alternate streams and absolute paths are refused. Limits
are 256 occurrences, 32 MiB per GX3-FX5 source, 16 MiB per GXW-Q source,
512 MiB in total and a 4 MiB report. The FX5 archive inflation limits remain
2,000 entries, 16 MiB per entry and 64 MiB in total; a larger container budget
does not relax database, compression or semantic checks.
Duplicate source hashes are reported and every occurrence is checked. A bad
pin, changed source or failed census remains a blocked case; other cases run.
The CLI returns 1 for any blocked case and refuses to overwrite its output.

The combined report exposes case IDs, input pins, counts and hashed container
keys. The same key with different contents is recorded separately by adapter
and content SHA. A reused container name or GUID alone cannot establish a
cross-project semantic identity. Source names and exception text are omitted.
The report's semantic coverage is `NOT_MEASURED`, lifecycle and target
acceptance are `NOT_RUN`, and support is `NOT_CLAIMED`. These structural counts
do not measure conversion correctness or replace an official export comparison.
R-series remains available through the separate `r04_census` adapter.

Keep manifests, source copies and resulting reports outside this public
repository. Only synthetic tests and generic implementation belong here.
