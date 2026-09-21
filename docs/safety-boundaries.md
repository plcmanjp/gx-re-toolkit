# Execution and input safety boundaries

[English](safety-boundaries.md) | [한국어](safety-boundaries-ko.md)

Default imports and help do not perform GUI, network, or PLC operations.
Parsers and Lab inspect local files; some outputs may contain POU names and
user-supplied strings. Review research output before sharing it externally.

Snapshot handling checks size limits, regular-file status, link ancestors,
open-handle identity, final paths, and path replacement. These checks detect errors
in a trusted local environment; they do not guarantee an atomic sandbox against
a hostile filesystem.

Writers and encoders use explicit input copies and output paths. Do not apply
them to live equipment files or the only original. Do not fill in unsupported
formats by guessing.

No manufacturer affiliation, official certification, warranty, or approval for
field deployment is claimed.
