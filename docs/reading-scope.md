# Project reading scope

`gx_re_lab.reading_scope.build_reading_scope(ir, entries)` creates an additive
GX3 report from validated Neutral IR and caller-verified archive metadata.
Each entry has `name`, `sha256` and `byte_count`. The report preserves IR coverage
and findings separately from project semantics. CPU registration, execution type,
module/HSC parameters and opaque compiled/project data remain unverified with
entry locations and reasons. PouLinkOrder alone is not CPU execution registration.
The report is always PARTIAL and never certifies complete project reading.
It does not change parser IR, infer settings from hashes, or execute engineering
software. Archive binding remains the caller's responsibility.

The R parser's [bounded object projection](r-object-reading.md) preserves known
comment/label identity and text while retaining PARTIAL coverage for unbound
ownership and other attributes. This does not make a project reading complete.

The Q GXW Reference IR recognizes the first bare `U0` token as a literal only in
the exact `SP.SOCOPEN`/`SP.SOCCLOSE` four-operand and `SP.SOCRCV`/`SP.SOCSND`
five-operand forms. This follows the dummy string definition in the manufacturer's
[QnUCPU Ethernet manual, SH-080811ENG-X, sections 7.4.1, 7.4.2, 7.4.3 and 7.4.5](https://www.mitsubishielectric.com/dl/fa/document/manual/plc/sh080811eng/sh080811engx.pdf).
Raw spelling is retained. This does not introduce a generic U device family or
validate network operation, other operand roles, or other instruction forms.
