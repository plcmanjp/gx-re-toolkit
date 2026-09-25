# Contract evolution and provenance design

[English](contract-evolution.md) | [한국어](contract-evolution-ko.md)

The FX5 and R Neutral IR files currently share `schema_name`, version and
JSON Schema `$id`, while their committed schema bytes and finding enums differ.
Readers must select the installed package and exact profile identity before
validating. An `$id` or version match alone is insufficient. Existing schema
files and emitted IR remain unchanged by this design note.

## Future schema identity

Preferred next contract: a distinct immutable `$id` per profile and contract
revision, with a manifest that records package, profile ID, family, schema
SHA-256, and compatible producer versions. The consumer must require an exact
manifest tuple; unknown tuples fail closed. Alternatives are a common base
schema plus profile overlays, or a single schema with conditional profile
branches. Both require more moving parts and can accidentally widen one
profile when another changes. Before migration, inventory every consumer,
publish migration adapters, test old/new selection and cross-profile rejection,
and review the compatibility impact. Do not silently reinterpret 1.0.0 data.

## Build and attestation

The build manifest records the clean source commit/tree, pinned build tool
versions, archive hashes, and `published: false`. Installed verification
checks resource provenance and import origins. A future attestation may bind
these values, the dependency lock hash, CI runner identity, test reports, and
each archive-member digest. Whole-archive hashes and member hashes serve
different comparisons; differing archive metadata cannot be called a
bit-identical build. An attestation format, trusted issuer, key custody,
verification policy and release approval must be specified before signing or
publishing. This document does not establish a signer or release workflow.

## Module boundaries

Keep archive/SQLite/XML guards in each installed profile package and keep GXW
OLE limits in the GXW package. A later split of large decoders should preserve
public imports and CLI entry points, schema/resource bytes, opcode tables and
output ordering. First identify stable internal interfaces, then compare
installed wheel outputs against fixed private authority and synthetic negative
cases on every supported platform. No broad module split is authorized here.
