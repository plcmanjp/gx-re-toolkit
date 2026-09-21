# External research and code inclusion boundaries

[English](THIRD_PARTY_RESEARCH.md) | [한국어](THIRD_PARTY_RESEARCH-ko.md)

External parsers and structured ladder research are references only for comparing
failure conditions and test dimensions. Do not copy or translate source-available
or proprietary implementations or fixtures into this repository.
Do not execute external programs as runtime fallbacks.

Adapters receiving external results distinguish the status and provenance of
user-supplied results. They do not promote those results to official ground truth,
supported scope, product acceptance, or field approval. Introducing third-party
code requires review of its exact version, license, direct dependencies, and
notices.
