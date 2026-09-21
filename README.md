# GX RE Toolkit

[English](README.md) | [한국어](README-ko.md)

An independent research toolkit for offline analysis of the explicitly supported
Mitsubishi project formats. It is not affiliated with or endorsed by Mitsubishi
Electric. Successful analysis does not establish a successful GX rebuild,
agreement with official exports, approval for PLC use, or field safety.
This is a local pre-publication candidate and requires publication approval.

## Packages

| Distribution | Version | Purpose |
| --- | --- | --- |
| gx3-fx5-parser-toolkit | 0.4.0 | GX3 FX5 structure and Neutral IR analysis |
| gx3-r-parser-toolkit | 0.2.0 | Analysis of the specified R04CPU GX3 profile |
| gxw-parser-toolkit | 0.1.0 | GXW analysis, Reference IR, and candidate file writing |
| gx-re-lab | 0.1.0 | Bounded comparison, census, planning, and reduction research tools |

Python 3.12 or later is required. Full writing functionality uses Windows and
pywin32. See the [compatibility matrix](docs/compatibility-matrix.md) for CPU
coverage and limitations. Private originals, customer data, official exports,
and vendor materials are not included. Default tests and runtime operations do
not launch GX software or connect to a PLC.

## Build and install

Build from a reviewed, committed, clean standalone checkout. The output directory
must be a new path outside the checkout. The following example uses PowerShell.

```powershell
python -m venv C:\Temp\gx-build-env
C:\Temp\gx-build-env\Scripts\python.exe -m pip install build==1.3.0 setuptools==84.0.0
C:\Temp\gx-build-env\Scripts\python.exe tools/build_artifacts.py --output C:\Temp\gx-build-01
$wheels = Get-ChildItem C:\Temp\gx-build-01\artifacts -Recurse -Filter *.whl
C:\Temp\gx-build-env\Scripts\python.exe -m pip install $wheels.FullName
C:\Temp\gx-build-env\Scripts\python.exe -m pip check
$commit = git rev-parse HEAD
$tree = git rev-parse 'HEAD^{tree}'
C:\Temp\gx-build-env\Scripts\python.exe tools/verify_install.py --commit $commit --tree $tree --output C:\Temp\gx-install-report.json
```

Editable installs are not release-validation evidence. The build includes the
root LICENSE, NOTICE, and dependency notices in each distribution. FX5/R source
commit and tree identifiers are recorded in an artifact-only provenance resource,
not in committed source. Zero values used when that resource is absent from a
source checkout are not a verified distribution identity.
`build-manifest.json` records actual tool versions, the source commit/tree, and
distribution SHA-256 hashes.

## Usage

```powershell
gx3-fx5-inspect --help
gx3-r-inspect --help
gxw-reference-ir --help
gxw-write --help
gxw-encode --help
python -m gx_re_lab.lab --help
python -m gx_re_lab.census --help
python -m gx_re_lab.planner --help
```

The Lab module CLIs are `explorer_diff`, `reference_query`, `census`,
`r04_census`, `gxw_census`, `planner`, `coverage_ledger`, `external_compare`,
`final_scope`, `lab`, `experiment`, `relation_audit`, and `campaign_coverage`.
Without an input, `gxw-inspect` and `python -m gxw_pou_devmap` display usage and
exit with code 1. Give writing tools only disposable input copies and new output
paths, never originals. Atomic protection against a hostile filesystem is not
guaranteed across all input and output operations.

## Validation and publication boundaries

`tools/audit_public_tree.py` checks paths, file types, and selected sensitive
patterns in the working tree, files reachable from all local refs, and
distributions supplied with `--artifact`. It is not exhaustive secret detection
or independent legal review. Do not combine private comparison results and public
synthetic tests into a claim of field acceptance.

- [Validation methodology](docs/validation-methodology.md)
- [Safety boundaries](docs/safety-boundaries.md)
- [Reverse engineering and rights policy](docs/reverse-engineering-policy.md)
- [Dependency notices](THIRD_PARTY_NOTICES.md)
- [External research boundaries](THIRD_PARTY_RESEARCH.md)
- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Documentation languages

English is the default documentation language. Korean translations use the
`-ko.md` suffix and link back to their English originals. Keep both versions in
sync when changing meaning, commands, or safety boundaries. The English version
is authoritative if translations differ. LICENSE and NOTICE retain their
original legal text.

## Recovery

This checkout uses its own Git database. Another repository does not
automatically back up these files or commits. Create a Git bundle with explicit
refs outside the working tree, restore it separately, and verify the commit/tree.
A local backup is not off-device disaster recovery. Do not recursively clean a
parent directory: that can delete the nested repository.
