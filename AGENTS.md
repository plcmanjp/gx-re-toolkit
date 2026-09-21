# Standalone engineering rules

This repository is an independent offline toolkit. Do not load or modify a
parent workspace, private corpus, customer data, or another Git repository.

- Preserve parser meaning, binary constants, schema bytes and fail-closed checks.
- Never connect to a PLC or launch engineering software without explicit approval.
- Work only on disposable input copies; do not overwrite original projects.
- Keep synthetic tests separate from private authority and field acceptance.
- Do not add proprietary projects, exports, screenshots, manuals or credentials.
- Inspect diffs and run relevant tests before committing. Never force push.
- Remote creation, first publication and release upload require explicit approval
  for the exact destination, refs and artifacts. A local commit is not publication.
- Git history and recovery must remain independent; no linked worktree, alternates
  or shared object store. Do not copy another repository's history or hooks.

The source is a local candidate until installation, conformance and content gates
are complete. Do not represent candidate code as accepted for field use.
