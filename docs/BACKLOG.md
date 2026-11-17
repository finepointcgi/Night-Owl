# Night Owl backlog

Prioritized by (impact on real users) ÷ (effort). Status is checked against the code, not guessed.
"Have" means it exists today; "Gap" is what is missing.

## P1: trust and noise (do first; decides whether people keep using it)

| # | Item | Have | Gap |
|---|------|------|-----|
| 1 | Noise reduction | gitignore-style `.nightowl/ignore`, triage with expiry, new-code gate, reachability hint (imports only), **path context (test/example/docs/generated/vendored) excluded from the gate by default** | Still open: confidence field on findings; merge a pattern rule and a taint rule that fire on the same line (NodeGoat reports `eval` twice); framework code that implements the sink itself (express `res.send`); measure the false-positive rate on a few real open-source repos and tune rules against that. |
| 2 | Policy as code | **Done (uncommitted):** `.nightowl/policy.yml` covers gate thresholds (per category), license deny/review/allow, coverage, duplication, complexity; `nightowl policy init/validate`. Left: required SBOM fields, default expiry for accepted risks. | (original ask:) One committed `.nightowl/policy.yml`: severity thresholds per category, allowed/denied licenses, required SBOM fields, max-age for accepted risk. CLI flags override it. Same file read by the GitHub Action. |
| 3 | Fingerprint robustness | Stable fingerprints from rule, path, snippet, line | Normalize whitespace and comments before hashing; survive file renames (`git diff -M`) in `--since`. Needs a regression corpus so changes never silently re-open triaged findings. |
| 4 | `fix` coverage | npm, NuGet, pip, Go; OSV verification of the target; `--pr` | Maven, Cargo, Composer; refuse or warn on major-version jumps; lockfile-only updates. |

## P2: depth against commercial tools

| # | Item | Have | Gap |
|---|------|------|-----|
| 5 | C/C++ | cppcheck built from source, graded by defect class | Second engine (Clang Static Analyzer with a compile database, or Infer) merged by `FindingMerger`. Honest note: Coverity-level interprocedural analysis will not be matched by open source; aim for "finds the common serious defects". |
| 6 | Code quality | lizard complexity and duplication, coverage import | Cognitive complexity, long-method and parameter-count rules, a named "quality profile", technical-debt trend (history already recorded per scan). |
| 7 | SCA | OSV, licenses, SBOM (CycloneDX/SPDX), VEX from triage | Binary and snippet analysis is Black Duck's moat; do not chase it. Cheaper wins: license obligation mapping, GitHub Advisory and EPSS enrichment, symbol-level reachability for Go (govulncheck). |
| 8 | Monitoring | OSV batch re-check, webhooks | Additional sources (GitHub Advisories), EPSS and reachability in the alert priority. |

## P3: experience

| # | Item | Have | Gap |
|---|------|------|-----|
| 9 | IDE | `editors/vscode` shows SARIF diagnostics on demand | Scan on save of the changed file only, quick-fix to triage from the editor, status-bar gate. Needs a real VS Code test pass first; it has only had a syntax check. |
| 10 | Dashboard | Per-project page, trend chart, triage buttons, token gate | Keyboard shortcuts, bulk triage, reason templates, organization view across repositories. |
| 11 | AI layer | `--ai` exploitability review (local Ollama or cloud, opt-in) | Suggest a triage decision (never auto-apply), "explain this finding" button, draft fix PRs for simple cases. Keep local-first; never send secrets. |
| 12 | Attestation | Signed engine manifest | in-toto/SLSA provenance for Night Owl's own releases and for generated SBOMs. |

## P4: engineering and distribution

| # | Item | Notes |
|---|------|-------|
| 13 | Adapter robustness | Every engine failure already degrades to a warning; add per-engine timeouts and malformed-output tests with real captured outputs. |
| 14 | Performance | Run independent engines in parallel; skip unchanged directories using git; cache per-engine results keyed by content hash. |
| 15 | Packaging | Homebrew tap and Scoop manifest first (small); apt later. Needs a stable release name after the rename. |
| 16 | Docs | Table of which engine covers which language, and how findings merge. Can be generated from `engines.json` and the rule packs. |

## Release engineering

- Trust a list of signing keys (current + next) so a key can be rotated without a manual reinstall. See `docs/SIGNING-KEY.md`.

## Known loose ends (from the last session)

- v0.1.0 binaries and `install.sh` still use the old Nightjar names; cut v0.1.1 after the rename settles.
- `engines-release` fix (#4) must merge before the engine bump (#3).
- Windows and Linux binaries are built but never run.
- `BaseImageWatcher`, `FixCommand`, `AdvisoryMonitor` slightly exceed the complexity limit.

## Suggested order

1 → 2 → 3 (shared work on the findings model), then 4, then 6 and 9 in parallel, then 5.
