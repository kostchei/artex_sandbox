# Remediation implementation and validation

This record covers the earlier timed runner. See the [current Wire tool state](current-tool-state.md) for live playback, comparison behavior and manifest compatibility.

Implemented on local `main` after the planning commit `cd9137b`. The original Gemini merge baseline is `8aeae9b`.

## Delivered behavior

1. **Fair exploration:** the active engine uses a common 1,000 evaluated-transition ceiling. Per-layer and per-source display caps no longer stop access. Worker concurrency does not change the allowance. Pending work at exhaustion is incomplete even after impact. Suppressed action effects are separate from prevented attempts.
2. **Honest results:** a shared classifier returns impact, completeness and session-containment facts. The HUD uses those facts for its text and styling; absence of a read alone does not mean containment. Reads before enforcement remain in the history. Partial containment, failed enforcement and alerts without enforcement are visible.
3. **Causal scheduling:** workers consume time and discover onward work only after source access. Confirmed enforcement cancels in-flight effects and prevents queued work in the same scope. Enforcement wins an exact completion tie. Signals, decisions and enforcement share the attack clock. The fixed ARTEX final-stage offsets are removed. Stage allocations, sensors, authority, latency and enforcement success use explicit scenario inputs; estate-owned draws are reused for attacker/defense comparisons. See [timing assumptions](timing-assumptions.md) for historical sources and calibration limits.
4. **Readable layout:** labels are measured and packed deterministically in four layer columns. Dense estates scroll; narrow screens can scroll horizontally. Keyboard focus and selection reveal full details in a stable panel. Resize and Results reuse the current estate.

The existing five top-row modes remain. A sixth, **Layered Defense**, enables virtual patching + agentic SOC + canary together through the same response lifecycle. No real data store is silently repurposed as a canary when the estate lacks a deployed decoy.

Selected Codex and Claude improvements were adapted into this integration: explicit skipped effects, fair budgets, neutral incomplete/no-read presentation, five missing CVE control declarations, required interfaces and eager action-order validation. The latter checks all assets, including one-item cases, duplicates and unknown IDs. CVE coverage is checked before playback, including baseline runs. Declared decoys must reference actual decoy assets.

## Validation

- `node scripts/test-wire-model.cjs`: existing prerequisite, credential, replay, generation and comparison coverage passes. Assertions that encoded predetermined active-UI timing outcomes were replaced with lifecycle invariants; the legacy authored comparison fixtures remain explicit examples.
- `node scripts/test-remediation.cjs`: focused coverage passes for equal allowances, impact plus pending work, exact ties, failed enforcement, missing authority, wrong scope, early/late/untouched decoys, partial containment, worker capacity, deterministic replay and invalid configuration.
- `node scripts/review-remediation.cjs`: 7,200 runs across 200 seeds × three presets × two actors × six modes pass causal source-access, enforcement, budget, decoy and estate-immutability checks. These sampled scenarios contain both reads and non-reads under SOC and layered defenses; the counts are synthetic scenario observations, not effectiveness estimates.
- `node scripts/test-browser-remediation.cjs`: automated Edge checks cover seeds 1/42/99 at 1440 × 900, 1280 × 720 and 390 × 844, both attackers and all six modes, Replay/Results, New Infra, root redirect, keyboard details and label collisions. The test checks model/UI result agreement and unchanged scenario inputs across comparisons.
- `git diff --check`: passes.

The browser test uses Playwright Core. If installed outside this repository, set `PLAYWRIGHT_CORE_PATH` to that package's absolute path. `EDGE_PATH` can override the browser executable; `REMEDIATION_SCREENSHOT` optionally saves desktop and narrow-screen screenshots.

## Practical limits

The historical stopwatch is preserved, with source milestone definitions and explicit synthetic allocations. It is not an empirically calibrated breach-time predictor. WAF coverage and adaptive evasion remain scenario assumptions. Sensor correlation is simplified and does not model benign-event noise or a complete SOC investigation. Session scope still follows the first successful ingress lineage, rather than a full multi-principal identity model. The objective remains a non-decoy Layer 3 read.

Enterprise archetype expansion, comprehensive CVE evidence auditing, dataset sensitivity independent of layout and richer attacker discovery policies remain broader six-phase roadmap work. Legacy `evaluateComparisonRun()` teaching traces are documented separately from the active Wire scheduler. These boundaries are not hidden by the remediation result labels.
