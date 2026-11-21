# Repository State & Engineering Specification Alignment Review

This review records the earlier implementation gaps. See the [current Wire tool state](current-tool-state.md) for the causal playback cutover and verification results.

**Date:** 21 November 2026  
**Reviewed Baseline:** `main` (`e:/work/artex_sandbox`)  
**Target Specification:** [docs/wire-improvement-engineering-spec.md](wire-improvement-engineering-spec.md)

---

## 1. Current State of `main`

- **Active Development Branch:** `main` is the single active branch for implementing the wire simulation improvements.
- **Specification & Review Artifacts:**
  - [docs/wire-improvement-engineering-spec.md](wire-improvement-engineering-spec.md) — Revised engineering specification defining the causal model, Schema v4 contracts, invariants `R01`–`R14`, work packages `WP1`–`WP6`, and verification fixtures `F01`–`F35`.
  - [docs/implementation-critique-and-fixes.md](implementation-critique-and-fixes.md) — Initial critique of the `286cf02` baseline.
  - [docs/artex-comparison-realism-review.md](artex-comparison-realism-review.md), [docs/comparison-review-evidence.json](comparison-review-evidence.json), and [scripts/review-comparison.cjs](../scripts/review-comparison.cjs) — Empirical 200-seed review probes and evidence motivating the specification's invariants.
- **Pre-LLM (Pre-2023) Baseline Expansion:**
  - `PRE2023_ATTACK_PATTERNS`, `WIRE_ATTACKERS`, `wire.html`, and [docs/pre-llm-vs-artex-comparison.md](pre-llm-vs-artex-comparison.md) include the five landmark 2020–2023 systemic attack patterns (**SolarWinds SUNBURST / APT29**, **Colonial Pipeline / DarkSide**, **Kaseya VSA / REvil (`CVE-2021-30116`)**, **Log4Shell (`CVE-2021-44228`)**, and **MOVEit Transfer / Cl0p (`CVE-2023-34362`)**) alongside the pre-2023 RaaS profiles (`lockbit`, `conti`, `blackcat`, `hive`, `revil`), with explicit `operator_with_tools` behavior preset metadata, historical provenance, and explicit `KEV_MITIGATION_RULES` coverage.

---

## 2. Gap Analysis: Current `main` vs. Engineering Spec Intent

The core philosophy of [docs/wire-improvement-engineering-spec.md](wire-improvement-engineering-spec.md) is to **replace predetermined outcome shortcuts with a causal, deterministic, and explainable model** where results emerge from reachability, prerequisites, knowledge-limited attacker decisions, control coverage, observable evidence, and scoped response authority.

| Spec Dimension | Current State on `main` | Spec Requirement ([wire-improvement-engineering-spec.md](wire-improvement-engineering-spec.md)) |
| --- | --- | --- |
| **1. Exercise Shortcuts (`R01`, §7.2)** | `wire.html` passes `seedExercise: true`. `evaluateDistinctActions` short-circuits on `kind: 'exercise'`, bypassing product, version, interface, capability, and credential checks (163/200 seeds breach even when relationship capabilities are impossible). | Remove `seedExercise` and `kind: 'exercise'`. Use `instantiateScenario(template, estate)` for `authored_walkthrough` runs and unforced generation for `exploratory` runs. |
| **2. Attacker Behavior vs. Defender Visibility (`R02`, `R04`, §8)** | `WIRE_ATTACKERS` binds telemetry (`boundarySignal`) and decoy placement (`canary`) to historical actor names (`revil` gets `none`/`untouched`; `artex` gets `all`/`early`). Baseline action sequences for Pre-2023 and ARTEX are identical across all 200 seeds once timestamps are stripped. | Move sensors, decoys, and enforcement points onto the **estate**. Separate historical actor/campaign metadata (`PRE2023_ATTACK_PATTERNS`) from two behavior presets (`operator_with_tools` vs. `agentic_orchestration`) operating under equal total attempt budgets (`R08`). |
| **3. Timing Race vs. Causal Contracts (`R11`, §12)** | `wireTiming()` places ARTEX's Layer 1 boundary crossing at `readTime - 50s` against a fixed `60s` SOC timer so SOC loses by 10 seconds by construction. | Historical elapsed times are projection context only (`projectRun`) and must never decide winners. Reactive races use explicit **intervention contracts** (`confirmed_before_action`, `confirmed_after_action`, `not_confirmed`, `ordering_unspecified`). |
| **4. Canaries & SOC Mechanics (`R03`, `R05`–`R07`, §10–§11)** | `recordTelemetry()` fires "early" canary signals on Layer 0 perimeter appliances (`canaryAssetId: null` in 200/200 runs) and only emits regular telemetry at Layer 1. No standalone Canary mode in `wire.html`. | Place explicit decoys (services, datasets, honeytokens) on the estate. Canary-only mode reports detection without revoking access. SOC correlates sensor observations across layers and executes scoped responses respecting session/token lineage. |
| **5. Virtual Patching (`R05`, §9)** | Exercise path uses a 65% coin flip (`rng() < 0.65`). Non-exercise CVE lookup uses `KEV_MITIGATION_RULES` without checking route-level inline enforcement points. | Evaluate inline rules only at `enforcementPoints` traversed by the route, checking protocol inspection capability and modeled action variant (`RULE_ENFORCED`, `OUTSIDE_CONTROL_PATH`, `UNSUPPORTED_PROTOCOL`, `RULE_NOT_MATCHED`). |
| **6. Fairness, Budgets & Provenance (`R08`, `R09`, `R13`, `R14`, §6)** | `simulateEstate` caps Layer 3 reached assets to `1` in defense modes vs. `3` in baseline. Any `data_read` (including Layer 0 public S3) counts as a breach. Some unmapped CVEs fall back silently to unmitigated. | Equal simulation budgets across all defenses; impact defined by dataset sensitivity classification and objective predicates; strict validation with zero silent fallbacks; `assets/calibration.json` for source statistics vs. simulation assumptions. |
| **7. Split Engines (WP5)** | `js/wire-engine.js` contains both `simulateEstate`/`simulateWireRun` (used by `wire.html`) and `evaluateComparisonMatrix` (used only by tests). | Consolidate into a single Schema v4 engine facade driving both the interactive diagram and comparison views. |

---

## 3. Recommended Implementation Sequence on `main`

1. **Immediate Integrity Fixes (`R08`, `R12`, `R13`, §6.5):**
   - Equalize Layer 3 traversal limits across all defense modes (`R08`).
   - Record explicit `outcome: 'suppressed'` events when containment prevents a transition (`R12`), and avoid applying the `contained` HUD class when exploration is truncated without containment.
   - Ensure all reachable edge-appliance CVEs (`CVE-2020-3452`, `CVE-2021-20016`, `CVE-2022-1040`, `CVE-2023-28771`, `CVE-2024-24919`) have explicit `KEV_MITIGATION_RULES` entries and remove silent unmitigated/ordering/interface fallbacks (`R13`).
2. **WP1 & WP2 — Schema v4, Calibration Register & Archetypes:**
   - Add `assets/calibration.json` (`observedStatistic` vs. `simulationAssumption`, `R14`).
   - Implement Schema v4 entities (`datasets` with sensitivity classification independent of layer, `routes` with `enforcementPoints`, `sensors`, `decoys`, `responseIntegrations`) and strict validators (`validateEstate`, `validateRunConfig`).
   - Build the 4 coherent infrastructure archetypes (`enterprise-identity`, `public-web`, `cloud-saas`, `cicd-secrets`) and replace `seedExercise` with `instantiateScenario(template, estate)` for authored walkthroughs and unforced generation for exploratory runs.
3. **WP3 & WP4 — Knowledge-Limited Attacker Frontier, Sensors, Canaries & SOC Contracts:**
   - Implement `simulateScenario({ estate, attackerProfile, defenseConfig, runConfig })` using a frontier of known candidate actions under equal attempt budgets (`operator_with_tools` vs. `agentic_orchestration`) without actor-name visibility flags or stealth multipliers (`R04`).
   - Implement route-based WAF virtual patching, explicit decoy triggers, and the SOC investigation/authority/lineage state machine with causal intervention contracts (`confirmed_before_action`, `confirmed_after_action`, `not_confirmed`, `ordering_unspecified`).
4. **WP5 & WP6 — Unified UI Projection & Verification Suite:**
   - Drive `wire.html` and `evaluateComparison` through the unified engine and `projectRun`, exposing independent defense switches, the "Why" inspection drawer, manifest import/export, and the `F01`–`F35` fixture suite in [scripts/test-wire-model.cjs](../scripts/test-wire-model.cjs).
