# ARTEX Wire tool state — 21 November 2026

Wire is a static browser application. Start it with `start.bat` on Windows or `start.sh` on macOS and Linux. The browser and the Node verification suite use the same Schema v4 causal model. [README](../README.md)

## Infrastructure and discovery

- **New Infra** creates a seeded estate. **Authored walkthrough** instantiates and validates the route required by its template, including any required scoped credential and dataset access. **Exploratory** uses the generated conditions and may end without a sensitive read.
- **Full enterprise** places employee systems, public applications, cloud workloads and software delivery in one estate. Selected service routes and their endpoints are visible at the start. Findings, credentials and activity appear as the run discovers them.
- Switching the attacker or defenses keeps the estate. **Replay** repeats the run, **Results** advances the current trace, and resizing only changes layout.

## Playback and comparisons

`simulateWireRun`, `evaluateComparisonRun` and `evaluateComparisonMatrix` use `simulateScenario` for decisions and `projectRun` for display. The graph, activity, tickets and result derive from the same trace. The **Modeled elapsed** clock advances from the first modeled probes. Display durations and animation speed are independent of access, response and impact decisions. [Timing and data volumes](wire-timing-and-volume.md)

- **Virtual patching** follows route coverage and matching rules. **Canaries** supply evidence after an eligible interaction. SOC requires observable evidence, response authority and confirmation for the affected scope.
- **Observe only** records evidence. **Playbook** uses directly attributed alerts. **Human-led** and **Agentic** use the same current investigation and response rules, with identical outcomes under identical deployment and inputs.
- Intervention contracts govern whether confirmation affects a dependent action. Reads completed before confirmation remain in the trace. Unresolved ordering and incomplete exploration are reported separately from prevention.
- The canvas uses the engine's sensitive-read flag. Sensitive reads can occur on any diagram layer. The volume panel distinguishes dataset inventory, recorded reads and confirmed exports.

## Manifests and verification

Wire playback exports include the estate, attacker profile, defense settings, run configuration, causal trace and projected events. Replay verifies the recorded trace. Wire playback manifests exported by engine 4.0.0 use the archived timed runner. Older single-run and comparison exports require the matching engine. [Timing assumptions and replay](timing-assumptions.md)

- `npm test` passed all 13 suites, including both browser suites and the engineering spec fixtures F01–F35. Browser coverage includes the four response policies, sensitive and public read badges, manifest replay and Full Enterprise discovery.
- The bounded generation check validated 18,000 authored estates across the default generator and five named archetypes. Eight manifests produced by the previous Wire engine replayed with their original traces.
- The comparison tests cover missing telemetry, matching and uncovered patch rules, early and late decoys, scoped response, denied dataset access and before/after intervention contracts. Historical timing diagnostics exercise the archived runner.

The recorded GIFs show earlier revisions with a fixed estate. The live model's control behavior and stopwatch assumptions are synthetic. [Recordings](v2-animation.md) · [Engineering specification](wire-improvement-engineering-spec.md)
