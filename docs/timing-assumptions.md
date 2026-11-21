# Stopwatch calibration and limits

The Wire stopwatch reports cumulative modeled time from the first probes. See [Timing and data volumes in Wire](wire-timing-and-volume.md) for the milestones, historical references, and volume evidence shown in the demo.

## Historical context

CrowdStrike's [2023 Global Threat Report announcement](https://www.crowdstrike.com/en-us/press-releases/2023-crowdstrike-global-threat-report-reveals-sophisticated-adversaries-re-exploiting-patched-vulnerabilities-moving-beyond-ransomware/) reports mean eCrime breakout times of 98 minutes in 2021 and 84 minutes in 2022. Breakout measures movement from a compromised host to another host. It does not measure the time to read a sensitive record, the full duration of an intrusion or individual gang timing distributions.

Anthropic's [AI-orchestrated espionage report](https://www.anthropic.com/news/disrupting-AI-espionage) describes automated orchestration and human intervention. It supplies behavioral context for an agentic profile, not a validated 45–75-minute distribution for enterprise data breach. ARTEX-like is a scenario policy applied to a modern generated estate, not a reconstruction of that campaign.

## Display timing and causal ordering

| Input | Current rule |
| --- | --- |
| Conventional nominal path duration | Seeded draw of 80–270 whole minutes for an illustrative path. |
| ARTEX-like nominal path duration | Seeded draw of 45–75 whole minutes for an illustrative path. |
| Stage durations | Three seeded weights split the nominal duration among the internal layers. External probes have a separate modeled duration. |
| Workers | One conventional worker or three ARTEX-like workers by default. Concurrent actions use the longest modeled duration in their batch for the display. |

Playback and comparisons use the same causal engine. Both attacker profiles use the same estate, sensor deployment, response authority and attempt budget. A matching inline patch acts within the access attempt. A reactive response affects an access check according to its intervention contract. The trace preserves completed reads and shows an unresolved outcome when the order would change impact and no assumption resolves it.

The generated sensor deployment is a seeded scenario assumption. Observe only records evidence. Playbook uses directly attributed alerts, while Human-led and Agentic share the current investigation and scoped response rules. A canary alerts only after a qualifying interaction. Containment requires confirmation from a matching integration.

`simulateWireRun(estate, mode, attacker, options)` accepts `runConfig` for budgets and intervention contracts, and `actionDurations` and `reentryDurationSec` for display timing. Wire playback manifests include the estate, effective policies, run configuration, causal trace and projected events. Playback manifests produced by 4.0.0 retain their original timed interpretation when opened in Wire.
