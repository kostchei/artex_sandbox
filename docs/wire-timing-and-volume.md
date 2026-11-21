# Timing and data volumes in Wire

The **Modeled elapsed** stopwatch starts with the first modeled probes and advances through the causal event trace. Each concurrent batch takes the longest projected action duration in that batch. The browser can play the same trace at different speeds. The simulation determines the causal order of access and response before assigning display timestamps.

Show the historical calibration in the existing **Controls & Manifest** panel, next to the current run's modeled first lateral move, first protected read, alert, containment, and completed export when present. The historical references retain their original milestones and populations.

- CrowdStrike's 2024 Global Threat Report records a 62-minute mean and a 2-minute-7-second fastest observed eCrime breakout in 2023. Breakout measures the first host-to-host movement after initial compromise.
- GTIG and Mandiant's October 31, 2026 report describes about four hours from first compromised account to deep system access in one ARTEX-associated campaign, and 15 minutes in one case. Neither value specifies first sensitive read or export completion.
- Mandiant's M-Trends 2023 reports a 16-day median from compromise to discovery in its 2022 investigations. That reference measures detection, with no implied time to containment.

Correct the ARTEX reference dates in the JSON register and bundled browser copy. Use the register for displayed references. Keep those observations out of the outcome and scheduling rules. Treat the two ARTEX observations as context for a typical campaign case and a fast observed case, without fitting a distribution or adding more playback presets.

For data volumes, use the synthetic estate inventory and the run's recorded evidence. The results and selected dataset show inventory, recorded read volume, and confirmed export volume separately. Use record counts and bytes where available. Preserve unknown sizes. For interrupted export, show that completion was unconfirmed and leave any partial volume unknown. The current transfer model records completion as one event, so it cannot substantiate a partial byte count. Keep the same inventory for all attackers and defenses on an estate.

Public disclosures can illustrate scale in documentation. Maximus's July 2023 SEC filing estimated that impacted MOVEit files contained personal information for 8–11 million people. People affected is a distinct unit, independent of rows, files, and bytes. See the [SEC filing](https://www.sec.gov/Archives/edgar/data/1032220/000103222023000061/mms-20230726.htm).

Verification uses the existing browser and model suites plus focused checks for the display. Replay and defense switches retain the estate, and the details only show milestones and impact already recorded at the current playback position.
