# ARTEX Attack and Defense Demo

An interactive visual demonstration of an attacker moving through an enterprise environment and the potential effects of layered defenses. The wire diagram shows a generated infrastructure, representative attack paths, vulnerability details and a rolling stream of SOC tickets.

The demo is illustrative: its infrastructure, access paths, alerts and defense outcomes are generated for presentation. They are not observations of a real environment or measurements of a product's effectiveness.

![ARTEX wire diagram demo](assets/wire_current_demo.gif)

[Watch the v2 ARTEX versus Pre-LLM animation](assets/ARTEX_vs_PreLLM_v2.gif): eight runs across the four defense options, with moving attacker/agent markers and the modeled stopwatch. [Scenario and capture notes](docs/v2-animation.md).

[Watch the full 54-asset infrastructure recording](assets/ARTEX_vs_PreLLM_full_estate.gif): the entire estate stays visible from the start across eight comparisons. See [current tool state and backend validation](docs/current-tool-state.md) for random generation, logical connections, canary visibility, verification evidence and remaining model limits.

## Get and start the demo

Clone the current repository:

```powershell
git clone https://github.com/kostchei/artex_sandbox.git
cd artex_sandbox
```

On Windows, install Python 3 and make sure `python` or the Python launcher `py` is available on your PATH. Then double-click **`start.bat`** in the repository folder, or run it from PowerShell:

```powershell
.\start.bat
```

The batch file runs `start.py`, which starts a local HTTP server and opens [http://localhost:8080/wire.html](http://localhost:8080/wire.html) in your browser. Keep the launcher window open while using the demo; press **Ctrl+C** in that window to stop it.

If port 8080 is already in use, the launcher opens the existing service at that address rather than starting another server. If neither `python` nor `py` is available, `start.bat` attempts to open that address but does not start a server.

On macOS or Linux, run `./start.sh` from the repository folder. It looks for `python3` and then `python`.

## Demo branches

- **`main`** runs the demo on the full wire diagram. The site root and old Table View address (`/index.html`) redirect to `/wire.html`.
- **`wire-combined`** preserves the demo before that change, including the standalone Range Operations dashboard and the original **Compare Combined** toggle. Use this branch to revisit that version.

## Run the wire diagram

1. Use the header toggle to choose **ARTEX** or **Pre-LLM Attacks**, and optionally pick a specific pattern from the **Pre-LLM** dropdown (which defaults to **Pre-LLM: Rotation (auto)** across the nine pre-2023 attack patterns and RaaS examples: **LockBit**, **Conti**, **BlackCat**, **Hive**, **REvil · Kaseya VSA**, **APT29 · SolarWinds**, **DarkSide · Colonial VPN**, **Log4Shell · Log4j**, or **Cl0p · MOVEit Transfer**). In rotation mode, each new estate draws one pattern in randomized order and keeps that selection for replay and defense comparisons; picking a specific Pre-LLM path pins that pattern and switches the active attacker view to **Pre-LLM Attacks** on the current estate. Nominal path-duration assumptions are **80–270 minutes** for conventional examples and **45–75 minutes** for ARTEX-like. Actual completion includes queued work. These illustrative ranges are not measured breach-time distributions; see [timing assumptions and historical sources](docs/timing-assumptions.md). ARTEX-like uses three workers and conventional profiles use one.
2. Start with **Baseline**, then compare **Virtual Patch**, **Agentic SOAR**, and **Defense-in-Depth** for virtual patching + SOC + canary together. Changing the attacker or defense replays the same topology.
3. Use **Replay** to repeat the run or **Results** to jump to its outcome. The **Modeled elapsed** clock advances from the first modeled probes. Open **Timing and data volumes** inside **Controls & Manifest** to see the milestones and counts recorded so far, alongside [historical references and their limits](docs/wire-timing-and-volume.md).
4. Use **Hide CVE stream** / **Reveal CVE stream** to collapse or restore the TTP / CVE activity panel beside the diagram. **Dual view** opens Pre-LLM and ARTEX side by side on the same estate. Use the **Archetype** selector (`enterprise-identity`, `public-web`, `cloud-saas`, `cicd-secrets`) and **Controls & Manifest** panel to toggle independent defense switches (`virtualPatching`, `canaries`, `responsePolicy`), switch between `authored_walkthrough` and `exploratory` generation modes, inspect causal "Why" details on any node, or save and restore the exact displayed run with a playback manifest.
5. Choose **Full enterprise** in the archetype picker to see employee systems, public apps, cloud workloads, and software delivery on the same estate. The overview shows selected service links from the start. Findings, credentials, and attack activity appear during playback. **Authored walkthrough** uses the public web scenario on this larger estate. **Exploratory** uses the same estate type without planting that path.
6. Use **New Infra** to generate a fresh topology and a different mix of five to seven appliance families from the [Layer 1 appliance pool](docs/wire_diagram_logic.md#layer-1-appliance-pool). Authored walkthroughs include a validated route to a sample dataset. Exploratory runs use the generated conditions. Credential exposure in logs can appear as an opening.

### Why ARTEX is faster

A conventional attack is one human operator at a keyboard. ARTEX is three LLM agents running in a shared harness. The model reflects this in two ways:

- **Faster steps.** The displayed clock uses a shorter nominal path duration for ARTEX-like. Timing is a presentation assumption applied after the engine determines access and response outcomes.
- **Three agents sharing state.** Access, credentials and footholds that one agent obtains are immediately available to the others, and the three work in parallel. On a single straight path this saves no time. It pays off when routes branch, fail or are blocked: ARTEX tries alternatives concurrently while the human works through them one at a time.

**New Infra** draws from 100 CISA KEV and CTID references. Each entry selects one of four representative infrastructure profiles, and the remaining topology is generated around it. The simulation shows which generated services were reached or defended. See the [JSON catalog](assets/wire-defense-catalog.json).

The estate may also contain an exposure from the [external misconfiguration pool](docs/wire_diagram_logic.md#external-misconfiguration-pool). The replay identifies the exposed service and the access established there.

## Scenarios

| Scenario | What the demo shows |
| --- | --- |
| **Baseline** | The estate model evaluates usable paths. Either profile can reach protected data if the generated estate supplies a complete path. |
| **Virtual Patch** | The WAF stops requests when the modeled rule covers the finding. |
| **Agentic SOAR** | Matching telemetry starts the estate's modeled collection, decision and response lifecycle. Coverage, authority, latency and enforcement success determine whether the affected session reads protected data before containment. |
| **Defense-in-Depth** | Virtual patching, the same SOC response lifecycle, and explicit canary alerts together. Decoy contact supplies evidence rather than instantaneous containment. |

WAF coverage, response timing, and outcomes are synthetic assumptions for this exercise.

## Infrastructure and tickets

The diagram spans internet-facing access, gateways and security controls, internal applications, and data stores. Assets occupy staggered lanes within trust layers, with space reserved for callouts; dense estates scroll vertically and narrow screens can scroll horizontally. Untouched assets use quiet green dots; successful attacks use pink halos, dashed paths and visible CVE callouts. Amber marks prevention, cyan marks containment and gold marks decoy alerts, with text labels explaining each state. Click or keyboard-focus an asset for connections and full details; the magnifier searches asset names, products and CVEs. ARTEX-like uses up to three workers; conventional profiles use one. Every defense uses the same 1,000 evaluated-transition ceiling; label density never limits modeled access. Pending work at the ceiling is reported as incomplete, including when a read has already occurred.

Standalone canary and SOC-plus-canary modes remain available to engine tests; the UI presents the four defense cards from the design reference.

The HUD distinguishes impact, incomplete exploration and partial or complete session containment. A missing read alone does not earn containment styling. Steps suppressed by effective containment do not count as new blocked attack attempts. Replay preserves the scenario and modeled event history; New Infra generates a new scenario.

An environment may include one network-monitoring system, selected from Cacti, LibreNMS, SolarWinds NPM, Zabbix, PRTG and ManageEngine OpManager. The selection has a 90% inclusion chance before topology filtering. Some products have a mapped historical CVE; others have no CVE assigned.

The SOC tickets are illustrative, generated as activity occurs. A node can produce one or several tickets, with a title, severity and short alert description. Severity and breach detection are demonstration choices, not CVSS scores or actual SIEM findings. Remediation tickets appear when a modeled virtual patch, agentic SOAR response or canary triggers.

See [wire diagram logic](docs/wire_diagram_logic.md) for the topology and scenario assumptions, [Pre-LLM vs. ARTEX comparison notes](docs/pre-llm-vs-artex-comparison.md) for field context and fixture limits, and the [threat matrix](docs/cisa_kev_threat_matrix.md) for additional vulnerability background.

## Testing

The simulation runs headlessly under Node, so most suites need nothing beyond Node.js. Install the one dependency once, then run everything:

```powershell
npm install
npm test
```

`npm test` runs every `scripts/test-*.cjs` suite and reports each result. The browser suites drive Microsoft Edge through `playwright-core`; set `EDGE_PATH` if Edge is not at its default Windows location. To run only the headless model suites, use `npm run test:model`.

## License

[Apache License 2.0](LICENSE).
