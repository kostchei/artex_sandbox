// Historical diagnostic for the timed runner retained for archived Wire manifests.
// Read-only review probes. Run: node scripts/review-comparison.cjs
const e = require('../js/wire-engine.js');
const attackers = ['lockbit', 'conti', 'blackcat', 'hive', 'revil', 'artex'];
const modes = ['baseline', 'patch', 'soc', 'soc-canary'];
const counts = Object.fromEntries(attackers.map(a => [a, Object.fromEntries(modes.map(m => [m, 0]))]));
let withoutExerciseReads = 0, identicalBaselineActions = 0, exerciseReadsWithImpossibleCapability = 0;
let canarySignalsWithoutCanaryAsset = 0;
let noSignalSocReducedDataCount = 0, budgetSample;
let sample;
for (let seed = 1; seed <= 200; seed++) {
  const estate = e.generateEstate({seed, seedExercise: true});
  for (const a of attackers) for (const m of modes) {
    if (e.simulateLegacyWireRun(estate, m, a).summary.dataReached) counts[a][m]++;
  }
  const strict = structuredClone(estate);
  strict.findings = strict.findings.filter(f => f.kind !== 'exercise');
  if (e.simulateLegacyWireRun(strict, 'baseline', 'artex').summary.dataReached) withoutExerciseReads++;
  const stripTime = run => run.events.map(({timeSec, ...event}) => event);
  if (JSON.stringify(stripTime(e.simulateLegacyWireRun(estate, 'baseline', 'lockbit'))) ===
      JSON.stringify(stripTime(e.simulateLegacyWireRun(estate, 'baseline', 'artex')))) identicalBaselineActions++;
  const altered = structuredClone(estate);
  altered.relationships.forEach(r => {r.requiredSourceCapability = 'review_impossible_capability';});
  if (e.simulateLegacyWireRun(altered, 'baseline', 'artex').events.some(ev =>
      ev.finding?.kind === 'exercise' && ev.grantedCapability === 'data_read')) exerciseReadsWithImpossibleCapability++;
  const canary = e.simulateLegacyWireRun(estate, 'soc-canary', 'artex');
  if (canary.canaryAssetId === null && canary.controls.some(c => c.source === 'canary')) canarySignalsWithoutCanaryAsset++;
  const baseline = e.simulateLegacyWireRun(estate, 'baseline', 'revil');
  const noSignalSoc = e.simulateLegacyWireRun(estate, 'soc', 'revil');
  if (baseline.summary.layerSuccessCounts[3] > noSignalSoc.summary.layerSuccessCounts[3]) {
    noSignalSocReducedDataCount++;
    budgetSample ??= {seed, baselineDataAssets: baseline.summary.layerSuccessCounts[3],
      socDataAssets: noSignalSoc.summary.layerSuccessCounts[3], controlEvents: noSignalSoc.controls.length};
  }
  if (!sample && e.simulateLegacyWireRun(estate, 'baseline', 'artex').summary.dataReached) {
    const run = e.simulateLegacyWireRun(estate, 'soc', 'artex');
    const read = run.events.find(ev => ev.grantedCapability === 'data_read');
    const signal = read && run.controls.find(c => c.scope === read.scope && c.control === 'signal');
    const enforcement = read && run.controls.find(c => c.scope === read.scope && c.control === 'enforced');
    if (signal && enforcement) sample = {seed, readSec: read.timeSec, signalSec: signal.timeSec, enforcementSec: enforcement.timeSec};
  }
}
console.log(JSON.stringify({seedRange: [1, 200], dataReadCounts: counts, withoutExerciseReads,
  identicalBaselineActions, exerciseReadsWithImpossibleCapability, canarySignalsWithoutCanaryAsset,
  noSignalSocReducedDataCount, budgetSample, sample}, null, 2));
