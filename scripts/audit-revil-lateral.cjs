const assert = require('node:assert/strict');
const e = require('../js/wire-engine');
const d = require('../js/run-discovery');

const rows = [];
for (let seed = 1; seed <= 50; seed++) {
  const estate = e.generateEstate({preset:'mixed', seed, seedExercise:true});
  const run = e.simulateWireRun(estate, 'baseline', 'revil');
  const assets = new Map(estate.assets.map(a => [a.id,a]));
  const successful = run.events.filter(x => x.outcome === 'succeeded');
  const remote = run.events.filter(x => x.sourceId && x.sourceId !== x.targetId &&
    x.relationshipId && !assets.get(x.targetId)?.isDecoy);
  const lateral = remote.filter(x => x.outcome === 'succeeded' && x.grantedCapability === 'app_exec');
  for (const hop of lateral) assert(successful.some(x => x.targetId === hop.sourceId && x.timeSec <= hop.startSec));
  rows.push({seed, foothold:successful.some(x => x.grantedCapability === 'app_exec'),
    lateralExecution:lateral.length > 0,
    lateralTargets:[...new Set(lateral.map(x => x.targetId))],
    lateralTechniques:[...new Set(lateral.map(x => x.technique))],
    anyRemoteAccess:remote.some(x => x.outcome === 'succeeded'),
    failedRemoteChecks:remote.filter(x => ['ineligible','blocked','suppressed'].includes(x.outcome) && !x.policySkipped).length,
    encryptedEndpoints:run.summary.encryptedEndpointIds.length,
    truncated:run.summary.truncated,
    continuation:d.lateralStatus(estate,run)});
}
const count = predicate => rows.filter(predicate).length;
const summary = {runs:rows.length, seeds:'1–50', actor:'revil', defense:'baseline',
  generation:{preset:'mixed',seedExercise:true},
  definition:'Successful cross-asset execution (app_exec) over an explicit relationship from an already reached source; excludes external entry, reads, decoys and local encryption.',
  footholdRuns:count(r => r.foothold), lateralExecutionRuns:count(r => r.lateralExecution),
  lateralExecutionPercent:100*count(r => r.lateralExecution)/rows.length,
  anyRemoteAccessRuns:count(r => r.anyRemoteAccess),
  noLateralExecutionSeeds:rows.filter(r => !r.lateralExecution).map(r => r.seed),
  runsWithFailedRemoteChecks:count(r => r.failedRemoteChecks > 0),
  fleetExecutionRuns:count(r => r.lateralTargets.some(id => id.startsWith('windows-fleet-'))),
  multipleEncryptedEndpointRuns:count(r => r.encryptedEndpoints > 1),
  truncatedRuns:count(r => r.truncated),
  techniqueRunCounts:Object.fromEntries([...new Set(rows.flatMap(r => r.lateralTechniques))].map(t => [t,count(r => r.lateralTechniques.includes(t))]))};
console.log(JSON.stringify({summary,rows},null,2));
