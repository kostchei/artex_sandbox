// Historical diagnostic for the timed runner retained for archived Wire manifests.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const engine=require('../js/wire-engine');
const discovery=require('../js/run-discovery');
const cases=[['lockbit',1853],['conti',3],['blackcat',8],['hive',42],['revil',99]];
const success=run=>run.events.filter(event=>event.outcome==='succeeded');
const stamp=seconds=>`${Math.floor(seconds/3600)}:${String(Math.floor(seconds%3600/60)).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`;
function validate(estate,run){
  const successes=success(run);
  assert(successes.filter(event=>!event.sourceId&&event.timeSec===0).length<=1,'Only the starting foothold is instantaneous');
  for(const event of successes){
    if(event.sourceId&&event.sourceId!==event.targetId){
      const route=estate.relationships.find(r=>r.id===event.relationshipId);
      assert(route,'Successful movement follows a real route');
      assert(successes.some(prior=>prior.targetId===event.sourceId&&prior.timeSec<=event.startSec&&
        (!route.requiredSourceCapability||prior.grantedCapability===route.requiredSourceCapability)),
        'Required source capability exists before the attempt starts');
    }
    if(event.credentialUsed&&!event.credentialUsed.startingAccess){
      assert(successes.some(prior=>prior.timeSec<=event.startSec&&prior.acquiredCredentials?.some(c=>c.id===event.credentialUsed.id)),
        'Credential is acquired before its use starts');
    }
    if(event.actionKind==='data_exfiltration'){
      assert(successes.some(read=>read.isProtectedRead&&read.targetId===event.targetId&&read.timeSec<=event.startSec&&read.scope===event.scope));
      assert(!run.controls.some(c=>c.control==='enforced'&&c.scope===event.scope&&c.timeSec<=event.timeSec),'Containment wins transfer ties');
    }
  }
  for(const duplicate of run.events.filter(event=>event.outcome==='revisit'||event.policySkipped))
    assert.equal(duplicate.timeSec,duplicate.startSec,'Redundant and excluded actions consume no worker time');
  const jobs=[...new Map(run.events.filter(event=>event.timeSec>event.startSec).map(event=>
    [`${event.sourceId}:${event.targetId}:${event.startSec}:${event.timeSec}`,event])).values()];
  for(const job of jobs){
    const middle=(job.startSec+job.timeSec)/2;
    assert(jobs.filter(other=>other.startSec<=middle&&other.timeSec>middle).length<=run.lanes,'Worker count is respected');
  }
  if(run.attackerProfile.gangId){
    const transfers=run.events.filter(event=>event.actionKind==='data_exfiltration');
    for(const encryption of successes.filter(event=>event.actionKind==='encryption'))
      assert(transfers.every(transfer=>transfer.timeSec<=encryption.startSec),'Available collection/transfer work precedes encryption');
  }
}
function activity(run){
  return run.events.filter(event=>!event.policySkipped&&event.outcome!=='revisit'&&(
    discovery.observed(event)||event.actionKind==='data_exfiltration'||event.analysisKind==='route_review'&&event.timeSec>event.startSec));
}
function keyEvent(event){
  return event.isProtectedRead?'DATA FOUND':event.actionKind==='data_exfiltration'
    ?event.outcome==='succeeded'?'DATA EXFILTRATED':event.outcome==='blocked'?'EXFILTRATION BLOCKED':event.outcome==='ineligible'?'EXPORT NOT ATTEMPTED':'EXFILTRATION STOPPED'
    :event.analysisKind==='route_review'?'PATH REVIEW':event.outcome==='ineligible'?'NO NEW ACCESS'
    :event.actionKind||event.finding?.cveId||event.technique||event.finding?.kind||event.outcome;
}
function generateReport(rows){
  const lines=['# Five paired activity-flow reviews (archived timed runner)','',
    'Each pair uses the identical generated estate for ARTEX and one gang. Five fixed seeds were selected before changing progression; they are not selected for successful outcomes. Four defense modes are checked for every pair (40 runs); the detailed logs below show baseline. Times are elapsed H:MM:SS. This review concerns causal order and consistency, not field-duration calibration.','',
    '## Findings and corrections','',
    '- Gang runs previously opened multiple footholds at the same instant and interleaved unrelated branches. They now prefer progressing an established foothold; additional access attempts consume five minutes. The starting foothold remains at time zero.',
    '- Data transfers previously waited behind unrelated expansion. They now get prompt worker priority after a read. Gang impact follows collection, transfer attempts and exploration; ARTEX pipelines access, collection and export across three workers.',
    '- Duplicate capabilities and excluded techniques previously consumed full action durations. They now consume no worker time. Concurrent attempts for the same capability wait for the first result; an alternate path remains available if the first fails.',
    '- Genuine failed probes and route reviews retain their elapsed time and appear as NO ACCESS or PATH REVIEW. Reviews name the known source, without exposing an unvisited target.',
    '- A session-to-execution upgrade previously failed to reopen outgoing routes. Route keys now include source capabilities and are captured when an attempt starts. Capability ownership preserves the relevant session for containment.',
    '- A running check cannot retroactively use a credential recovered after it started. Newly learned access needs another scheduled attempt.','',
    'Different routes are not forced: shared documented techniques may overlap, and blocked exports or limited footholds remain legitimate outcomes. The first foothold and five-minute additional access cost are explicit scenario assumptions, not incident measurements.','',
    '## Pair summaries','',
    '| Gang / seed | Gang result | ARTEX result | Gang timed dead ends | ARTEX timed dead ends |',
    '| --- | --- | --- | ---: | ---: |'];
  for(const row of rows){
    const failed=run=>run.events.filter(e=>e.outcome==='ineligible'&&e.timeSec>e.startSec).length;
    lines.push(`| ${row.gang} / ${row.seed} | ${row.gangRun.result.label} | ${row.artexRun.result.label} | ${failed(row.gangRun)} | ${failed(row.artexRun)} |`);
  }
  lines.push('','## Detailed activity logs','',
    'These show the completed sequence, including timed dead ends; the historical playback presents the same activity newest first. Source-only PATH REVIEW entries describe reasoning about an unavailable continuation, rather than claiming an unreachable target was probed.','');
  for(const row of rows)for(const [actor,run]of [[row.gang,row.gangRun],['ARTEX',row.artexRun]]){
    lines.push(`### ${actor} · seed ${row.seed}`,'','| Start → end | Event | Asset / known source | Outcome |','| --- | --- | --- | --- |');
    const labels=new Map(row.estate.assets.map(asset=>[asset.id,asset.label]));
    for(const event of activity(run)){
      const id=event.analysisKind==='route_review'?event.sourceId:event.targetId;
      const detail=event.dataTransfer?` · ${event.dataTransfer.records==null?'Record count unknown':`${event.dataTransfer.records} records`} · ${event.dataTransfer.tool}`:'';
      lines.push(`| ${stamp(event.startSec)} → ${stamp(event.timeSec)} | ${keyEvent(event)}${detail} | ${labels.get(id)||id} | ${event.outcome} |`);
    }
    lines.push('');
  }
  lines.push('## Reproduce','','Run `node scripts/audit-activity-flows.cjs`. Add `--write-report docs/activity-flow-audit.md` to regenerate this report. The same checks run across baseline, virtual patching, SOC and combined defenses. `scripts/test-activity-progression.cjs` covers the capability-upgrade, scope and concurrency regressions.','');
  return lines.join('\n');
}
const rows=[];
for(const [gang,seed]of cases){
  const estate=engine.generateEstate({seed,seedExercise:true}),snapshot=JSON.stringify(estate),runs={};
  for(const mode of ['baseline','patch','soc','combined'])for(const actor of [gang,'artex']){
    const run=engine.simulateLegacyWireRun(estate,mode,actor);validate(estate,run);
    assert.deepEqual(engine.simulateLegacyWireRun(estate,mode,actor),run,'Replay retains progression');
    assert.equal(JSON.stringify(estate),snapshot,'Review does not mutate the estate');
    if(mode==='baseline')runs[actor]=run;
  }
  rows.push({gang,seed,estate,gangRun:runs[gang],artexRun:runs.artex});
  console.log(`PASS ${gang}/${seed}: ${runs[gang].result.label} | ARTEX: ${runs.artex.result.label}`);
}
const output=process.argv.indexOf('--write-report');
if(output>=0){const destination=process.argv[output+1];assert(destination);fs.writeFileSync(path.resolve(destination),generateReport(rows));}
console.log('PASS five paired logs: 40 defense/actor runs, causal prerequisites, credential timing, transfer order, worker limits, timed failures and replay');
