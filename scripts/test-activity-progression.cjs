// Regression coverage for the timed runner used by archived Wire playback manifests.
const assert=require('node:assert/strict');
const e=require('../js/wire-engine');
const success=run=>run.events.filter(event=>event.outcome==='succeeded');
const run=(estate,actor='artex',mode='baseline',options={})=>e.simulateLegacyWireRun(estate,mode,actor,options);

// Hive first has an account session through the Windows branch, then obtains
// execution through a different foothold. Retry outgoing execution routes and
// attribute their containment scope to the execution-owning session.
const hive=run(e.generateEstate({seed:42,seedExercise:true}),'hive');
const account=success(hive).find(event=>event.targetId==='app-engine-2'&&event.grantedCapability==='account_session');
const execution=success(hive).find(event=>event.targetId==='app-engine-2'&&event.grantedCapability==='app_exec');
const read=success(hive).find(event=>event.targetId==='redis-debian-1'&&event.isProtectedRead);
assert(account&&execution&&read);assert(account.timeSec<execution.timeSec);assert.notEqual(account.scope,execution.scope);
assert(read.startSec>=execution.timeSec);assert.equal(read.scope,execution.scope);

const asset=(id,layerIdx,interfaces=['https'])=>({id,groupId:id,label:id,product:'Fixture',assumedVersion:'1',layerIdx,interfaces,conditions:{},isExternalEntry:layerIdx===0});
function sharedTarget(patchedLeft=false){
  const assets=[asset('left',0),asset('right',0),asset('shared',1,patchedLeft?['https','api-https']:['https'])];
  const relationships=['left','right'].map(sourceId=>({
    id:`${sourceId}-shared`,
    sourceId,
    targetId:'shared',
    protocol:patchedLeft&&sourceId==='right'?'api-https':'https',
    direction:'outbound',
    requiredSourceCapability:'app_exec'
  }));
  const findings=assets.filter(a=>a.layerIdx===0).map(a=>({id:`f-${a.id}`,assetId:a.id,kind:'anonymous_access',
    technique:'T1190',yieldsCapability:'app_exec'}));
  if(patchedLeft){
    findings.push(
      {id:'f-left-shared',assetId:'shared',kind:'cve',cveId:'CVE-2022-1388',requiredProduct:'Fixture',affectedVersions:['1'],requiredConditions:{},sourceUrl:'https://nvd.nist.gov/vuln/detail/CVE-2022-1388',requiredInterface:'https',technique:'T1190',yieldsCapability:'app_exec'},
      {id:'f-right-shared',assetId:'shared',kind:'cve',cveId:'CVE-2023-46747',requiredProduct:'Fixture',affectedVersions:['1'],requiredConditions:{},sourceUrl:'https://nvd.nist.gov/vuln/detail/CVE-2023-46747',requiredInterface:'api-https',technique:'T1190',yieldsCapability:'app_exec'}
    );
  } else {
    findings.push({id:'f-shared',assetId:'shared',kind:'anonymous_access',yieldsCapability:'app_exec',technique:'T1190'});
  }
  return {schemaVersion:e.SCHEMA_VERSION,preset:'comparison',seed:1,assets,relationships,findings,credentials:[],actionOrder:assets.map(a=>a.id),defensePosture:{telemetryLayers:[],decoys:[]}};
}
const timing={actionDurations:[0,10,10,10],reentryDurationSec:0};
const shared=run(sharedTarget(),'artex','baseline',timing);
assert.equal(success(shared).filter(event=>event.targetId==='shared').length,1,'Workers do not race for the same already planned capability');
const revisit=shared.events.find(event=>event.targetId==='shared'&&event.outcome==='revisit');
assert(revisit);assert.equal(revisit.timeSec,revisit.startSec,'Redundant alternative consumes no additional attack time');
const alternate=run(sharedTarget(true),'artex','patch',timing);
const blocked=alternate.events.find(event=>event.targetId==='shared'&&event.outcome==='blocked');
const passed=success(alternate).find(event=>event.targetId==='shared');
assert(blocked&&passed);assert(passed.startSec>=blocked.timeSec,'A failed first attempt leaves the alternate route available');

const lockbit=run(e.generateEstate({seed:1853,seedExercise:true}),'lockbit');
const access=success(lockbit),firstMove=access.find(event=>event.sourceId&&event.sourceId!==event.targetId);
const nextEntry=access.filter(event=>!event.sourceId)[1];
assert.equal(access[0].technique,'T1133');assert.equal(firstMove.targetId,'windows-management');
assert(firstMove.timeSec<nextEntry.timeSec,'Gang follows the initial foothold before opening another');
const revil=run(e.generateEstate({seed:99,seedExercise:true}),'revil');
const deadEnd=revil.events.find(event=>event.outcome==='ineligible'&&event.timeSec>event.startSec);
assert(deadEnd,'An unsuccessful continuation still costs time');
assert.equal(deadEnd.finding.requiredInterface,e.generateEstate({seed:99,seedExercise:true}).relationships.find(r=>r.id===deadEnd.relationshipId).protocol,
  'Failure evidence names the actual attempted transport');
assert(e.gangTechniqueEvidence('revil',deadEnd.finding.technique,deadEnd.finding),'Failure names a supported method');
const encryption=success(revil).find(event=>event.actionKind==='encryption');
assert(encryption.startSec>=deadEnd.timeSec,'The gang checks its available continuation before applying local impact');

const artex=run(e.generateEstate({seed:1853,seedExercise:true}));
const transfer=success(artex).find(event=>event.actionKind==='data_exfiltration');
assert(transfer);
assert(artex.events.some(event=>event.startSec<transfer.timeSec&&event.timeSec>transfer.timeSec),'ARTEX exports while another worker continues');
assert(!success(artex).some(event=>['encryption','persistence'].includes(event.actionKind)));
console.log('PASS progression: capability upgrades, session ownership, concurrent deduplication, retained alternatives, foothold continuity, timed dead ends, parallel bulk export');
