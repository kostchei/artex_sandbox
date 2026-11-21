// Regression coverage for the timed runner used by archived Wire playback manifests.
const assert=require('node:assert/strict');
const e=require('../js/wire-engine');
function fixture(protocol='rdp',tool=false) {
  const conditions={userOpensAttachment:true,attachmentExecutionAllowed:true,mailFilterBlocksAttachment:false,
    remoteLoginEnabled:true,mfaProtocols:[]};
  const assets=[{id:'entry',groupId:'entry',label:'Entry',layerIdx:0,isExternalEntry:true,interfaces:['email','https'],conditions},
    {id:'target',groupId:'target',label:'Target',layerIdx:1,interfaces:[protocol],accessModel:'windows_remote_service',conditions:{...conditions}}];
  const findings=[{id:'phish',assetId:'entry',kind:'phishing_attachment',technique:'T1566.001',requiresUserInteraction:true,yieldsCapability:'app_exec'},
    {id:'web',assetId:'entry',kind:'anonymous_access',technique:'T1190',yieldsCapability:'app_exec'},
    {id:'remote',assetId:'target',kind:'remote_service',technique:protocol==='rdp'?'T1021.001':protocol==='smb'?'T1569.002':'T1047',
      requiredInterface:protocol,requiredPermission:protocol==='smb'?'service_execute':'execute',yieldsCapability:'app_exec',
      ...(tool&&{tool:'cobalt_strike',requiredSourceCapability:'app_exec'})}];
  return {schemaVersion:e.SCHEMA_VERSION,seed:3,preset:'comparison',assets,findings,actionOrder:['entry','target'],
    relationships:[{id:'route',sourceId:'entry',targetId:'target',protocol,direction:'outbound',requiredSourceCapability:'app_exec'}],
    credentials:[{id:'admin',sourceAssetId:'entry',requiredSourceCapability:'app_exec',targetAssetIds:['target'],audience:'target',
      permissions:['execute','service_execute'],revoked:false,expired:false}],
    defensePosture:{telemetryLayers:[0,1,2,3],decoys:[],collectionDelaySec:0,decisionDelaySec:0}};
}
const run=(x,actor,options={},mode='baseline')=>e.simulateLegacyWireRun(x,mode,actor,{actionDurations:[0,20,20,20],...options});
const reached=r=>r.events.find(x=>x.targetId==='target'&&x.outcome==='succeeded');
for(const actor of ['lockbit','conti','blackcat','hive','revil','artex']) {
  const x=fixture(),before=JSON.stringify(x),result=run(x,actor);
  assert.equal(reached(result)?.technique,'T1021.001',`${actor} supports internal RDP`);
  assert.deepEqual(run(x,actor),result);assert.equal(JSON.stringify(x),before);
  x.assets[1].conditions.mfaProtocols=['rdp'];
  assert(!reached(run(x,actor)),`${actor} RDP cannot bypass MFA`);
}
for(const protocol of ['smb','wmi'])for(const actor of ['lockbit','conti','blackcat','hive','revil']) {
  const x=fixture(protocol,true),result=run(x,actor),hop=reached(result);
  assert.equal(hop?.tool,'cobalt_strike',`${actor} uses the configured ${protocol} tool route`);
  assert.equal(hop.attackerEvidence.basis,'affiliate_reporting');assert(hop.attackerEvidence.methodSource);
  assert.equal(reached(run(x,actor,{},'patch'))?.tool,'cobalt_strike','HTTP WAF does not block lateral tooling');
  assert(!reached(run(x,actor,{attackerProfile:{availableTools:[]}})),'Missing tool inventory denies tool use');
  for(const change of ['credential','permission','expired','revoked','audience','route','source']) {
    const altered=structuredClone(x);
    if(change==='credential')altered.credentials=[];
    if(change==='permission')altered.credentials[0].permissions=['read'];
    if(['expired','revoked'].includes(change))altered.credentials[0][change]=true;
    if(change==='audience')altered.credentials[0].audience='unrelated';
    if(change==='route')altered.relationships=[];
    if(change==='source') {
      altered.findings=altered.findings.filter(f=>f.kind!=='phishing_attachment');
      altered.findings.filter(f=>f.assetId==='entry').forEach(f=>f.yieldsCapability='account_session');
    }
    assert(!reached(run(altered,actor)),`${actor}/${protocol}: ${change}`);
  }
}
const cobalt=fixture('smb',true);
assert.equal(reached(run(cobalt,'hive'))?.attackerEvidence.source,'https://www.hhs.gov/sites/default/files/ransomware-trends-q1-2022.pdf',
  'Hive tool use is separately sourced from HHS rather than invented in the software catalogue');
assert(!reached(run(cobalt,'artex')),'ARTEX has no assumed Cobalt Strike inventory');
assert.equal(reached(run(cobalt,'artex',{attackerProfile:{availableTools:['cobalt_strike']}}))?.attackerEvidence.basis,'modeled_action');
cobalt.credentials[0].permissions=['execute'];
assert(!reached(run(cobalt,'revil')),'Generic execution permission cannot create a remote service');
const rawWmi=fixture('wmi');
assert(!reached(run(rawWmi,'revil',{attackerProfile:{availableTools:[]}})),'Local WMI process-killing mapping does not license remote execution');
const fallback=e.generateEstate({seed:3,seedExercise:true});
assert(run(fallback,'revil',{attackerProfile:{availableTools:[]}}).events.some(x=>
  x.outcome==='succeeded'&&x.technique==='T1021.001'),'REvil selects internal RDP when Beacon inventory is disabled');
const sourceCheck=fixture('wmi',true);
delete sourceCheck.findings.find(f=>f.tool).requiredSourceCapability;
sourceCheck.relationships[0].requiredSourceCapability='account_session';
const state={reachedAssets:new Map([['entry',{capabilities:new Set(['account_session'])}]]),
  acquiredCredentials:new Map([['admin',sourceCheck.credentials[0]]]),revokedCredentials:new Set()};
assert.equal(e.evaluateAction(state,sourceCheck.assets[0],sourceCheck.assets[1],sourceCheck.relationships[0],sourceCheck).eligible,false,
  'A custom finding cannot omit the source execution prerequisite for Beacon');
const early=run(fixture('wmi',true),'revil',{responseDelay:0},'soc');
assert(!reached(early),'Containment stops tool movement before completion');
assert.equal(reached(run(fixture('wmi',true),'revil',{responseDelay:1000},'soc'))?.tool,'cobalt_strike');
for(const actor of ['lockbit','conti','blackcat','hive','revil','artex']) {
  const x=fixture('smb',true);x.findings.find(f=>f.tool).tool='psexec';
  const options=actor==='artex'?{attackerProfile:{availableTools:['psexec']}}:{};
  assert.equal(reached(run(x,actor,options))?.tool,'psexec',`${actor} can select scoped PsExec service execution`);
  assert(!reached(run(x,actor,{attackerProfile:{availableTools:[]}})));
  x.credentials[0].permissions=['execute'];
  assert(!reached(run(x,actor,options)),`${actor} PsExec cannot bypass service permissions`);
}
function alternatives() {
  const x=fixture();x.assets[1].interfaces=['smb','wmi','rdp'];
  const sources=[fixture('smb',true),fixture('wmi',true),fixture('wmi'),fixture('rdp')];
  x.findings=x.findings.filter(f=>f.assetId==='entry');
  sources.forEach((source,i)=>x.findings.push({...source.findings.find(f=>f.assetId==='target'),id:`method-${i}`}));
  x.findings.push({...x.findings.find(f=>f.tool&&f.requiredInterface==='smb'),id:'psexec',tool:'psexec'});
  x.relationships=['wmi','rdp','smb'].map(protocol=>({...x.relationships[0],id:`route-${protocol}`,protocol}));
  return x;
}
const method=hop=>hop.tool==='cobalt_strike'?`cobalt_strike:${hop.finding.requiredInterface}`:hop.tool||hop.technique;
for(const [actor,preferred] of Object.entries({lockbit:'psexec',conti:'cobalt_strike:wmi',blackcat:'psexec',hive:'T1021.001',revil:'cobalt_strike:smb'})) {
  const x=alternatives(),snapshot=JSON.stringify(x),result=run(x,actor);
  assert.equal(method(reached(result)),preferred,`${actor} selects its explicit preferred method`);
  assert.equal(reached(result).attackerEvidence.selectionPreference.basis,'authored_order_among_reported_methods');
  const reversed=structuredClone(x);reversed.relationships.reverse();reversed.findings.reverse();
  assert.equal(method(reached(run(reversed,actor))),preferred,'Incidental array order cannot choose a different method');
  assert.deepEqual(run(x,actor),result);assert.equal(JSON.stringify(x),snapshot);
  const fallback=structuredClone(x);
  if(preferred==='T1021.001')fallback.assets[1].conditions.mfaProtocols=['rdp'];
  else fallback.findings=fallback.findings.filter(f=>method({tool:f.tool,technique:f.technique,finding:f})!==preferred);
  const alternative=reached(run(fallback,actor));assert(alternative,`${actor} retains eligible alternatives`);
  assert.notEqual(method(alternative),preferred);
}
console.log('PASS lateral tools: sourced gang RDP and Beacon, configured ARTEX tools, service rights, source execution, route/credential/MFA gates, WAF scope, containment and replay');
