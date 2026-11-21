// Regression coverage for the timed runner used by archived Wire playback manifests.
const assert=require('node:assert/strict');
const e=require('../js/wire-engine');
function fixture({apiEntry=false}={}) {
  const asset=(id,layerIdx,interfaces,conditions={})=>({id,groupId:id,label:id,layerIdx,interfaces,conditions,isExternalEntry:layerIdx===0,product:'Windows fixture',assumedVersion:'1'});
  const assets=[asset('entry',0,apiEntry?['https']:['email'],{userOpensAttachment:true,attachmentExecutionAllowed:true,mailFilterBlocksAttachment:false}),
    asset('management',1,['smb'],{remoteLoginEnabled:true,mfaEnforced:false}),
    asset('fleet',2,['smb'],{remoteLoginEnabled:true,mfaEnforced:false,localFilesWritable:true,startupChangesAllowed:true})];
  Object.assign(assets[2],{endpointIds:['ep1','ep2','ep3'],endpointCount:3,accessModel:'windows_remote_service'});
  assets[1].accessModel='windows_remote_service';
  const findings=[{id:'entry-finding',assetId:'entry',kind:apiEntry?'anonymous_access':'phishing_attachment',
    technique:apiEntry?'T1190':'T1566.001',requiresUserInteraction:!apiEntry,yieldsCapability:'app_exec'}];
  for(const id of ['management','fleet'])findings.push({id:`${id}-login`,assetId:id,kind:'remote_service',technique:'T1021.002',requiredPermission:'execute',requiredInterface:'smb',yieldsCapability:'app_exec'});
  findings.push({id:'persistence',assetId:'fleet',kind:'persistence',technique:'T1547.001',modeledDurationSec:10},
    {id:'encryption',assetId:'fleet',kind:'encryption',technique:'T1486',modeledDurationSec:20});
  const cred=(id,source,target,permissions,extras={})=>({id,sourceAssetId:source,requiredSourceCapability:'app_exec',targetAssetIds:[target],targetGroupIds:[],audience:target,permissions,revoked:false,expired:false,mfaRequired:false,...extras});
  return {schemaVersion:e.SCHEMA_VERSION,seed:1,preset:'comparison',assets,findings,
    relationships:[['entry','management'],['management','fleet']].map(([sourceId,targetId])=>({id:`${sourceId}-${targetId}`,sourceId,targetId,protocol:'smb',direction:'outbound',requiredSourceCapability:'app_exec'})),
    credentials:[cred('admin','entry','management',['execute']),cred('fleet-admin','management','fleet',['execute','write_local_files','persist_user'],{endpointScope:['ep1','ep2']})],
    actionOrder:assets.map(a=>a.id),defensePosture:{telemetryLayers:[0,1,2,3],decoys:[],collectionDelaySec:0,decisionDelaySec:0}};
}
const run=(x,mode='baseline',options={})=>e.simulateLegacyWireRun(x,mode,'lockbit',{actionDurations:[1,2,3,4],responseDelay:100,...options});
const x=fixture(),before=JSON.stringify(x);
const baseline=run(x);
assert.deepEqual(baseline.summary.encryptedEndpointIds,['ep1','ep2']);
assert.deepEqual(baseline.summary.persistentEndpointIds,['ep1','ep2']);
assert.equal(baseline.summary.dataReached,false,'Encryption is distinct from a data read');
assert.equal(baseline.result.impact,true);assert.equal(baseline.result.label,'Endpoint encryption');
const access=baseline.events.find(event=>event.targetId==='fleet'&&event.grantedCapability==='app_exec');
for(const event of baseline.events.filter(event=>['persistence','encryption'].includes(event.actionKind))) {
  assert(event.startSec>=access.timeSec);assert(event.timeSec>event.startSec);
  assert.equal(event.sourceId,event.targetId,'Local action does not invent a network self-loop');
  assert.equal(event.relationshipId,null);
}
assert.deepEqual(run(x,'patch').summary.encryptedEndpointIds,['ep1','ep2'],'WAF cannot reverse endpoint encryption');
assert.equal(e.simulateLegacyWireRun(x,'baseline','artex').summary.encryptedEndpointIds.length,0);
assert.equal(e.simulateLegacyWireRun(fixture({apiEntry:true}),'baseline','artex').summary.encryptedEndpointIds.length,0,'ARTEX can enter without being assigned a ransomware objective');
for(const change of ['execute','write','persist','scope','expired','revoked','route','source-capability','writable','startup']) {
  const modified=structuredClone(x),credential=modified.credentials[1];
  if(change==='execute')credential.permissions=credential.permissions.filter(p=>p!=='execute');
  if(change==='write')credential.permissions=credential.permissions.filter(p=>p!=='write_local_files');
  if(change==='persist')credential.permissions=credential.permissions.filter(p=>p!=='persist_user');
  if(change==='scope')credential.endpointScope=['unrelated-endpoint'];
  if(['expired','revoked'].includes(change))credential[change]=true;
  if(change==='route')modified.relationships.pop();
  if(change==='source-capability')modified.credentials[1].requiredSourceCapability='unestablished';
  if(change==='writable')modified.assets[2].conditions.localFilesWritable=false;
  if(change==='startup')modified.assets[2].conditions.startupChangesAllowed=false;
  const result=run(modified);
  if(!['persist','startup'].includes(change))assert.equal(result.summary.encryptedEndpointIds.length,0,change);
  if(!['write','writable'].includes(change))assert.equal(result.summary.persistentEndpointIds.length,0,change);
}
// A desktop sign-in policy does not protect every protocol accepting the account.
for(const protocol of ['smb','wmi','rdp']) {
  const modified=structuredClone(x),fleet=modified.assets[2];
  fleet.interfaces=[protocol];fleet.conditions.mfaProtocols=['rdp'];
  modified.credentials[1].mfaRequired=true; // Legacy account flag must not gate SMB/WMI.
  modified.relationships[1].protocol=protocol;
  Object.assign(modified.findings.find(f=>f.id==='fleet-login'),{
    requiredInterface:protocol,technique:{smb:'T1021.002',wmi:'T1047',rdp:'T1021.001'}[protocol]});
  const state={reachedAssets:new Map([['management',{capabilities:new Set(['app_exec'])}]]),
    acquiredCredentials:new Map([[modified.credentials[1].id,modified.credentials[1]]]),revokedCredentials:new Set()};
  const routeCheck=()=>e.evaluateAction(state,modified.assets[1],fleet,modified.relationships[1],modified);
  assert.equal(routeCheck().eligible,protocol!=='rdp',`${protocol} respects its own MFA policy`);
  if(protocol!=='rdp')assert.equal(run(modified).summary.encryptedEndpointIds.length,2,'Scoped remote execution still enables local encryption');
  if(protocol==='rdp') {
    assert.equal(routeCheck().reason,'RDP access requires MFA.');
    fleet.conditions.mfaProtocols=[];
    assert.equal(routeCheck().eligible,true,'RDP without an MFA gate accepts scoped credentials');
  }
}
const phished=structuredClone(x);
phished.assets[0].conditions.mfaEnforced=true;
phished.assets[0].conditions.mfaProtocols=['rdp'];
phished.assets[0].conditions.localFilesWritable=true;
phished.assets[0].conditions.startupChangesAllowed=true;
phished.assets[0].localUserPermissions=['write_local_files','persist_user'];
phished.findings.push(...phished.findings.filter(f=>['persistence','encryption'].includes(f.kind))
  .map(f=>({...f,id:`entry-${f.id}`,assetId:'entry'})));
const phishRun=run(phished);
assert(phishRun.summary.encryptedEndpointIds.includes('entry'),'Existing phished execution can encrypt writable files without a new MFA check');
assert(phishRun.summary.persistentEndpointIds.includes('entry'),'Existing phished execution can install permitted startup persistence');
const early=run(x,'soc',{responseDelay:10});
assert.equal(early.summary.encryptedEndpointIds.length,0);assert.equal(early.summary.persistentEndpointIds.length,0);
const middle=run(x,'soc',{responseDelay:20});
assert.equal(middle.summary.encryptedEndpointIds.length,0);assert.equal(middle.summary.persistentEndpointIds.length,2);
assert(middle.events.some(event=>event.actionKind==='encryption'&&event.outcome==='suppressed'));
assert.equal(middle.result.label,'Session contained; persistence was established');
const late=run(x,'soc',{responseDelay:100});
assert.equal(late.summary.encryptedEndpointIds.length,2);assert.equal(late.result.label,'Endpoint encryption before containment');
const tie=run(x,'soc',{responseDelay:33});
assert.equal(tie.summary.encryptedEndpointIds.length,0,'Containment wins exact encryption-completion ties');
const noTelemetry=structuredClone(x);noTelemetry.defensePosture.telemetryLayers=[];
assert.equal(run(noTelemetry,'soc',{responseDelay:0}).summary.encryptedEndpointIds.length,2);
assert.equal(JSON.stringify(x),before);assert.deepEqual(run(x),baseline);

// A credential recovered later can unlock an already explored directed route.
const delayed=fixture({apiEntry:true});
delayed.assets.push({id:'donor',groupId:'donor',label:'Credential donor',layerIdx:2,interfaces:['https'],conditions:{}});
delayed.actionOrder.push('donor');
delayed.findings.push({id:'donor-access',assetId:'donor',kind:'anonymous_access',technique:'T1190',yieldsCapability:'app_exec'});
delayed.relationships.push({id:'management-donor',sourceId:'management',targetId:'donor',protocol:'https',direction:'outbound',requiredSourceCapability:'app_exec'});
delayed.credentials[1].sourceAssetId='donor';
const discovered=e.simulateLegacyWireRun(delayed,'baseline','artex',{actionDurations:[1,2,3,4]});
const fleetAttempts=discovered.events.filter(event=>event.targetId==='fleet');
assert.equal(fleetAttempts[0].outcome,'ineligible');
assert(fleetAttempts.some(event=>event.outcome==='succeeded'),'Recovering a scoped credential unlocks the prior route');
const donorAccess=discovered.events.find(event=>event.targetId==='donor'&&event.outcome==='succeeded');
assert(fleetAttempts.find(event=>event.outcome==='succeeded').startSec>=donorAccess.timeSec,'Recovered credential cannot unlock access before acquisition');
const duringProbe=structuredClone(delayed);
duringProbe.assets.find(a=>a.id==='donor').layerIdx=1;
const changing=e.simulateLegacyWireRun(duringProbe,'baseline','artex',{actionDurations:[1,2,20,4]});
const recoveredAt=changing.events.find(event=>event.targetId==='donor'&&event.outcome==='succeeded').timeSec;
for(const event of changing.events.filter(event=>event.targetId==='fleet'&&event.outcome==='succeeded'))
  assert(event.startSec>=recoveredAt,'An in-flight failed probe cannot retroactively use a credential recovered after it started');

const located=fixture({apiEntry:true});
located.assets.push({id:'records',groupId:'records',label:'Records',layerIdx:3,interfaces:['https'],conditions:{}});
located.actionOrder.push('records');
located.relationships.push({id:'fleet-records',sourceId:'fleet',targetId:'records',protocol:'https',direction:'outbound',requiredSourceCapability:'app_exec'});
located.credentials.push({id:'endpoint-stored-secret',sourceAssetId:'fleet',sourceEndpointIds:['ep3'],requiredSourceCapability:'app_exec',
  targetAssetIds:['records'],targetGroupIds:[],audience:'records',permissions:['read']});
assert.equal(run(located).summary.dataReached,false,'Cannot recover a secret stored only on an unexecuted fleet endpoint');
located.credentials.at(-1).sourceEndpointIds=['ep1'];
assert.equal(run(located).summary.dataReached,true,'Secret becomes available only on an executed source endpoint');

const kinds=new Set(),statuses=new Set(),fleetSizes=new Set();
for(let seed=1;seed<=50;seed++) {
  const estate=e.generateEstate({seed,seedExercise:true}),snapshot=JSON.stringify(estate);
  const fleets=estate.assets.filter(a=>a.endpointIds);
  assert(fleets.length>=2&&fleets.length<=3);
  for(const fleet of fleets) {assert(fleet.endpointCount>=12&&fleet.endpointCount<=80);fleetSizes.add(fleet.endpointCount);}
  assert(estate.relationships.some(r=>r.sourceId.startsWith('windows-fleet-')&&!r.targetId.startsWith('windows-')),'Workforce uses actual estate applications');
  for(const credential of estate.credentials.filter(c=>c.provenance==='synthetic_deployment_assumption')) {
    kinds.add(credential.kind);if(credential.revoked)statuses.add('revoked');if(credential.expired)statuses.add('expired');
    if(credential.mfaRequired)statuses.add('mfa');
  }
  if(estate.assets.some(a=>a.conditions?.mfaEnforced || a.conditions?.mfaProtocols?.length))statuses.add('mfa');
  for(const actor of ['lockbit','conti','hive','blackcat','revil','artex']) {
    const result=e.simulateLegacyWireRun(estate,'baseline',actor);
    assert.deepEqual(e.simulateLegacyWireRun(estate,'baseline',actor),result);
    for(const event of result.events.filter(event=>event.outcome==='succeeded'&&event.affectedEndpointIds)) {
      const asset=estate.assets.find(a=>a.id===event.targetId);
      const inventory=asset.endpointIds||[asset.id];assert(event.affectedEndpointIds.every(id=>inventory.includes(id)));
      assert(result.events.some(access=>access.targetId===asset.id&&access.grantedCapability==='app_exec'&&access.timeSec<=event.startSec));
    }
    if(actor==='artex')assert.equal(result.summary.encryptedEndpointIds.length,0);
  }
  assert.equal(JSON.stringify(estate),snapshot);
}
assert.deepEqual([...kinds].sort(),['department_user','deployment_service','domain_admin','helpdesk','local_admin']);
assert.equal(statuses.size,3);assert(fleetSizes.size>10);
console.log('PASS Windows fleets: scoped execution/write/persistence, randomized accounts, integrated estate, timed containment, preserved impact, actor objectives and replay');
