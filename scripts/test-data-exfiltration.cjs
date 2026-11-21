// Regression coverage for the timed runner used by archived Wire playback manifests.
const assert=require('node:assert/strict');
const e=require('../js/wire-engine');
const gangs=['lockbit','conti','blackcat','hive','revil'];
function fixture(){
  const assets=[0,1,2,3].map(layerIdx=>({id:`a${layerIdx}`,groupId:`a${layerIdx}`,label:`Asset ${layerIdx}`,
    layerIdx,product:'Fixture',assumedVersion:'1',interfaces:layerIdx===0?['https','email']:layerIdx===3?['db']:['smb','wmi','rdp'],
    isExternalEntry:layerIdx===0,conditions:{userOpensAttachment:true,attachmentExecutionAllowed:true,mailFilterBlocksAttachment:false,remoteLoginEnabled:true,mfaEnforced:false},
    egress:{cloudUploadAllowed:true,responseExportAllowed:true}}));
  const findings=[{id:'phish',assetId:'a0',kind:'phishing_attachment',technique:'T1566.001',requiresUserInteraction:true,yieldsCapability:'app_exec'},
    {id:'public-entry',assetId:'a0',kind:'anonymous_access',technique:'T1190',yieldsCapability:'app_exec'}];
  const relationships=[],credentials=[];
  for(let layer=1;layer<=2;layer++){
    assets[layer].accessModel='windows_remote_service';
    for(const [protocol,technique]of [['smb','T1021.002'],['wmi','T1047'],['rdp','T1021.001']]){
      relationships.push({id:`r${layer}-${protocol}`,sourceId:`a${layer-1}`,targetId:`a${layer}`,protocol,direction:'outbound',requiredSourceCapability:'app_exec'});
      findings.push({id:`f${layer}-${protocol}`,assetId:`a${layer}`,kind:'remote_service',technique,requiredInterface:protocol,requiredPermission:'execute',yieldsCapability:'app_exec'});
    }
    credentials.push({id:`c${layer}`,sourceAssetId:`a${layer-1}`,requiredSourceCapability:'app_exec',targetAssetIds:[`a${layer}`],audience:`a${layer}`,permissions:['execute']});
  }
  relationships.push({id:'r3',sourceId:'a2',targetId:'a3',protocol:'db',direction:'outbound',requiredSourceCapability:'app_exec'});
  credentials.push({id:'c3',sourceAssetId:'a2',requiredSourceCapability:'app_exec',targetAssetIds:['a3'],audience:'a3',permissions:['read']});
  assets[3].dataHandling={label:'Customer records',records:1000,bytes:1024000};
  return {schemaVersion:e.SCHEMA_VERSION,seed:9,preset:'comparison',assets,relationships,credentials,findings,
    actionOrder:assets.map(a=>a.id),defensePosture:{telemetryLayers:[0,1,2,3],decoys:[],collectionDelaySec:0,decisionDelaySec:0,responseDelaySec:10000}};
}
const options={actionDurations:[0,10,10,10],decisionDelay:0,responseDelay:10000};
const run=(estate,actor='artex',mode='baseline',extra={})=>e.simulateLegacyWireRun(estate,mode,actor,{...options,...extra});
const transferred=r=>r.events.find(x=>x.actionKind==='data_exfiltration'&&x.outcome==='succeeded');
for(const actor of [...gangs,'artex']){
  const estate=fixture(),snapshot=JSON.stringify(estate),result=run(estate,actor);
  const read=result.events.find(x=>x.isProtectedRead&&x.outcome==='succeeded'),transfer=transferred(result);
  assert(read,`${actor} reaches readable data`);assert(transfer,`${actor} exports readable data`);
  assert(transfer.startSec>=read.timeSec);assert(transfer.timeSec>transfer.startSec);
  assert.equal(transfer.dataTransfer.datasetId,read.targetId);
  assert.equal(transfer.dataTransfer.records,1000);
  assert.equal(transfer.dataTransfer.bytes,1024000);
  assert.equal(result.summary.exfiltratedDatasets.length,1);
  const privateEstate=structuredClone(estate);
  privateEstate.assets.push({...structuredClone(privateEstate.assets[3]),id:'private',groupId:'private',label:'Unreachable private records'});
  privateEstate.actionOrder.push('private');
  assert(!run(privateEstate,actor).summary.exfiltratedDatasets.some(d=>d.datasetId==='private'),'Bulk transfer cannot include unreadable datasets');
  assert.deepEqual(run(estate,actor),result);assert.equal(JSON.stringify(estate),snapshot);
  for(const dataHandling of [undefined,{records:1000},{bytes:1024000},{records:-1,bytes:NaN}]){
    const unknown=structuredClone(estate);
    unknown.assets[3].dataHandling=dataHandling;
    const unknownSnapshot=JSON.stringify(unknown),unknownRun=run(unknown,actor),exported=transferred(unknownRun);
    assert(exported,`${actor}: data volume is not an access prerequisite`);
    assert.equal(exported.dataTransfer.records,dataHandling?.records>0?dataHandling.records:null);
    assert.equal(exported.dataTransfer.bytes,dataHandling?.bytes>0?dataHandling.bytes:null);
    assert(Number.isFinite(exported.timeSec)&&exported.timeSec>exported.startSec);
    assert.deepEqual(run(unknown,actor),unknownRun);assert.equal(JSON.stringify(unknown),unknownSnapshot);
    unknown.assets.forEach(a=>a.egress={cloudUploadAllowed:false,responseExportAllowed:false});
    const denied=run(unknown,actor);
    assert(!transferred(denied),'Unknown volume cannot bypass denied egress');
    assert(denied.events.some(e=>e.actionKind==='data_exfiltration'&&e.outcome==='blocked'));
    unknown.assets.forEach(a=>{delete a.egress;});
    const unspecified=run(unknown,actor);
    assert(!transferred(unspecified),'Unknown policy cannot grant egress');
    assert(unspecified.events.some(e=>e.actionKind==='data_exfiltration'&&/outbound policy is unspecified/.test(e.reason)));
  }
  if(actor!=='artex')assert(e.gangTechniqueEvidence(actor,transfer.technique),'Gang transfer has sourced technique evidence');
  for(const removed of ['read','egress','execution']){
    const changed=structuredClone(estate);
    if(removed==='read')changed.credentials=changed.credentials.filter(c=>c.id!=='c3');
    if(removed==='egress')changed.assets.forEach(a=>a.egress={cloudUploadAllowed:false,responseExportAllowed:false});
    if(removed==='execution')changed.relationships=changed.relationships.filter(r=>r.sourceId!=='a0');
    const failed=run(changed,actor);
    assert(!transferred(failed),`${actor}: no export without ${removed}`);
    if(removed==='egress'){
      assert(failed.events.some(x=>x.isProtectedRead&&x.outcome==='succeeded'),'Egress denial preserves earlier data discovery');
      assert(failed.events.some(x=>x.actionKind==='data_exfiltration'&&x.outcome==='blocked'));
      assert.equal(failed.summary.exfiltratedDatasets.length,0);
    }
  }
}
// Enforcement wins ties and cancels a transfer without erasing the earlier read.
const estate=fixture(),base=run(estate),transfer=transferred(base),read=base.events.find(x=>x.isProtectedRead);
// First correlated boundary signal is at a1=10, hence enforcement = 10 + responseDelay.
for(const enforcement of [read.timeSec+1,transfer.timeSec,transfer.timeSec+1]){
  const result=run(estate,'artex','soc',{responseDelay:enforcement-10});
  assert(result.events.some(x=>x.isProtectedRead&&x.outcome==='succeeded'));
  assert.equal(!!transferred(result),enforcement>transfer.timeSec,'Transfer survives only when it completes before enforcement');
  if(enforcement<=transfer.timeSec)assert(result.events.some(x=>x.actionKind==='data_exfiltration'&&x.outcome==='suppressed'));
}
const noRead=run(estate,'artex','soc',{responseDelay:5});
assert(!noRead.events.some(x=>x.isProtectedRead&&x.outcome==='succeeded'));assert(!transferred(noRead));
console.log('PASS data transfers: all actor methods, full accessible dataset export, read/execution/egress gates, immutable replay, containment before/during/after and exact ties');
