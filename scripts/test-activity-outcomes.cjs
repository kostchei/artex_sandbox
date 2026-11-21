const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const engine=require('../js/wire-engine');
const RunDiscovery=require('../js/run-discovery');
const root=path.resolve(__dirname,'..');
const estate=engine.generateEstate({seed:3060107786,seedExercise:true});
const run=engine.simulateWireRun(estate,'baseline','artex');
const snapshot=JSON.stringify(run);
const context=vm.createContext({
  location:{search:'?embedded=1'},URLSearchParams,
  document:{documentElement:{classList:{add(){}}},createElement:()=>({}),head:{append(){}}},
  window:{},RunDiscovery,estate,run,discoveryStarted:true,modeledTime:Infinity,
  formatEstimate:seconds=>`${seconds}s`
});
// The page loads attack-feed.js before dual-bridge.js and exposes AttackFeed globally.
vm.runInContext(fs.readFileSync(path.join(root,'js/attack-feed.js'),'utf8'),context);
context.AttackFeed=context.window.AttackFeed;
vm.runInContext(fs.readFileSync(path.join(root,'js/dual-bridge.js'),'utf8'),context);
const activity=()=>context.window.comparison.activity();
const transfer=run.events.find(event=>event.actionKind==='data_exfiltration'&&event.outcome==='succeeded');
const read=run.events.find(event=>event.isProtectedRead&&event.outcome==='succeeded');
assert(read&&transfer);
const laterFailure=activity().find(item=>item.code==='NO NEW ACCESS'&&item.time>transfer.timeSec);
assert(laterFailure,'Retain failed branches after a real completed export');
assert.match(laterFailure.detail,/This attempt gained no new access/);
assert.match(laterFailure.detail,/Earlier data exfiltration remains successful/);
assert.equal(run.result.label,'Data exfiltrated');
assert(activity().some(item=>item.code==='DATA EXFILTRATED'));
const completed=activity();
assert.equal(completed[0].code,'DATA EXFILTRATED','Completed export stays above later hunting activity');
for(const pinned of [true,false]){
  const group=completed.filter(item=>(item.code==='DATA EXFILTRATED')===pinned);
  assert(group.every((item,index)=>!index||group[index-1].time>=item.time),'Each group remains newest first');
}
assert(completed.findIndex(item=>item.id===laterFailure.id)>completed.findLastIndex(item=>item.code==='DATA EXFILTRATED'));
context.modeledTime=transfer.timeSec;
assert.equal(activity()[0].code,'DATA EXFILTRATED','Pin export as soon as it completes');
context.run={...run,events:run.events.map(event=>event.actionKind==='data_exfiltration'
  ?{...event,outcome:'blocked',reason:'Egress denied.'}:event)};
assert.equal(activity()[0].code,'EXFILTRATION BLOCKED','Blocked transfers are pinned too');
context.modeledTime=Infinity;
for(const outcome of ['blocked','suppressed','ineligible']){
  context.run={...run,events:run.events.map(event=>event.actionKind==='data_exfiltration'
    ?{...event,outcome,reason:'Transfer cannot complete.'}:event)};
  assert(activity()[0].isExport,'Every export outcome stays above later hunting failures');
  assert(activity().filter(item=>item.isExport).every((item,index,items)=>!index||items[index-1].time>=item.time));
}
const legacy=structuredClone(estate);
legacy.assets.forEach(asset=>{delete asset.dataHandling;asset.egress={cloudUploadAllowed:true,responseExportAllowed:true};});
legacy.datasets.forEach(dataset=>{delete dataset.records;delete dataset.bytes;});
context.run=engine.simulateWireRun(legacy,'baseline','artex');
assert(context.run.events.some(event=>event.isProtectedRead),'Legacy estate retains confirmed reads');
assert(context.run.summary.exfiltratedDatasets.length>0,'Unknown volume does not block an authorized export path');
assert.equal(activity()[0].code,'DATA EXFILTRATED');
assert.match(activity()[0].detail,/Record count unknown.*Data size unknown/);
assert.doesNotMatch(activity()[0].detail,/null|undefined|0 records/);
legacy.assets.forEach(asset=>{delete asset.egress;});
context.run=engine.simulateWireRun(legacy,'baseline','artex');
assert.equal(context.run.summary.exfiltratedDatasets.length,0,'Unknown outbound policy does not imply permission');
assert.equal(activity()[0].code,'EXPORT NOT ATTEMPTED');
assert.match(activity()[0].detail,/outbound policy is unspecified/);
context.run=run;context.modeledTime=Infinity;
assert(activity().filter(item=>item.time<read.timeSec).every(item=>!/Earlier data/.test(item.detail)),
  'Never leak future reads or exports into earlier failures');
context.modeledTime=read.timeSec;
assert(!activity().some(item=>item.code==='DATA EXFILTRATED'),'A read is not an export');
// Exercise the read-only interval separately from the subsequent transfer.
const failure={sourceId:read.sourceId,targetId:'unrelated',startSec:read.timeSec,timeSec:read.timeSec+1,
  outcome:'ineligible',reason:'No access established for unrelated.'};
context.run={...run,events:[read,failure,transfer]};context.modeledTime=failure.timeSec;
const readOnly=activity().find(item=>item.code==='NO NEW ACCESS');
assert.match(readOnly.detail,/Earlier data access remains successful/);
assert.doesNotMatch(readOnly.detail,/Earlier data exfiltration remains successful/);
assert(!activity().some(item=>item.code==='DATA EXFILTRATED'));
assert.equal(JSON.stringify(run),snapshot,'Reporting must not change simulation history');

// Execute the actual renderer against a node already marked as compromised.
const html=fs.readFileSync(path.join(root,'wire.html'),'utf8');
const renderer=html.slice(html.indexOf('function renderEvent('),html.indexOf('function renderControl('));
const classes=new Set(['hit']);
const nodeState={textContent:'DATA EXFILTRATED'};
const node={el:{hidden:false,title:'',classList:{contains:name=>classes.has(name),add:name=>classes.add(name)},
  querySelector:()=>nodeState}};
const display=vm.createContext({currentNodes:new Map([['unrelated',node]]),currentWires:new Map(),
  RunDiscovery,formatEstimate:seconds=>`${seconds}s`});
vm.runInContext(renderer,display);
display.renderEvent(failure,failure.timeSec,false);
assert.equal(nodeState.textContent,'DATA EXFILTRATED','A failed alternative cannot erase completed impact');
classes.clear();nodeState.textContent='';
display.renderEvent(failure,failure.timeSec,false);
assert.equal(nodeState.textContent,'PROBED · NO ACCESS','An unreached target retains its failed probe status');
console.log('PASS activity outcomes: all exports pinned, unknown volume displayed honestly, unspecified egress distinct, no future impact leaks, compromised status preserved');
