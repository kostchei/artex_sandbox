// Historical diagnostic for the timed runner retained for archived Wire manifests.
// Reproducible model sensitivity/invariant sweep; these are simulated counts, not efficacy estimates.
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const e=require('../js/wire-engine.js');
let revision='unknown', workingTree='unknown';
try {
  revision=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
  workingTree=execFileSync('git',['status','--porcelain','--untracked-files=no'],{encoding:'utf8'}).trim()?'dirty':'clean';
} catch (_) { /* A source archive need not contain Git metadata. */ }
const modes=['baseline','patch','canaries','soc','soc-canary','combined'];
const counts=Object.fromEntries(['lockbit','artex'].map(a=>[a,Object.fromEntries(modes.map(m=>[m,{reads:0,incomplete:0}]))]));
const sensitivity={responseLatency:{},responseScope:{},signalPlacement:{}};
let runs=0;
for(const preset of ['mixed','demo','logs'])for(let seed=1;seed<=200;seed++){
  const estate=e.generateEstate({preset,seed,seedExercise:true});
  const original=JSON.stringify(estate);
  for(const actor of ['lockbit','artex'])for(const mode of modes){
    const manifest={revision,workingTree,preset,seed,attacker:actor,mode,
      generation:{seedExercise:true},simulationOptions:{},estate};
    try {
    const r=e.simulateLegacyWireRun(estate,mode,actor);runs++;
    const bucket=counts[actor][mode];bucket.reads+=Number(r.summary.dataReached);bucket.incomplete+=Number(r.summary.truncated);
    assert.equal(r.summary.explorationLimit,1000);
    assert(r.summary.evaluatedTransitions<=1000);
    assert.equal(r.summary.dataReached,r.events.some(x=>x.outcome==='succeeded'&&x.isProtectedRead));
    if(mode==='canaries'||mode==='baseline'||mode==='patch')assert(!r.controls.some(c=>c.control==='enforced'));
    const reached=new Map();
    for(const event of r.events){
      assert(Number.isFinite(event.timeSec)&&event.timeSec>=0);
      assert(event.startSec<=event.timeSec);
      if(event.sourceId&&event.outcome==='succeeded'){
        assert(reached.has(event.sourceId),`source not reached: ${preset}/${seed}/${actor}/${mode}`);
        assert(reached.get(event.sourceId)<=event.startSec);
      }
      if(event.outcome==='succeeded'){
        if(!reached.has(event.targetId))reached.set(event.targetId,event.timeSec);
        assert(!r.controls.some(c=>c.control==='enforced'&&c.scope===event.scope&&c.timeSec<=event.timeSec));
      }
    }
    for(const c of r.controls.filter(c=>c.source==='canary'))assert(estate.defensePosture.decoys.some(d=>d.assetId===c.targetId)&&estate.assets.some(a=>a.isDecoy&&a.id===c.targetId));
    assert.equal(JSON.stringify(estate),original);
    } catch(error) {
      console.error('Failing simulation manifest:',JSON.stringify(manifest));
      throw error;
    }
  }
}
for(const delay of [0,60,300]) sensitivity.responseLatency[delay]=0;
for(const scope of ['matched','unrelated']) sensitivity.responseScope[scope]=0;
for(const placement of ['all','none']) sensitivity.signalPlacement[placement]=0;
for(let seed=1;seed<=25;seed++){
  const estate=e.generateEstate({preset:'demo',seed,seedExercise:true});
  for(const delay of [0,60,300]) sensitivity.responseLatency[delay]+=Number(e.simulateLegacyWireRun(estate,'soc','artex',{responseDelay:delay}).summary.dataReached);
  sensitivity.responseScope.matched+=Number(e.simulateLegacyWireRun(estate,'soc','artex',{responseDelay:0}).summary.dataReached);
  sensitivity.responseScope.unrelated+=Number(e.simulateLegacyWireRun(estate,'soc','artex',{responseDelay:0,responseScope:'unrelated'}).summary.dataReached);
  const noSignals=structuredClone(estate);noSignals.defensePosture.telemetryLayers=[];
  const allSignals=structuredClone(estate);allSignals.defensePosture.telemetryLayers=[0,1,2,3];
  sensitivity.signalPlacement.all+=Number(e.simulateLegacyWireRun(allSignals,'soc','artex',{responseDelay:60}).summary.dataReached);
  sensitivity.signalPlacement.none+=Number(e.simulateLegacyWireRun(noSignals,'soc','artex',{responseDelay:60}).summary.dataReached);
}
console.log(JSON.stringify({revision,workingTree,presets:['mixed','demo','logs'],seeds:[1,200],attackers:['lockbit','artex'],modes,generation:{seedExercise:true},simulationOptions:{},timing:'archived timed defaults',exploration:'engine default: 1000 evaluated transitions',runs,counts,sensitivity:{pairedPreset:'demo',pairedSeeds:[1,25],attacker:'artex',metric:'protected-read runs',...sensitivity},invariants:'PASS: causal prerequisites, enforcement, budgets, deployed decoys, unchanged estate'},null,2));
