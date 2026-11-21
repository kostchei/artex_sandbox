// A trace-derived display plan. Never removes assets or actions from the simulation.
(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.RunDiscovery=factory();})(typeof self!=='undefined'?self:this,function(){
  function observed(event) {
    if(event.policySkipped || ['revisit','truncated'].includes(event.outcome))return false;
    if(event.outcome==='suppressed' && event.suppressionPhase==='queued')return false;
    if(event.outcome==='ineligible' || event.outcome==='suppressed') {
      if(!Number.isFinite(event.startSec) || !Number.isFinite(event.timeSec) || event.timeSec<=event.startSec)return false;
      // Missing source access or an invalid route is not a probe of the target.
      if(/source capability|No directed relationship|Protocol mismatch|Relationship direction|endpoints do not match/i.test(event.reason||''))return false;
    }
    return ['succeeded','blocked','alert_only','ineligible','suppressed'].includes(event.outcome);
  }
  function create(estate,run) {
    const assets=new Map(estate.assets.map(a=>[a.id,a]));
    const relationships=new Map(estate.relationships.map(r=>[r.id,r]));
    const assetTimes={},relationshipTimes={};
    const remember=(times,id,time)=>{if(id)times[id]=Math.min(times[id]??Infinity,time);};
    for(const event of run.events.filter(observed)) {
      const time=Number.isFinite(event.startSec)?event.startSec:Number.isFinite(event.timeSec)?event.timeSec:0;
      if(assets.has(event.targetId))remember(assetTimes,event.targetId,time);
      if(assets.has(event.sourceId))remember(assetTimes,event.sourceId,time);
      const rel=relationships.get(event.relationshipId);
      if(rel && rel.sourceId===event.sourceId && rel.targetId===event.targetId)remember(relationshipTimes,rel.id,time);
    }
    // Starting knowledge belongs to the estate, not to an attacker's future trace.
    const initialAssetIds=estate.assets.filter(a=>a.isExternalEntry).map(a=>a.id);
    for(const id of initialAssetIds)assetTimes[id]=0;
    return {assetIds:estate.assets.filter(a=>Object.hasOwn(assetTimes,a.id)).map(a=>a.id),
      relationshipIds:estate.relationships.filter(r=>Object.hasOwn(relationshipTimes,r.id)).map(r=>r.id),
      initialAssetIds,assetTimes,relationshipTimes};
  }
  function at(plan,time,started=true) {
    const assetIds=started?plan.assetIds.filter(id=>plan.assetTimes[id]<=time):plan.initialAssetIds;
    const known=new Set(assetIds);
    return {assetIds,relationshipIds:started?plan.relationshipIds.filter(id=>plan.relationshipTimes[id]<=time):[],known};
  }
  // Explain continuation failures without treating a route review as a target probe.
  function lateralStatus(estate,run) {
    const assets=new Map(estate.assets.map(a=>[a.id,a]));
    const execution=run.events.filter(e=>e.outcome==='succeeded' && e.grantedCapability==='app_exec');
    if(!execution.length)return null;
    const controlled=new Set(execution.map(e=>e.targetId));
    const remote=run.events.filter(e=>controlled.has(e.sourceId) && e.sourceId!==e.targetId &&
      !assets.get(e.targetId)?.isDecoy && (e.relationshipId || !e.actionKind));
    const reached=new Set(remote.filter(e=>e.outcome==='succeeded').map(e=>e.targetId));
    const failures=remote.filter(e=>['ineligible','blocked','suppressed'].includes(e.outcome) && !reached.has(e.targetId));
    if(reached.size && !failures.length)return null;
    const reasons=[...new Set(failures.map(e=>e.policySkipped
      ? 'No supported lateral method in the attacker profile.' : e.reason).filter(Boolean))];
    if(!reasons.length)reasons.push(run.summary?.truncated
      ? 'Exploration ended before further movement could be established.'
      : run.summary?.containedSessions ? 'The established session was contained before further movement.'
      : 'No usable outgoing route was available from the established foothold.');
    const summary=reached.size ? 'Further lateral movement failed on remaining routes'
      : run.summary?.truncated ? 'No lateral movement established; exploration incomplete'
      : failures.some(e=>observed(e)) ? 'Lateral movement failed; no host reached laterally'
      : 'No lateral movement established';
    return {summary,detail:reasons.join(' '),reachedTargets:[...reached]};
  }
  return {observed,create,at,lateralStatus};
});
