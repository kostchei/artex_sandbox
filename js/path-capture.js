// Opt-in focused replay of full-estate simulation events, including failed jobs.
if (new URLSearchParams(location.search).get('capture') === 'path') {
  document.documentElement.classList.add('path-capture');
  const style=document.createElement('style');
  style.textContent=`
    .path-capture body{min-width:0!important;overflow:hidden}
    .path-capture .brand-row,.path-capture .mode-strip,.path-capture .run-row,
    .path-capture .canvas-tools,
    .path-capture .soc-ticker,.path-capture #asset-details{display:none!important}
    .path-capture #run-hud{margin:0 6px;padding:5px 10px;font-size:12px;min-height:30px;line-height:1.4}
    .path-capture #viewport{margin:0 6px 6px;min-width:0;min-height:0!important}
    .path-capture .node{width:192px}
    .path-capture .node-label{width:188px;font-size:13px;line-height:16px}
    .path-capture .node-kev{max-width:190px;font-size:11px;line-height:13px;margin-top:4px;padding:4px 6px}
    .path-capture .node.hit .node-label{margin-top:14px}
    .path-capture .node-state{font-size:10px}
    .branch-kind{position:absolute;top:-30px;font-size:9px;letter-spacing:.5px;color:#7ed5e4;background:#0e1820;padding:1px 4px}
    .branch-kind.exploration{color:#d9bd8c}
    .origin-wire{fill:none;stroke:#7396a6;stroke-width:1.2;stroke-dasharray:3 6;opacity:.6;marker-end:url(#wire-arrow-strong)}
    .origin-label{fill:#aabccc;font:11px Arial,sans-serif}
    .path-capture .attacker-marker{width:38px;height:38px;z-index:30;opacity:.7}
    .path-capture .attacker-marker.working{opacity:1;box-shadow:0 0 13px currentColor}
    .path-capture .attacker-marker b{position:absolute;right:-8px;top:-9px;background:#14222d;border:1px solid currentColor;border-radius:4px;padding:1px 3px;font:700 11px Arial}
    .path-capture .wire{opacity:0}
    .path-capture .wire.hit-wire{opacity:1;stroke-width:2}
    .path-capture .wire.failed-wire{opacity:.85;stroke:#d4b16d;stroke-width:1.5;stroke-dasharray:5 7}
    .path-capture .wire.active-wire{opacity:.9;stroke:#83ecfa;stroke-width:2;stroke-dasharray:3 6}
    .path-capture .node.attempt-failed:not(.hit) .node-halo{background:#51442b;border:1px dashed #d4b16d}
    .path-capture .node.being-probed .node-halo{outline:2px solid #83ecfa;outline-offset:4px}
    .attempt-note{font-size:10px;line-height:13px;color:#e3c78f;text-align:center;max-width:190px;margin-top:4px}
    .path-capture *{transition:none!important}
    #capture-heading{display:flex;align-items:center;justify-content:space-between;margin:6px;padding:7px 12px;border:1px solid #304651;border-radius:5px;color:#83ecfa;background:#101d28;font-size:17px}
    #capture-heading .time{text-align:right;display:flex;align-items:center;gap:14px}
    #capture-heading small{color:#aabccc;font-size:11px;font-weight:400}
    #capture-heading .capture-clock{font-size:34px;line-height:38px;font-weight:800;font-variant-numeric:tabular-nums;color:#f0f6ff}
  `;
  document.head.append(style);
  const heading=document.createElement('div');heading.id='capture-heading';document.body.prepend(heading);
  const title=document.createElement('strong');
  const meta=document.createElement('div');meta.className='time';
  const caption=document.createElement('small');caption.textContent='Elapsed since starting access';
  const timeLabel=document.createElement('strong');timeLabel.className='capture-clock';
  meta.append(caption,timeLabel);heading.append(title,meta);
  let plan,sharedPlan;
  const originalLayout=layoutGraph, originalRender=renderEvent, originalControl=renderControl, originalAttackers=renderAttackers;
  renderControl=function(event){if(!plan||plan.ids.has(event.targetId)&&plan.ids.has(event.scope))return originalControl(event);};
  layoutGraph=function(example){
    if(!run)return originalLayout(example);
    const selection=sharedPlan||CapturePlan.create(example,[run]);
    plan={ids:new Set(selection.assetIds),relationships:new Set(selection.relationshipIds)};
    originalLayout({...example,assets:example.assets.filter(a=>plan.ids.has(a.id)),relationships:example.relationships.filter(r=>plan.relationships.has(r.id))});
    const width=document.documentElement.clientWidth-14;
    const columns=[...new Set([...currentNodes.values()].map(n=>n.layerIdx))].sort();
    const groups=columns.map(layer=>[...currentNodes.values()].filter(n=>n.layerIdx===layer).sort((a,b)=>a.id.localeCompare(b.id)));
    const capacity=Math.max(columns.length,Math.floor(width/210));
    let rows=1;
    while(groups.reduce((sum,nodes)=>sum+Math.ceil(nodes.length/rows),0)>capacity)rows++;
    const lanes=groups.map(nodes=>Math.ceil(nodes.length/rows));
    const total=lanes.reduce((a,b)=>a+b,0);
    let offset=0;
    groups.forEach((nodes,column)=>{
      nodes.forEach((node,index)=>{
        node.x=(offset+index%lanes[column]+.5)*width/total;
        node.y=78+Math.floor(index/lanes[column])*168;
        node.el.style.left=`${node.x}px`;node.el.style.top=`${node.y}px`;
      });
      offset+=lanes[column];
    });
    document.getElementById('viewport').style.height=`${rows*168+60}px`;
    for(const wire of currentWires.values())wire.path.setAttribute('d',typeof wirePath==='function'?wirePath(wire.source,wire.target):`M ${wire.source.x} ${wire.source.y} L ${wire.target.x} ${wire.target.y}`);
    const chainIds=new Set(selection.chainIds||[]);
    for(const node of currentNodes.values()){
      const tag=document.createElement('span');tag.className='branch-kind'+(chainIds.has(node.id)?'':' exploration');tag.textContent=chainIds.has(node.id)?'BREACH CHAIN':'EXPLORATION';node.el.append(tag);
    }
    const ns='http://www.w3.org/2000/svg';
    const origin=document.createElementNS(ns,'text');origin.setAttribute('class','origin-label');origin.setAttribute('x','18');origin.setAttribute('y','17');origin.textContent='External origin / starting access';svg.append(origin);
    for(const id of selection.entryIds||[]){
      const node=currentNodes.get(id);if(!node)continue;
      const path=document.createElementNS(ns,'path');path.setAttribute('class','origin-wire');path.setAttribute('d',`M 18 26 C ${node.x-85} 26 ${node.x-85} ${node.y} ${node.x-25} ${node.y}`);svg.prepend(path);
    }
    renderAttackers(0);
  };
  renderEvent=function(event,time,animate){
    if(plan&&!plan.ids.has(event.targetId))return;
    originalRender(event,time,animate);
    if(!CapturePlan.attempted(event))return;
    const node=currentNodes.get(event.targetId),wire=currentWires.get(event.relationshipId);
    if(!node||node.el.hidden)return;
    if(event.outcome==='ineligible'){
      node.el.classList.add('attempt-failed');
      let note=node.el.querySelector('.attempt-note');
      if(!note){note=document.createElement('div');note.className='attempt-note';node.el.append(note);}
      note.textContent=event.reason.includes('source capability')?'Prerequisite missing / no access':'Attempt unsuccessful / no access';
      note.title=event.reason;
      if(wire&&!wire.path.classList.contains('hit-wire'))wire.path.classList.add('failed-wire');
    }
    if(event.outcome==='succeeded')node.el.querySelector('.attempt-note')?.remove();
  };
  renderAttackers=function(time){
    if(!plan)return originalAttackers(time);
    const fullTracks=attackerTracks;
    attackerTracks=fullTracks.map(track=>track.filter(e=>plan.ids.has(e.targetId)&&CapturePlan.attempted(e)));
    try{originalAttackers(time);}finally{attackerTracks=fullTracks;}
    document.querySelectorAll('.being-probed').forEach(n=>n.classList.remove('being-probed'));
    document.querySelectorAll('.active-wire').forEach(n=>n.classList.remove('active-wire'));
    document.querySelectorAll('.attacker-marker').forEach((marker,index)=>{
      let badge=marker.querySelector('b');if(!badge){badge=document.createElement('b');marker.append(badge);}badge.textContent=run.lanes===3?`A${index+1}`:'H1';
      if(marker.hidden){marker.hidden=false;marker.style.left=`${document.documentElement.clientWidth-150+index*48}px`;marker.style.top='25px';marker.classList.remove('working');}
      for(const job of fullTracks[index]||[]){
        if(job.startSec<=time&&job.timeSec>time&&CapturePlan.attempted(job)){
          currentNodes.get(job.targetId)?.el.classList.add('being-probed');
          currentWires.get(job.relationshipId)?.path.classList.add('active-wire');
        }
      }
    });
  };
  function updateHeading(){
    title.textContent=`${attackerChoice==='artex'?'ARTEX / 3 agents':'Pre-2023 crime gang / 1 attacker'} / ${pathCapture.label} / ${defenseLabels[defense]}`;
    timeLabel.textContent=CapturePlan.clock(modeledTime);
  }
  window.pathCapture={
    prepare(example,actor='artex',mode='baseline',label='Infrastructure',displayPlan=null){
      cancelAnimationFrame(frame);sharedPlan=displayPlan;estate=structuredClone(example);referenceCase=null;pre2023Group='lockbit';attackerChoice=actor;defense=mode;
      playRun();cancelAnimationFrame(frame);this.done=false;this.label=label;updateHeading();
      return {end:phases.at(-1)?.time||0,height:Math.ceil(document.getElementById('viewport').getBoundingClientRect().bottom+6)};
    },
    advance(time){
      if(this.done)return;
      if(time<=0&&phaseIndex===0){showTime(0);updateHeading();return;}
      while(phaseIndex<phases.length&&phases[phaseIndex].time<=time){renderPhase(phases[phaseIndex]);phaseIndex++;}
      showTime(Math.min(time,phases.at(-1)?.time||0));
      if(phaseIndex===phases.length){finishRun();this.done=true;}
      updateHeading();
    },
    state(){return {ids:[...plan.ids],edges:[...plan.relationships],estate,events:run.events,controls:run.controls,tracks:attackerTracks,lanes:run.lanes,time:modeledTime,done:this.done};}
  };
  const params=new URLSearchParams(location.search);
  if(!params.has('manual')){
    const info=pathCapture.prepare(WireEngine.generateEstate({preset:'mixed',seed:Number(params.get('seed'))||1853,seedExercise:true}),params.get('actor')==='pre2023'?'pre2023':'artex',params.get('mode')||'baseline');
    const start=performance.now();
    function tick(now){pathCapture.advance((now-start)/30000*info.end);if(!pathCapture.done)frame=requestAnimationFrame(tick);}
    frame=requestAnimationFrame(tick);
  }
}
