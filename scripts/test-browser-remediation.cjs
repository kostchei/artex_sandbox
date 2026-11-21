// Set PLAYWRIGHT_CORE_PATH and optionally EDGE_PATH when Playwright is installed outside this repo.
const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
async function main(){
  const server=http.createServer((req,res)=>{
    const requested=decodeURIComponent(req.url.split('?')[0]);
    const file=path.join(root,requested==='/'?'index.html':requested);
    if(!file.startsWith(root+path.sep)){res.writeHead(403);res.end();return;}
    fs.readFile(file,(err,data)=>{res.statusCode=err?404:200;res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':file.endsWith('.html')?'text/html':'application/octet-stream');res.end(err?'missing':data);});
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
    const page=await browser.newPage({viewport:{width:1440,height:900}});
    const errors=[];page.on('pageerror',err=>errors.push(err.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.waitForURL('**/wire.html');await page.waitForSelector('.node');
    assert.equal(await page.locator('.mode-btn').count(),4);
    assert.equal(await page.locator('[data-mode="canaries"], [data-mode="soc-canary"], select#map-profile').count(),0);
    assert.equal(await page.locator('select#pre2023-pattern').inputValue(),'rotation');
    if(process.env.REMEDIATION_SCREENSHOT){
      await page.evaluate(()=>{estate=generateEstate({preset:'demo',seed:777,seedExercise:true});referenceCase=null;playRun();finishRun();});
      await page.waitForTimeout(250); // Allow the 200 ms state-color transition to settle for visual assertions.
      const cues=await page.evaluate(()=>[...document.querySelectorAll('.node.hit')].map(n=>({color:getComputedStyle(n.querySelector('.node-icon')).backgroundColor,labelTop:n.querySelector('.node-label').getBoundingClientRect().top,haloBottom:n.querySelector('.node-halo').getBoundingClientRect().bottom})));
      assert(cues.length>0);
      for(const cue of cues){assert.equal(cue.color,'rgb(216, 91, 123)');assert(cue.labelTop>=cue.haloBottom,'Attack halo must not cover its label');}
      await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT.replace('.png','-baseline.png')});
    }
    for(const viewport of [{width:1440,height:900},{width:1280,height:720},{width:390,height:844}]){
      await page.setViewportSize(viewport);
      for(const seed of [1,42,99]){
        await page.evaluate(seed=>{estate=generateEstate({seed,seedExercise:true});referenceCase=null;pre2023Group='lockbit';playRun();finishRun();},seed);
        const collisions=await page.evaluate(()=>{
          const boxes=[...document.querySelectorAll('.node-label')].map(n=>({id:n.parentElement.id,r:n.getBoundingClientRect()}));
          return boxes.flatMap((a,i)=>boxes.slice(i+1).filter(b=>a.r.left<b.r.right&&a.r.right>b.r.left&&a.r.top<b.r.bottom&&a.r.bottom>b.r.top).map(b=>[a.id,b.id]));
        });
        assert.deepEqual(collisions,[],`labels overlap: ${viewport.width}, seed ${seed}`);
        const before=await page.evaluate(()=>JSON.stringify(estate));
        for(const attacker of ['pre2023','artex']){
          await page.click(`[data-attacker="${attacker}"]`);
          assert.equal(await page.locator(`[data-attacker="${attacker}"]`).getAttribute('aria-pressed'),'true');
          assert.equal(await page.locator('.attacker-marker').count(),attacker==='artex'?3:1);
          for(const mode of ['baseline','patch','soc','combined']){
            await page.click(`[data-mode="${mode}"]`);
            if(mode==='combined') {
              const deployed=await page.evaluate(()=>estate.defensePosture.decoys.length);
              assert(deployed>0,'Generated estate must deploy a canary');
              assert.equal(await page.locator('.node.decoy:not([hidden]) .canary-marker').count(),0,'Unprobed internal decoys must not be disclosed at the start');
            }
            await page.click('#map-results-btn');
            const snapshot=await page.evaluate(()=>({run:JSON.stringify(run),style:runHud.className,expected:run.result.style,text:runHud.textContent,label:run.result.label}));
            assert.equal(snapshot.style,snapshot.expected);assert(snapshot.text.includes(snapshot.label));
            const overlaps=await page.evaluate(()=>{
              const boxes=[...document.querySelectorAll('.node-label, .node-kev')].filter(n=>getComputedStyle(n).display!=='none').map(n=>({id:n.parentElement.id,r:n.getBoundingClientRect()}));
              return boxes.flatMap((a,i)=>boxes.slice(i+1).filter(b=>a.id!==b.id&&a.r.left<b.r.right&&a.r.right>b.r.left&&a.r.top<b.r.bottom&&a.r.bottom>b.r.top).map(b=>[a.id,b.id]));
            });
            assert.deepEqual(overlaps,[],`active callout collision: ${viewport.width}/${seed}/${attacker}/${mode}`);
            await page.click('#map-replay-btn');await page.click('#map-results-btn');
            assert.equal(await page.evaluate(()=>JSON.stringify(run)),snapshot.run);
            assert.equal(await page.evaluate(()=>JSON.stringify(estate)),before);
          }
        }
        await page.locator('.node').first().focus();
        assert((await page.locator('#asset-details').textContent()).length>20);
        await page.click('#search-toggle');
        const label=await page.locator('.node-label').first().textContent();
        await page.fill('#asset-search',label);
        assert(await page.locator('.node.search-match').count()>0);
        assert.equal(await page.evaluate(()=>JSON.stringify(estate)),before);
        await page.fill('#asset-search','definitely-not-an-enterprise-asset');
        assert.equal(await page.locator('.node.search-match').count(),0);
        await page.press('#asset-search','Escape');
        assert.equal(await page.locator('#search-toggle').getAttribute('aria-expanded'),'false');
        await page.evaluate(()=>window.scrollTo(0,0));
        if(viewport.width===1440 && seed===1 && process.env.REMEDIATION_SCREENSHOT) await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT.replace('.png','-desktop.png')});
        console.log(`PASS browser ${viewport.width}x${viewport.height}, seed ${seed}: layout, 8 combinations, replay, details`);
      }
    }
    for (const gang of ['lockbit','conti','blackcat','hive','revil']) {
      const spawned = await page.evaluate(gang=>{
        estate=generateEstate({seed:3,seedExercise:true});
        const before=JSON.stringify(estate);
        pre2023Group=gang;attackerChoice='pre2023';defense='baseline';referenceCase=null;
        playRun();finishRun();
        return {gang:run.attackerProfile.gangId,unchanged:JSON.stringify(estate)===before,
          desktopVisible:!!document.getElementById('node-windows-desktop')&&!document.getElementById('node-windows-desktop').hidden,
          workstation:estate.assets.some(a=>a.id==='windows-desktop'),
          techniques:run.events.filter(e=>e.outcome==='succeeded').map(e=>e.technique)};
      },gang);
      assert.equal(spawned.gang,gang);assert(spawned.unchanged);assert(spawned.workstation);
      assert(spawned.desktopVisible,'The workforce email surface is visible to both profiles even when they choose different methods');
      if(['conti','revil','hive'].includes(gang))assert(spawned.techniques.includes('T1566.001'));
    }
    console.log('PASS browser: five spawned gangs use mapped policy on the same workforce estate');
    const fleetImpact=await page.evaluate(()=>{
      estate=generateEstate({seed:12,seedExercise:true});pre2023Group='lockbit';attackerChoice='pre2023';defense='baseline';
      playRun();finishRun();
      return {encrypted:run.summary.encryptedEndpointIds.length,persistent:run.summary.persistentEndpointIds.length,
        text:runHud.textContent,states:[...document.querySelectorAll('.node-state')].map(n=>n.textContent),
        fleets:estate.assets.filter(a=>a.endpointIds).length};
    });
    assert(fleetImpact.fleets>=2);assert(fleetImpact.encrypted>0);
    assert(fleetImpact.text.includes(`${fleetImpact.encrypted} endpoints encrypted`));
    assert(fleetImpact.states.some(text=>text.includes('ENCRYPTED')));
    console.log('PASS browser: fleet membership and scoped encryption appear in node states and final result');
    const initialView=await page.evaluate(()=>{
      estate=generateEstate({seed:3,seedExercise:true});pre2023Group='lockbit';attackerChoice='pre2023';defense='baseline';
      playRun();cancelAnimationFrame(frame);
      const future=discoveryPlan.assetIds.find(id=>!discoveryPlan.initialAssetIds.includes(id)&&discoveryPlan.assetTimes[id]>0);
      return {estate:JSON.stringify(estate),run:JSON.stringify(run),total:estate.assets.length,
        planned:discoveryPlan.assetIds.length,initial:discoveryPlan.initialAssetIds,
        visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),
        edges:[...currentWires.values()].filter(w=>w.path.style.display!=='none').length,
        future,label:currentNodes.get(future).label,time:discoveryPlan.assetTimes[future],
        positions:Object.fromEntries([...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>[n.id,[n.x,n.y]]))};
    });
    assert(initialView.planned<initialView.total,'Untouched infrastructure is excluded from the DOM plan');
    assert.deepEqual(initialView.visible,initialView.initial);assert.equal(initialView.edges,0);
    await page.click('#search-toggle');await page.fill('#asset-search',initialView.label);
    assert.equal(await page.locator('.node.search-match').count(),0,'Search cannot reveal a future asset');
    await page.press('#asset-search','Escape');
    const growing=await page.evaluate(({time,future})=>{
      while(phaseIndex<phases.length&&phases[phaseIndex].time<=time){renderPhase(phases[phaseIndex]);phaseIndex++;}
      showTime(time);
      return {visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),
        futureVisible:!currentNodes.get(future).el.hidden,
        positions:Object.fromEntries([...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>[n.id,[n.x,n.y]]))};
    },initialView);
    assert(growing.futureVisible);assert(growing.visible.length>initialView.visible.length);
    for(const id of initialView.visible)assert.deepEqual(growing.positions[id],initialView.positions[id],'Existing nodes stay anchored');
    await page.evaluate(()=>window.dispatchEvent(new Event('resize')));
    assert.deepEqual(await page.evaluate(()=>[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id)),growing.visible,'Resize preserves mid-probe discovery');
    await page.click('#map-results-btn');
    const completedView=await page.evaluate(()=>({estate:JSON.stringify(estate),run:JSON.stringify(run),
      visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),
      expected:discoveryPlan.assetIds,edges:[...currentWires].filter(([,w])=>w.path.style.display!=='none').map(([id])=>id),
      expectedEdges:discoveryPlan.relationshipIds}));
    assert.deepEqual(completedView.visible,completedView.expected);assert.deepEqual(completedView.edges,completedView.expectedEdges);
    assert.equal(completedView.estate,initialView.estate);assert.equal(completedView.run,initialView.run);
    await page.click('#map-replay-btn');await page.evaluate(()=>cancelAnimationFrame(frame));
    assert.deepEqual(await page.evaluate(()=>[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id)),initialView.initial);
    console.log('PASS browser: external-only start, no future search leaks, expanding anchored map, resize, results filtering, immutable model and replay reset');
    await page.evaluate(()=>{
      estate=generateEstate({preset:'demo',seed:404,seedExercise:false});
      estate.findings=[];estate.credentials=[];referenceCase=null;playRun();finishRun();
    });
    const neutral=await page.evaluate(()=>({label:run.result.label,style:runHud.className,text:runHud.textContent}));
    assert.equal(neutral.label,'No protected read established');
    assert.equal(neutral.style,'');
    assert(neutral.text.includes(neutral.label),'Neutral result must be rendered from classifyRun');
    const previous=await page.evaluate(()=>JSON.stringify(estate));
    await page.click('#new-run-btn');
    assert.notEqual(await page.evaluate(()=>JSON.stringify(estate)),previous);
    await page.click('#map-results-btn');
    await page.locator('[data-attacker="artex"]').focus();await page.keyboard.press('Enter');
    assert.equal(await page.locator('[data-attacker="artex"]').getAttribute('aria-pressed'),'true');
    await page.click('#map-replay-btn');
    await page.waitForTimeout(1600);
    assert(await page.evaluate(()=>phaseIndex>0),'Animation must advance its event history');
    await page.click('#map-results-btn');
    await page.click('#advanced-controls-toggle');
    await page.locator('#ctrl-virtual-patching').setChecked(true);
    await page.locator('#ctrl-canaries').setChecked(false);
    await page.locator('#ctrl-response-policy').selectOption('agentic');
    const downloadStarted = page.waitForEvent('download');
    await page.click('#export-manifest-btn');
    const download = await downloadStarted;
    const exported = fs.readFileSync(await download.path());
    const snapshot = JSON.parse(exported.toString());
    assert.equal(snapshot.defenseConfig.virtualPatching, true);
    assert.equal(snapshot.defenseConfig.canaries, false);
    assert.equal(snapshot.defenseConfig.responsePolicy, 'agentic');
    assert.deepEqual(snapshot.events, await page.evaluate(() => JSON.parse(JSON.stringify(run.events))));
    await page.click('[data-mode="baseline"]');
    await page.locator('#import-manifest-input').setInputFiles({
      name: 'replay.json', mimeType: 'application/json', buffer: exported
    });
    await page.waitForFunction(() => run.defenseConfig.virtualPatching && run.defenseConfig.responsePolicy === 'agentic');
    assert.deepEqual(snapshot.events, await page.evaluate(() => JSON.parse(JSON.stringify(run.events))));
    await page.click('#map-replay-btn');
    assert.deepEqual(snapshot.controls, await page.evaluate(() => JSON.parse(JSON.stringify(run.controls))));
    const evidence = await page.evaluate(() => {
      syncSwitches(normalizeDefenseConfig('baseline'));
      estate = generateEstate({ preset: 'demo', seed: 1 });
      for (const asset of estate.assets) asset.egress = { responseExportAllowed: true, cloudUploadAllowed: true };
      playRun();
      const milestoneText = () => document.getElementById('run-milestones').textContent;
      const before = milestoneText();
      const read = run.events.find(event => event.isProtectedRead && event.outcome === 'succeeded');
      const exported = run.events.find(event => event.targetId === read.targetId &&
        event.actionKind === 'data_exfiltration' && event.outcome === 'succeeded');
      const asset = estate.assets.find(asset => asset.id === read.targetId);
      const readOnly = describeDatasetVolume(asset, [read]);
      const interrupted = describeDatasetVolume(asset, [read, { ...exported, outcome: 'suppressed' }]);
      finishRun();
      return {
        before, after: milestoneText(), readOnly, interrupted,
        volumes: document.getElementById('run-data-volumes').textContent,
        references: document.getElementById('historical-timing').textContent
      };
    });
    assert(!evidence.before.includes('First sensitive read'));
    assert(evidence.after.includes('First sensitive read'));
    assert(evidence.after.includes('First export completed'));
    assert.match(evidence.readOnly, /Available .* Read .* no completion recorded/);
    assert.match(evidence.interrupted, /transferred volume unknown/);
    assert.match(evidence.volumes, /Exported .* records/);
    assert(evidence.references.includes('00:02:07'));
    assert(evidence.references.includes('04:00:00'));
    await page.emulateMedia({reducedMotion:'reduce'});
    assert.equal(await page.locator('.node-halo').first().evaluate(n=>getComputedStyle(n).animationName),'none');
    await page.locator('#archetype-selector').selectOption('full-enterprise');
    const overview = await page.evaluate(() => {
      cancelAnimationFrame(frame);
      const shown = [...currentNodes.values()].filter(node => !node.el.hidden);
      return {
        id: estate.id,
        shown: shown.map(node => node.groupId),
        runnerHelp: shown.find(node => node.groupId === 'cicd-runner')?.el.title,
        routes: document.querySelectorAll('.wire.estate-route').length
      };
    });
    for (const group of ['ad-identity', 'app-engine', 'lake-ops', 'cicd-runner']) {
      assert(overview.shown.includes(group), `Missing overview asset ${group}`);
    }
    assert(overview.routes > 0);
    assert.match(overview.runnerHelp, /Findings and stored credentials have not been observed/);
    await page.click('[data-mode="combined"]');
    assert.equal(await page.evaluate(() => estate.id), overview.id);
    const combined = await page.evaluate(() => JSON.stringify(run.events));
    await page.click('#map-replay-btn');
    assert.equal(await page.evaluate(() => estate.id), overview.id);
    assert.equal(await page.evaluate(() => JSON.stringify(run.events)), combined);
    assert.deepEqual(errors,[]);
    if(process.env.REMEDIATION_SCREENSHOT) await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT});
    console.log('PASS browser: New Infra, redirect, console; no label collisions or replay drift');
  }finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
}
main().catch(err=>{console.error(err);process.exitCode=1;});
