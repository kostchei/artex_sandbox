const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
async function main(){
  const server=http.createServer((req,res)=>{
    const file=path.join(root,decodeURIComponent(req.url.split('?')[0]));
    if(!file.startsWith(root+path.sep)){res.writeHead(403);res.end();return;}
    fs.readFile(file,(err,data)=>{res.statusCode=err?404:200;res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':'text/html');res.end(err?'missing':data);});
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
    const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    const base=`http://127.0.0.1:${server.address().port}`;
    await page.goto(`${base}/dual.html`);
    await page.waitForFunction(()=>!document.getElementById('run').disabled);
    const panels=page.frames().filter(frame=>frame.url().includes('wire.html'));
    assert.equal(panels.length,2);
    assert.equal(await page.locator('.attack-feed li').count(),0,'No future techniques in ready view');
    const before=[];
    for(const panel of panels){
      const initial=await panel.evaluate(()=>({estate:JSON.stringify(estate),run:JSON.stringify(run),
        visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),initial:discoveryPlan.initialAssetIds,
        positions:Object.fromEntries([...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>[n.id,[n.x,n.y]]))}));
      assert.deepEqual(initial.visible,initial.initial);before.push(initial);
    }
    assert.deepEqual(before[0].visible,before[1].visible,'Both attackers have identical starting infrastructure');
    assert.deepEqual(before[0].positions,before[1].positions,'Shared starting infrastructure has identical positions');
    await page.click('#run');await page.waitForTimeout(1200);
    assert(await page.locator('.attack-feed li').count()>0,'Used techniques appear during playback');
    assert(await page.evaluate(()=>frames.every(f=>f.contentWindow.comparison.activity().every(item=>item.time<=f.contentWindow.comparison.state().time))));
    assert(await page.evaluate(()=>fittedHeights===frames.map(f=>f.contentWindow.comparison.height()).join(',')),'Embedded frames fit the growing views');
    await page.evaluate(()=>{cancelAnimationFrame(animation);frames.forEach(f=>f.contentWindow.comparison.advance(Infinity));updateFeeds();fit();});
    for(const [i,panel] of panels.entries()){
      const expected=await panel.evaluate(()=>comparison.activity().map(item=>({code:item.code,time:item.time})));
      const listed=await page.locator('.attack-feed').nth(i).locator('li').evaluateAll(items=>items.map(item=>({code:item.querySelector('strong').textContent,time:Number(item.dataset.time)})));
      assert.deepEqual(listed,expected,'Feed shows exactly the completed techniques and CVEs');
      assert(listed.every((item,index)=>!index||
        (/EXFILTRAT|EXPORT NOT ATTEMPTED/.test(listed[index-1].code)&&!/EXFILTRAT|EXPORT NOT ATTEMPTED/.test(item.code)) ||
        /EXFILTRAT|EXPORT NOT ATTEMPTED/.test(listed[index-1].code)===/EXFILTRAT|EXPORT NOT ATTEMPTED/.test(item.code)&&listed[index-1].time>=item.time),
        'All export outcomes are pinned; each group is newest first');
      assert(await panel.evaluate(()=>comparison.activity().some(item=>['NO NEW ACCESS','PATH REVIEW'].includes(item.code))),'Timed dead ends remain visible');
      assert(await panel.evaluate(()=>comparison.activity().filter(item=>item.code==='PATH REVIEW').every(item=>{
        const event=run.events[item.id],source=estate.assets.find(a=>a.id===event.sourceId),target=estate.assets.find(a=>a.id===event.targetId);
        return item.asset===source.label&&!item.detail.includes(target.label);
      })),'Path reviews name the known source without exposing an inaccessible target');
    }
    for(const viewport of [{width:1280,height:720},{width:1920,height:1080},{width:2880,height:1620}]){
      await page.setViewportSize(viewport);await page.evaluate(()=>fit());
      const geometry=await page.evaluate(()=>frames.map(f=>{
        const frame=f.getBoundingClientRect(),canvas=f.parentElement.getBoundingClientRect(),feed=f.parentElement.previousElementSibling;
        return {left:Math.abs(frame.left-canvas.left),right:Math.abs(frame.right-canvas.right),bottom:Math.abs(frame.bottom-canvas.bottom),
          background:getComputedStyle(feed).backgroundColor,color:getComputedStyle(feed).color,overflow:getComputedStyle(feed).overflowY};
      }));
      for(const item of geometry){assert(item.left<1&&item.right<1&&item.bottom<2,'Estate fills available space without side gutters');
        assert.equal(item.background,'rgb(241, 243, 245)');assert.equal(item.color,'rgb(17, 17, 17)');assert.equal(item.overflow,'auto');}
    }
    if(process.env.DUAL_LAYOUT_SCREENSHOT)await page.screenshot({path:process.env.DUAL_LAYOUT_SCREENSHOT});
    for(const [i,panel] of panels.entries()){
      const final=await panel.evaluate(()=>({estate:JSON.stringify(estate),run:JSON.stringify(run),
        visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),expected:discoveryPlan.assetIds}));
      assert.deepEqual(final.visible,final.expected);assert.equal(final.estate,before[i].estate);assert.equal(final.run,before[i].run);
    }
    // Data discovery must appear before a separately completed bulk transfer.
    await page.evaluate(()=>prepare());
    const dataTimes=await panels[1].evaluate(()=>({read:run.events.find(e=>e.isProtectedRead&&e.outcome==='succeeded').timeSec,
      transfer:run.events.find(e=>e.actionKind==='data_exfiltration'&&e.outcome==='succeeded').timeSec,
      records:run.summary.exfiltratedDatasets[0].records}));
    await panels[1].evaluate(time=>comparison.advance(time),dataTimes.read);
    await page.evaluate(()=>updateFeeds());
    assert.match(await page.locator('.attack-feed').nth(1).innerText(),/DATA FOUND/);
    assert.doesNotMatch(await page.locator('.attack-feed').nth(1).innerText(),/DATA EXFILTRATED/);
    assert(dataTimes.records>3,'Malicious ARTEX exports beyond a proof sample');
    await panels[1].evaluate(time=>comparison.advance(time),dataTimes.transfer);
    await page.evaluate(()=>updateFeeds());
    const bulk=await page.locator('.attack-feed').nth(1).innerText();
    assert.match(bulk,/DATA EXFILTRATED/);assert(bulk.includes(`${dataTimes.records} records`));
    assert.match(bulk,/HTTP\/API bulk extraction/);assert.match(bulk,/Attacker-controlled workspace/);
    assert.doesNotMatch(bulk,/\(modeled\)/i);
    await page.evaluate(()=>{estate.assets.forEach(a=>{if(a.egress)a.egress.responseExportAllowed=false;});prepare();
      frames[1].contentWindow.comparison.advance(Infinity);updateFeeds();});
    const denied=await page.locator('.attack-feed').nth(1).innerText();
    assert.match(denied,/DATA FOUND/);assert.match(denied,/EXFILTRATION BLOCKED/);assert.doesNotMatch(denied,/DATA EXFILTRATED/);
    // New Infra must update the displayed seed and actual profile, not merely replay.
    let previousSeed=1853, previousGang='lockbit';
    const gangs=new Set([previousGang]);
    for(let i=0;i<4;i++){
      await page.click('#new');
      const current=await page.evaluate(()=>({seed:estate.seed,field:Number(document.getElementById('seed').value),
        status:status.textContent,gang:gangId,label:document.getElementById('gang-profile').textContent,
        estates:frames.map(f=>JSON.stringify(f.contentWindow.comparison.state().estate))}));
      assert.notEqual(current.seed,previousSeed);assert.equal(current.field,current.seed);
      assert(current.status.includes(`Seed ${current.seed}`));assert.notEqual(current.gang,previousGang);
      assert.equal(current.estates[0],current.estates[1]);assert.notEqual(current.estates[0],before[0].estate);
      const actual=await panels[0].evaluate(()=>({gang:run.assumptions.techniquePolicy.gangId,label:pre2023Groups[pre2023Group],infra:infrastructureNumber}));
      assert.equal(actual.gang,current.gang);assert(current.label.includes(actual.label));assert.equal(actual.infra,i+2);
      gangs.add(current.gang);previousSeed=current.seed;previousGang=current.gang;
    }
    assert.equal(gangs.size,5,'New infrastructure cycles through all five gang policies');
    const scenario=await page.evaluate(()=>({estate:JSON.stringify(estate),gang:gangId}));
    for(const selector of ['[data-mode="patch"]','#run','[data-mode="baseline"]']){
      await page.click(selector);
      assert.deepEqual(await page.evaluate(()=>({estate:JSON.stringify(estate),gang:gangId})),scenario);
      assert.equal(await panels[0].evaluate(()=>run.assumptions.techniquePolicy.gangId),scenario.gang);
      if(selector!=='#run')assert.equal(await page.locator('.attack-feed li').count(),0,'Defense changes clear the activity feeds');
    }
    await page.fill('#seed','1853');await page.press('#seed','Enter');
    assert.equal(await panels[0].evaluate(()=>JSON.stringify(estate)),before[0].estate,'Explicit seed reproduces the estate');
    await page.fill('#seed','4294967296');await page.press('#seed','Enter');
    assert.match(await page.locator('#status').textContent(),/Enter an integer seed/);
    assert.equal(await panels[0].evaluate(()=>JSON.stringify(estate)),before[0].estate,'Invalid seed leaves the current estate intact');
    await page.evaluate(()=>{gangId='revil';document.getElementById('seed').value=1;generate();
      estate.assets.find(a=>a.id==='windows-desktop').conditions.mailFilterBlocksAttachment=true;prepare();});
    assert.equal(await panels[0].evaluate(()=>comparison.done),false,'Ready view has not run');
    await page.click('#run');
    const failedEntry=await panels[0].evaluate(()=>{comparison.advance(Infinity);return {done:comparison.done,time:modeledTime,hud:runHud.textContent,
      successes:run.events.filter(e=>e.outcome==='succeeded').length};});
    assert.equal(failedEntry.done,true,'Failed entry playback completes');
    assert(failedEntry.time>0);assert.equal(failedEntry.successes,0);
    assert.match(failedEntry.hud,/REvil.*No access established.*Mail filtering blocks/);
    await page.evaluate(()=>{document.getElementById('seed').value=3;generate();});
    await page.click('#run');
    await panels[0].evaluate(()=>comparison.advance(Infinity));
    const successfulEntry=await panels[0].evaluate(()=>({done:comparison.done,events:run.events.filter(e=>e.outcome==='succeeded').map(e=>e.technique)}));
    assert(successfulEntry.done);assert(successfulEntry.events.includes('T1566.001'));assert(successfulEntry.events.some(t=>['T1047','T1569.002','T1021.001'].includes(t)));assert(successfulEntry.events.includes('T1486'));
    assert(await panels[0].evaluate(()=>comparison.activity().some(item=>/Cobalt Strike Beacon/.test(item.title))),
      'Named Cobalt Strike tool appears in the existing activity feed');
    for(const gang of ['conti','revil']){
      await page.evaluate(gang=>{gangId=gang;estate=WireEngine.generateEstate({seed:1,seedExercise:true});
        estate.findings=estate.findings.filter(f=>f.kind==='phishing_attachment');estate.credentials=[];runBoth();},gang);
      const phish=await panels[0].evaluate(()=>{comparison.advance(Infinity);return {state:currentNodes.get('windows-desktop').el.querySelector('.node-state').textContent,
        tickets:[...socTickets.values()],impact:run.result.impact};});
      assert.equal(phish.state,'PHISH EXECUTED');assert.equal(phish.impact,false);
      assert(phish.tickets.some(t=>t.title.includes('Phishing attachment executed')&&t.severity==='HIGH'),`${gang} phishing alert appears without lateral movement`);
      assert(await panels[0].evaluate(()=>comparison.done),`${gang} isolated phish completes`);
      const lateral=await panels[0].evaluate(()=>({hud:runHud.textContent,activity:comparison.activity()}));
      assert.match(lateral.hud,/No lateral movement established|Lateral movement failed/);
      assert.match(lateral.hud,/No usable outgoing route|No applicable|No supported|No access|credential|permission/i);
      assert(lateral.activity.some(item=>item.code==='LATERAL MOVEMENT'&&item.detail),`${gang} completion feed explains absent lateral movement`);
    }
    await page.evaluate(()=>{gangId='conti';estate=WireEngine.generateEstate({seed:99,seedExercise:true});runBoth();});
    const stopped=await panels[0].evaluate(()=>{comparison.advance(Infinity);return {hud:runHud.textContent,activity:comparison.activity()};});
    assert.match(stopped.hud,/Lateral movement failed/);
    assert(stopped.activity.some(item=>item.code==='LATERAL MOVEMENT'&&/credential/i.test(item.detail)),
      'A failed Conti continuation explains credential prerequisites even when local encryption succeeds');
    await page.evaluate(()=>{
      const duration = document.getElementById('duration');
      duration.add(new Option('Fast test playback', '0.01'));
      duration.value = '0.01';
      estate.findings=[];estate.credentials=[];runBoth();
    });
    await page.waitForFunction(()=>frames.every(f=>f.contentWindow.comparison.done) && status.textContent.includes('Both complete'));
    assert.match(await page.locator('#status').textContent(),/Both complete/);
    await page.goto(`${base}/wire.html?capture=path&manual=1`);
    await page.waitForFunction(()=>!!window.pathCapture);
    const pathStart=await page.evaluate(()=>{
      pathCapture.prepare(WireEngine.generateEstate({seed:3,seedExercise:true}),'pre2023','baseline');
      return {estate:JSON.stringify(estate),run:JSON.stringify(run),visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),initial:discoveryPlan.initialAssetIds};
    });
    assert.deepEqual(pathStart.visible,pathStart.initial);
    const pathEnd=await page.evaluate(()=>{
      pathCapture.advance(Infinity);
      return {estate:JSON.stringify(estate),run:JSON.stringify(run),visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),expected:discoveryPlan.assetIds};
    });
    assert.deepEqual(pathEnd.visible,pathEnd.expected);assert.equal(pathEnd.estate,pathStart.estate);assert.equal(pathEnd.run,pathStart.run);
    assert.deepEqual(errors,[]);
    console.log('PASS comparison discovery: shared initial view, growing fit, trace filtering, fresh seeds, gang rotation, stable replay/defenses, explicit seed reproduction');
  }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
