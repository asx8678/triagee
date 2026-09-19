// Run through browser-harness-js on the owned workspace_browser server only.
// CDP globals come from the browser skill. This probe is read-only (scroll/resize).
const info = await pageInfo();
if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+\/workspace/.test(info.url)) throw Error("Expected owned loopback workspace");
const fs = await import("node:fs/promises");
const out = globalThis.workspaceEvidenceDir;
if (!out) throw Error("Set globalThis.workspaceEvidenceDir to an absolute artifact directory first");
await fs.mkdir(out, {recursive:true});
const sizes = [[1600,1000],[1920,1080],[1366,768],[1280,720],[1750,1000],[1749,1000],[1151,768],[1150,768],[851,768],[850,768],[641,844],[640,844],[390,844]];
const reports = [];
for (const [width,height] of sizes) {
  await session.Emulation.setDeviceMetricsOverride({width,height,deviceScaleFactor:1,mobile:false});
  await session.Runtime.evaluate({expression:"new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))",awaitPromise:true});
  const {result} = await session.Runtime.evaluate({expression:`(() => {
    const sels=[".topbar",".scopebar",".queue-panel",".review-workspace",".decision-column",".review-footer"];
    for(const s of [".queue-list",".evidence-column",".decision-column",".review-content"]){const e=document.querySelector(s);if(e)e.scrollTop=e.scrollHeight;}
    const actions=["#save-decision","#save-next"].map(selector=>{const e=document.querySelector(selector);if(!e)return {selector,visible:false};const r=e.getBoundingClientRect();const hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return {selector,rect:r.toJSON(),visible:r.width>0&&r.height>0&&r.top>=0&&r.bottom<=innerHeight&&r.right<=innerWidth&&!!hit&&(hit===e||e.contains(hit))};});
    return {width:innerWidth,height:innerHeight,overflow:document.documentElement.scrollWidth>innerWidth,actions,rects:Object.fromEntries(sels.map(s=>[s,document.querySelector(s)?.getBoundingClientRect().toJSON()]))};
  })()`,returnByValue:true});
  reports.push(result.value);
  if ([1600,1366,1280,390,850].includes(width)) await fs.writeFile(`${out}/review-scrolled-${width}.png`,Buffer.from((await session.Page.captureScreenshot({format:"png"})).data,"base64"));
}
await fs.writeFile(`${out}/geometry.json`, JSON.stringify(reports,null,2));
const failures=reports.filter(r=>r.overflow||r.actions.some(a=>!a.visible));
if (failures.length) throw Error(`Action reachability/overflow failed at ${failures.map(r=>r.width).join(", ")}; see ${out}/geometry.json`);
return {cases:reports.length,passed:reports.length-failures.length,failures,artifact:`${out}/geometry.json`};
