// Read/draft-only CDP regression probe; never submits a decision.
// Use the same owned fixture/origin guard as workspace_interactions.js.
const info = await pageInfo();
const origin = globalThis.workspaceFixtureOrigin;
const out = globalThis.workspaceEvidenceDir;
if (!origin || !out || new URL(info.url).origin !== origin || !/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin)) throw Error("Owned fixture origin and evidence directory required");
const read = async expression => {
  const r = await session.Runtime.evaluate({expression,returnByValue:true,awaitPromise:true});
  if (r.exceptionDetails) throw Error(JSON.stringify(r.exceptionDetails));
  return r.result.value;
};
const wait = expression => read(`new Promise((resolve,reject)=>{const check=()=>{if(${expression}){observer.disconnect();clearTimeout(timer);resolve(true)}};const observer=new MutationObserver(check);observer.observe(document.documentElement,{subtree:true,childList:true,attributes:true});const timer=setTimeout(()=>{observer.disconnect();reject(new Error("Readiness timeout"))},5000);check();})`);
const guarded = () => read('(()=>{const e=new Event("beforeunload",{cancelable:true});window.dispatchEvent(e);return e.defaultPrevented;})()');
await session.Page.bringToFront();
await session.Emulation.setDeviceMetricsOverride({width:1600,height:1000,deviceScaleFactor:1,mobile:false});
await session.Page.navigate({url:origin+"/workspace?team=alpha&page=review&item=CVE-2099-1002"});
await wait('document.querySelector(".phx-connected #workspace-review")');
if (!await read('document.querySelector("#workspace-review").textContent.includes("Synthetic second advisory")')) throw Error("Not owned fixture");
if (await guarded()) throw Error("Pristine draft incorrectly guarded");
await read('document.querySelector("#scope-target-2").click()');
await wait('document.querySelector("#shell").dataset.dirty==="true"');
if (!await guarded()) throw Error("Target-only edit is unguarded");
const confirmations = [];
const off = session.onEvent((method, params) => {
  if (method !== 'Page.javascriptDialogOpening' || params.type !== 'confirm') return;
  confirmations.push(params.message);
  // Cancel leaving so the unsaved draft remains intact.
  session.Page.handleJavaScriptDialog({accept:false}).catch(()=>{});
});
try {
  const before = await read('location.href');
  await read('(()=>{const a=document.createElement("a");a.href="/imports";document.querySelector("#shell").append(a);a.click();a.remove();})()');
  if (await read('location.href') !== before) throw Error("Cancelled leave navigated away");
  if (!confirmations.some(s=>s.startsWith('Leave this workspace?'))) throw Error("Missing leave confirmation");
  if (await read(`document.querySelector('button[phx-click="new-draft"]') !== null`)) throw Error("Removed draft button rendered");
  await read('window.liveSocket.disconnect()');
  await read('(()=>{const e=document.querySelector("#workspace-decision textarea");e.value="Unacknowledged offline draft";e.dispatchEvent(new Event("input",{bubbles:true}));})()');
  if (!await guarded()) throw Error("Unacknowledged offline input is unguarded");
  if (await read('document.querySelector("#shell").dataset.dirty') !== 'true') throw Error("Existing dirty draft unexpectedly cleared");
  await read('window.liveSocket.connect()');
  await wait('document.querySelector(".phx-connected #workspace-review")');
  if (!await guarded()) throw Error("Reconnect lost the unsaved draft guard");
  const result = {targetOnlyGuarded:true,cancelledLeavePreserved:true,newDraftButtonAbsent:true,offlineInputGuarded:true,noDecisionSubmitted:true};
  await (await import('node:fs/promises')).writeFile(`${out}/draft-guard.json`,JSON.stringify(result,null,2));
  return result;
} finally {
  off();
}
