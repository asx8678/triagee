#!/usr/bin/env python3
"""Render the frozen reference. No production system is accessed or modified.
Requires Playwright and Chromium. Run from any directory; see --help.
"""
from __future__ import annotations
import argparse, hashlib, importlib.metadata, json, platform, shutil, sys
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
CSS_SELECTORS = [
 '#shell','.topbar','.brand','.topnav','.topnav button.active','.scopebar','.bottom-status',
 '.page','.page-head','h1','.callout','.metrics','.metric','.dashboard-grid','.panel',
 '.panel-head','.data-table','.data-table th','.data-table td','.toolbar','.tabs','.tabs button.active',
 '.review-tools','.review-grid','.queue-panel','.queue-heading','.queue-item.active',
 '.review-workspace','.review-heading','.review-content','.evidence-column','.decision-column',
 '.fact-grid','.scope-table','.scope-alert','#decisionAction','#decisionOwner','#decisionDue',
 '#decisionReason','.review-footer','[data-action="save-next"]','[data-action="save-decision"]',
 '#inspector[open]','.inspector-layout','.inspector-head','.inspector-body','.inspector-foot',
 '.timeline-stats','.legend','.timeline-chart','.time-header','.time-row','.track',
 '.heatmap','#modal[open]','.modal-head','.modal-body','.modal-foot']
PROPERTIES=['display','position','boxSizing','gridTemplateColumns','gridTemplateRows','gap',
 'width','height','minHeight','maxHeight','paddingTop','paddingRight','paddingBottom','paddingLeft',
 'marginTop','marginRight','marginBottom','marginLeft','borderTopWidth','borderRightWidth',
 'borderBottomWidth','borderLeftWidth','borderTopLeftRadius','borderTopRightRadius',
 'borderBottomRightRadius','borderBottomLeftRadius','borderColor','color','backgroundColor',
 'boxShadow','fontFamily','fontSize','fontWeight','lineHeight','letterSpacing','whiteSpace',
 'overflowX','overflowY','zIndex']

def main() -> int:
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--output',type=Path,default=ROOT/'qa/results/reference-capture')
 p.add_argument('--cases',type=Path,default=ROOT/'contracts/visual-cases.json')
 p.add_argument('--browser',default=shutil.which('chromium') or shutil.which('chromium-browser'))
 args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
 if out==ROOT/'reference/approved' or (ROOT/'reference/approved') in out.parents:
  p.error('Do not overwrite the approved files.')
 cases=json.loads(args.cases.read_text())['cases']
 htmlpath=ROOT/'reference/approved/ptv-triage-prototype.html';html=htmlpath.read_text()
 meta={'reference_sha256':hashlib.sha256(htmlpath.read_bytes()).hexdigest(),
       'python':sys.version.split()[0],'platform':platform.platform(),
       'playwright':importlib.metadata.version('playwright'),
       'locale':'en-US','timezone':'UTC','device_scale_factor':1,
       'origin':'page.set_content / about:blank; fresh isolated context per case',
       'clock':'2026-09-19T10:00:00Z, set in reference source','cases':[]}
 with sync_playwright() as pw:
  kwargs={'headless':True}
  if args.browser:kwargs['executable_path']=args.browser
  browser=pw.chromium.launch(**kwargs);meta['browser_version']=browser.version
  for case in cases:
   context=browser.new_context(viewport={'width':case['width'],'height':case['height']},
       device_scale_factor=1,locale='en-US',timezone_id='UTC',color_scheme='light',reduced_motion='reduce')
   page=context.new_page();errors=[];network=[]
   page.on('pageerror',lambda e:errors.append(str(e)))
   page.on('request',lambda r:network.append(r.url))
   page.set_content(html,wait_until='domcontentloaded')
   if case.get('setup_js'):page.evaluate(case['setup_js'])
   page.evaluate('document.fonts.ready');page.wait_for_timeout(80)
   shot=out/(case['id']+'.png');page.screenshot(path=str(shot),full_page=False,animations='disabled')
   measurements=page.evaluate('''({selectors,properties})=>{
     const result={viewport:{width:innerWidth,height:innerHeight},
       documentOverflow:document.documentElement.scrollWidth>innerWidth,selectors:{}};
     for(const selector of selectors){result.selectors[selector]=[...document.querySelectorAll(selector)].slice(0,5).map(el=>{
       const r=el.getBoundingClientRect(),s=getComputedStyle(el);
       return {text:(el.textContent||'').trim().slice(0,140),visible:r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none',
        rect:{x:r.x,y:r.y,width:r.width,height:r.height,bottom:r.bottom,right:r.right},
        styles:Object.fromEntries(properties.map(k=>[k,s[k]]))};
     });}return result;
   }''',{'selectors':CSS_SELECTORS,'properties':PROPERTIES})
   (out/(case['id']+'.json')).write_text(json.dumps(measurements,indent=2)+'\n')
   meta['cases'].append({'id':case['id'],'screenshot':shot.name,'width':case['width'],'height':case['height'],
       'sha256':hashlib.sha256(shot.read_bytes()).hexdigest(),'runtime_errors':errors,'network_requests':network,
       'document_overflow':measurements['documentOverflow']})
   if case['id']=='overview-1600':
    fixture=page.evaluate('({synthetic:true,fixture_id:"ptv-approved-v1",clock:DEMO_NOW.toISOString(),records:structuredClone(initial)})')
    (out/'synthetic-fixture.json').write_text(json.dumps(fixture,indent=2)+'\n')
    expectations=page.evaluate('''()=>{const out=[];for(const team of ['all','data','alpha','beta','platform','unassigned']){
      for(const env of ['all','prod','staging']){state.team=team;state.env=env;
       const scopes=active().flatMap(r=>visibleScopes(r).filter(activeScope));
       out.push({team,environment:env,active_cve_ids:active().map(r=>r.id).sort(),
        decision_cve_ids:needs().map(r=>r.id).sort(),priority_cve_ids:urgent().map(r=>r.id).sort(),
        unknown_exposure_scope_ids:scopes.filter(s=>s.exposure==='Unknown').map(s=>s.id).sort()});}}
      return out;}''')
    (out/'fixture-expectations.json').write_text(json.dumps({'fixture_id':'ptv-approved-v1','cases':expectations},indent=2)+'\n')
    icons=page.evaluate('I');assets=out/'icons';assets.mkdir(exist_ok=True)
    for name,svg in icons.items():
     (assets/(name+'.svg')).write_text(svg.replace('<svg ','<svg xmlns="http://www.w3.org/2000/svg" ',1))
   context.close()
  browser.close()
 (out/'capture-report.json').write_text(json.dumps(meta,indent=2)+'\n')
 rows='\n'.join(f'<article><h2>{c["id"]}</h2><p>{c["width"]} × {c["height"]} CSS px</p><a href="{c["screenshot"]}"><img loading="lazy" src="{c["screenshot"]}" alt="{c["id"]} approved prototype rendering"></a></article>' for c in meta['cases'])
 (out/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>PTV Triage visual baselines</title><style>body{font:15px/1.5 system-ui;margin:32px;background:#f3f5f8;color:#17263c}main{max-width:1640px;margin:auto}article{padding:20px;background:white;border:1px solid #d5dde7;margin:24px 0}img{width:100%;height:auto;border:1px solid #d5dde7}h2{font-size:18px}</style><main><h1>PTV Triage · frozen-reference renders</h1><p>Synthetic data. These are renderings of the approved HTML, not screenshots of an implemented production application. Open an image at native size for visual comparison.</p>'+rows+'</main></html>')
 failed=[c for c in meta['cases'] if c['runtime_errors'] or c['network_requests']]
 print(json.dumps({'cases':len(cases),'runtime_or_network_failures':len(failed),'output':str(out)},indent=2))
 return 1 if failed else 0
if __name__=='__main__':raise SystemExit(main())
