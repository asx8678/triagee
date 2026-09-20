#!/usr/bin/env python3
"""Capture an ISOLATED application fixture using actual routes and controls.
The config must be completed by the implementation agent. No assumed production routes or seeding.
"""
from __future__ import annotations
import argparse,json,shutil,sys
from pathlib import Path
from urllib.parse import urlparse,urljoin
from playwright.sync_api import sync_playwright
from capture_reference import CSS_SELECTORS,PROPERTIES
ROOT=Path(__file__).resolve().parents[1]

def origin(url:str)->str:
 p=urlparse(url);return f'{p.scheme}://{p.netloc}'
def step(page,s:dict)->None:
 action=s['action'];loc=page.locator(s['selector']).first
 if action=='click':loc.click()
 elif action=='fill':loc.fill(s['value'])
 elif action=='select_option':loc.select_option(s['value'])
 elif action=='check':loc.check()
 elif action=='uncheck':loc.uncheck()
 elif action=='press':loc.press(s['key'])
 elif action=='wait_for':loc.wait_for(state=s.get('state','visible'))
 elif action=='scroll':loc.evaluate('(el,p)=>{el.scrollTop=p.top;el.scrollLeft=p.left}',{'top':s.get('top',0),'left':s.get('left',0)})
 else:raise ValueError(f'Unsupported step action: {action}')

def main()->int:
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--acknowledge-test-environment',action='store_true');p.add_argument('--allow-remote',action='store_true')
 a=p.parse_args()
 if not a.acknowledge_test_environment:p.error('Require --acknowledge-test-environment; use synthetic isolated data only.')
 cfg=json.loads(a.config.read_text())
 if cfg.get('configured') is not True:p.error('Example config is not configured. Map actual routes/steps and fixture readiness first.')
 base=cfg.get('base_url','');u=urlparse(base)
 if u.scheme not in {'http','https'} or not u.hostname or u.username or u.password:p.error('Use an HTTP(S) base URL without embedded credentials.')
 if u.hostname not in {'127.0.0.1','localhost','::1'} and not a.allow_remote:p.error('Remote test origin requires explicit --allow-remote, in addition to fixture acknowledgement.')
 if cfg.get('fixture_id')!='ptv-approved-v1':p.error('Wrong fixture ID')
 expected={c['id']:c for c in json.loads((ROOT/'contracts/visual-cases.json').read_text())['cases']}
 cases=cfg.get('cases',[])
 if set(c.get('id')for c in cases)!=set(expected):p.error('Config must contain exactly the32reference visual cases; compare subsets later for investigation.')
 if len(cases)!=len(expected):p.error('Duplicate cases')
 for c in cases:
  if not c.get('route'):p.error('Unmapped route for '+c['id'])
  if [c.get('width'),c.get('height')]!=[expected[c['id']]['width'],expected[c['id']]['height']]:p.error('Viewport mismatch: '+c['id'])
  if origin(urljoin(base,c['route']))!=origin(base):p.error('Case route must stay on the configured test origin.')
 out=a.output.resolve()
 if (ROOT/'reference').resolve()==out or (ROOT/'reference').resolve() in out.parents:p.error('Cannot overwrite reference files')
 out.mkdir(parents=True,exist_ok=True);results=[]
 allowed={origin(base),*cfg.get('allowed_origins',[])};selector_map=cfg.get('selector_map',{})
 with sync_playwright() as pw:
  bp=cfg.get('browser_path') or shutil.which('chromium') or shutil.which('chromium-browser')
  kw={'headless':True}
  if bp:kw['executable_path']=bp
  browser=pw.chromium.launch(**kw)
  for c in cases:
   context=browser.new_context(viewport={'width':c['width'],'height':c['height']},device_scale_factor=1,
      locale='en-US',timezone_id='UTC',color_scheme='light',reduced_motion='reduce')
   page=context.new_page();page.set_default_timeout(12000);blocked=[];errors=[]
   page.on('pageerror',lambda e:errors.append(str(e)))
   def route_handler(route):
    request_url=route.request.url
    if request_url.startswith(('data:','blob:','about:')) or origin(request_url) in allowed:route.continue_()
    else:blocked.append(request_url);route.abort()
   context.route('**/*',route_handler)
   row={'id':c['id'],'passed':False}
   try:
    page.goto(urljoin(base,c['route']),wait_until='domcontentloaded')
    page.locator(cfg['ready_selector']).wait_for(state='attached')
    for s in c.get('steps',[]):step(page,s)
    page.evaluate('document.fonts.ready');page.wait_for_timeout(100)
    page.screenshot(path=str(out/(c['id']+'.png')),full_page=False,animations='disabled')
    measurement=page.evaluate('''({selectors,properties,map})=>{
      const result={viewport:{width:innerWidth,height:innerHeight},documentOverflow:document.documentElement.scrollWidth>innerWidth,selectors:{}};
      for(const s of selectors){const actual=map[s]||s;
        result.selectors[s]=[...document.querySelectorAll(actual)].slice(0,5).map(el=>{
          const r=el.getBoundingClientRect(),cs=getComputedStyle(el);return {
           text:(el.textContent||'').trim().slice(0,140),visible:r.width>0&&r.height>0&&cs.visibility!=='hidden'&&cs.display!=='none',
           rect:{x:r.x,y:r.y,width:r.width,height:r.height,bottom:r.bottom,right:r.right},
           styles:Object.fromEntries(properties.map(k=>[k,cs[k]]))};});}return result;
     }''',{'selectors':CSS_SELECTORS,'properties':PROPERTIES,'map':selector_map})
    (out/(c['id']+'.json')).write_text(json.dumps(measurement,indent=2)+'\n')
    row['passed']=not errors and not blocked and not measurement['documentOverflow']
   except Exception as e:row['error']=str(e)
   row.update({'runtime_errors':errors,'blocked_external_requests':blocked});results.append(row);context.close()
  version=browser.version;browser.close()
 report={'target':'caller-configured isolated application fixture','browser_version':version,'fixture_id':cfg['fixture_id'],
  'passed':sum(r['passed'] for r in results),'total':len(results),'cases':results}
 (out/'application-capture-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'total':report['total'],'output':str(out)},indent=2))
 return 0 if report['passed']==report['total'] else 1
if __name__=='__main__':raise SystemExit(main())
