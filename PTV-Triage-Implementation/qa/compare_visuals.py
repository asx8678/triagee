#!/usr/bin/env python3
"""Strict same-size screenshot comparison with overlays, heatmaps and geometry evidence.
Never rescales images or modifies baselines. Default pixel gate: channel delta>16 and <=0.5% changed.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from PIL import Image,ImageChops
ROOT=Path(__file__).resolve().parents[1]
STYLE_KEYS=['color','backgroundColor','borderTopLeftRadius','borderTopRightRadius',
 'borderBottomLeftRadius','borderBottomRightRadius','borderTopWidth','borderRightWidth',
 'borderBottomWidth','borderLeftWidth','fontSize','fontWeight']
def geometry(expected:Path,actual:Path):
 if not expected.exists() or not actual.exists():return {'passed':False,'errors':['Missing geometry JSON; capture it with the screenshot.']}
 e=json.loads(expected.read_text());a=json.loads(actual.read_text());errors=[];compared=0
 if a.get('documentOverflow'):errors.append('Document-wide horizontal overflow')
 for sel,rows in e.get('selectors',{}).items():
  ar=a.get('selectors',{}).get(sel,[])
  for i,row in enumerate(rows):
   if not row['visible']:continue
   if i>=len(ar) or not ar[i]['visible']:
    errors.append(f'{sel}[{i}]: missing visible element');continue
   actualrow=ar[i];compared+=1
   for key in ['x','y','width','height']:
    tol=1 if key=='height' and sel in {'.topbar','.scopebar','.bottom-status','.review-footer','#decisionAction','#decisionOwner','#decisionDue'} else 2
    if abs(row['rect'][key]-actualrow['rect'][key])>tol:
     errors.append(f'{sel}[{i}] {key}: expected {row["rect"][key]:.3f}, actual {actualrow["rect"][key]:.3f}; tolerance {tol}px')
   for key in STYLE_KEYS:
    if row['styles'].get(key)!=actualrow['styles'].get(key):
     errors.append(f'{sel}[{i}] {key}: expected {row["styles"].get(key)}, actual {actualrow["styles"].get(key)}')
 return {'passed':not errors,'elements_compared':compared,'errors':errors}
def main()->int:
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--baseline',type=Path,default=ROOT/'reference/baselines')
 p.add_argument('--actual',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--channel-threshold',type=int,default=16);p.add_argument('--max-diff-ratio',type=float,default=.005)
 p.add_argument('--case',action='append',default=[]);p.add_argument('--skip-geometry',action='store_true',help='Pixel-only investigation; not a complete acceptance run.')
 a=p.parse_args()
 if not 0<=a.channel_threshold<=255 or not 0<=a.max_diff_ratio<=1:p.error('Thresholds out of range')
 if a.output.resolve()==a.baseline.resolve() or a.baseline.resolve() in a.output.resolve().parents:p.error('Output cannot overwrite baseline directory')
 a.output.mkdir(parents=True,exist_ok=True)
 cases=json.loads((ROOT/'contracts/visual-cases.json').read_text())['cases']
 if a.case:
  unknown=set(a.case)-{c['id'] for c in cases}
  if unknown:p.error('Unknown cases: '+', '.join(sorted(unknown)))
  cases=[c for c in cases if c['id'] in a.case]
 results=[]
 for case in cases:
  cid=case['id'];ep=a.baseline/(cid+'.png');ap=a.actual/(cid+'.png')
  row={'id':cid,'passed':False}
  if not ep.exists() or not ap.exists():row['error']='Missing expected or actual screenshot';results.append(row);continue
  with Image.open(ep) as ex,Image.open(ap) as ac:
   e=ex.convert('RGB');v=ac.convert('RGB')
   if e.size!=v.size:row['error']=f'Dimension mismatch {e.size} vs {v.size}; never resized';results.append(row);continue
   diff=ImageChops.difference(e,v);channels=diff.split();mx=ImageChops.lighter(ImageChops.lighter(channels[0],channels[1]),channels[2])
   mask=mx.point(lambda x:255 if x>a.channel_threshold else 0);changed=mask.histogram()[255];ratio=changed/(e.width*e.height)
   overlay=Image.blend(e,v,.5);overlay.save(a.output/(cid+'-overlay.png'))
   heat=Image.new('RGB',e.size,(255,255,255));heat.paste((181,40,50),(0,0,e.width,e.height),mask);heat.save(a.output/(cid+'-diff.png'))
   g={'passed':True,'skipped':True} if a.skip_geometry else geometry(a.baseline/(cid+'.json'),a.actual/(cid+'.json'))
   row.update({'changed_pixels':changed,'changed_ratio':ratio,'pixel_passed':ratio<=a.max_diff_ratio,'geometry':g,'passed':ratio<=a.max_diff_ratio and g['passed']})
   results.append(row)
 report={'target':'actual screenshots supplied by caller; reference/application distinction must be recorded separately',
  'baseline_directory':str(a.baseline),'actual_directory':str(a.actual),'threshold':a.channel_threshold,
  'max_diff_ratio':a.max_diff_ratio,'geometry_skipped':a.skip_geometry,'passed':sum(r['passed'] for r in results),'total':len(results),'cases':results}
 (a.output/'comparison-report.json').write_text(json.dumps(report,indent=2)+'\n')
 blocks=''.join(f'<section><h2>{r["id"]} · {"PASS" if r["passed"] else "FAIL"}</h2><p>{r.get("error",str(round(r.get("changed_ratio",0)*100,4))+"% changed pixels")}</p>'+('' if 'error'in r else f'<img src="{r["id"]}-overlay.png" alt="50 percent overlay"><img src="{r["id"]}-diff.png" alt="Pixel difference heatmap">')+'</section>' for r in results)
 (a.output/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>PTV visual comparison</title><style>body{font:15px system-ui;margin:24px}section{border:1px solid #ccc;margin:24px 0;padding:16px}img{max-width:49%;border:1px solid #ccc}</style><h1>PTV Triage visual comparison</h1><p>Left:50%overlay. Right:changed-pixel heatmap. Review geometry details in the JSON report. A passing aggregate ratio is not permission for localized design drift.</p>'+blocks+'</html>')
 print(json.dumps({'passed':report['passed'],'total':report['total'],'output':str(a.output)},indent=2));return 0 if report['passed']==report['total'] else 1
if __name__=='__main__':raise SystemExit(main())
