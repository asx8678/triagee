#!/usr/bin/env python3
"""Self-tests for comparison failure detection and safe application-capture configuration guards."""
from __future__ import annotations
import argparse,hashlib,json,shutil,subprocess,sys,tempfile
from pathlib import Path
from PIL import Image,ImageDraw
ROOT=Path(__file__).resolve().parents[1]
def run(script,args):return subprocess.run([sys.executable,str(ROOT/'qa'/script),*args],capture_output=True,text=True,timeout=90)
def main()->int:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'qa/results/harness-self-tests.json');a=p.parse_args();checks=[]
 def check(name,ok):checks.append({'test':name,'passed':bool(ok)})
 with tempfile.TemporaryDirectory(prefix='ptv-harness-') as td:
  temp=Path(td);actual=temp/'actual';actual.mkdir();cid='review-1600'
  for suffix in ['.png','.json']:shutil.copy2(ROOT/'reference/baselines'/(cid+suffix),actual/(cid+suffix))
  def compare(name):return run('compare_visuals.py',['--actual',str(actual),'--output',str(temp/name),'--case',cid])
  result=compare('identical');check('Comparator accepts identical screenshot and geometry',result.returncode==0)
  with Image.open(actual/(cid+'.png')) as original:
   im=original.convert('RGB');ImageDraw.Draw(im).rectangle((0,0,300,120),fill=(240,0,240));im.save(actual/(cid+'.png'))
  result=compare('pixel-drift');report=json.loads((temp/'pixel-drift/comparison-report.json').read_text())
  check('Comparator rejects deliberate visual drift',result.returncode==1 and not report['cases'][0]['pixel_passed'])
  shutil.copy2(ROOT/'reference/baselines'/(cid+'.png'),actual/(cid+'.png'))
  data=json.loads((actual/(cid+'.json')).read_text());data['selectors']['.review-footer'][0]['rect']['height']+=8
  (actual/(cid+'.json')).write_text(json.dumps(data));result=compare('geometry-drift')
  report=json.loads((temp/'geometry-drift/comparison-report.json').read_text())
  check('Comparator rejects geometry drift even when pixels match',result.returncode==1 and report['cases'][0]['pixel_passed'] and not report['cases'][0]['geometry']['passed'])
  with Image.open(actual/(cid+'.png')) as original:original.crop((0,0,1500,1000)).save(actual/(cid+'.png'))
  result=compare('size-drift');report=json.loads((temp/'size-drift/comparison-report.json').read_text())
  check('Comparator rejects dimensions rather than rescaling',result.returncode==1 and 'Dimension mismatch' in report['cases'][0].get('error',''))
  result=run('capture_application.py',['--config',str(ROOT/'contracts/application-capture.example.json'),'--output',str(temp/'blocked'),'--acknowledge-test-environment'])
  check('Application runner refuses unmapped example before browser access',result.returncode==2 and 'not configured' in result.stderr)
  result=run('capture_application.py',['--config',str(ROOT/'contracts/application-capture.example.json'),'--output',str(temp/'unacknowledged')])
  check('Application runner requires test-environment acknowledgement',result.returncode==2 and 'acknowledge' in result.stderr)
  minimal=temp/'integrity';minimal.mkdir();(minimal/'asset.txt').write_text('original')
  (minimal/'MANIFEST.json').write_text(json.dumps({'files':[{'path':'asset.txt','sha256':hashlib.sha256(b'original').hexdigest()}]}))
  (minimal/'asset.txt').write_text('tampered');result=run('verify_package.py',['--root',str(minimal)])
  check('Integrity tool detects tampering',result.returncode==1 and 'Changed: asset.txt' in result.stdout)
 report={'target':'QA harness self-tests only, not application tests','passed':sum(x['passed']for x in checks),'total':len(checks),'tests':checks}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['target','passed','total']},indent=2));return 0 if report['passed']==report['total'] else 1
if __name__=='__main__':raise SystemExit(main())
