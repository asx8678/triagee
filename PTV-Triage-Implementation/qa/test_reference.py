#!/usr/bin/env python3
"""Run the supplied 61-check reference suite in a disposable copy, never in approved files."""
from __future__ import annotations
import argparse,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main()->int:
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--output',type=Path,default=ROOT/'qa/results/reference-interactions')
 p.add_argument('--browser',default=shutil.which('chromium') or shutil.which('chromium-browser'))
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='ptv-reference-') as td:
  temp=Path(td);(temp/'previews').mkdir()
  shutil.copy2(ROOT/'reference/approved/ptv-triage-prototype.html',temp/'ptv-triage-prototype.html')
  source=(ROOT/'reference/original-design/test_prototype.py').read_text()
  # Only the temporary runtime executable path is adapted; source and design remain unchanged.
  if a.browser:source=source.replace("executable_path=shutil.which('chromium')",'executable_path='+repr(a.browser))
  (temp/'test_prototype.py').write_text(source)
  result=subprocess.run([sys.executable,str(temp/'test_prototype.py')],capture_output=True,text=True,timeout=240)
  (a.output/'stdout.txt').write_text(result.stdout)
  (a.output/'stderr.txt').write_text(result.stderr)
  if (temp/'test-results.json').exists():shutil.copy2(temp/'test-results.json',a.output/'test-results.json')
  report={'target':'immutable standalone reference, not production application','exit_code':result.returncode,'browser_path':a.browser,'source_test':'reference/original-design/test_prototype.py','reference_modified':False}
  (a.output/'run-report.json').write_text(json.dumps(report,indent=2)+'\n')
  print(result.stdout,end='');print(result.stderr,end='',file=sys.stderr)
  return result.returncode
if __name__=='__main__':raise SystemExit(main())
