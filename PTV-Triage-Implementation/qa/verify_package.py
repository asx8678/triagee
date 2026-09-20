#!/usr/bin/env python3
"""Verify shipped file hashes and absence of distributed font binaries. Uses only the standard library."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main()->int:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args();root=a.root.resolve()
 manifest=root/'MANIFEST.json'
 if not manifest.exists():p.error('MANIFEST.json is missing')
 m=json.loads(manifest.read_text());errors=[]
 for row in m['files']:
  path=root/row['path']
  if root not in path.resolve().parents:errors.append('Unsafe manifest path: '+row['path']);continue
  if not path.is_file():errors.append('Missing: '+row['path']);continue
  if hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:errors.append('Changed: '+row['path'])
 forbidden={'.ttf','.otf','.woff','.woff2','.ttc','.dfont'}
 for path in root.rglob('*'):
  if path.is_file() and path.suffix.lower() in forbidden and '.venv' not in path.parts:errors.append('Font binary present: '+str(path.relative_to(root)))
 print(json.dumps({'files_checked':len(m['files']),'passed':not errors,'errors':errors},indent=2));return 1 if errors else 0
if __name__=='__main__':raise SystemExit(main())
