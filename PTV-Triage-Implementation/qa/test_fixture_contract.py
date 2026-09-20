#!/usr/bin/env python3
"""Independently recompute synthetic expected sets. This does not test any production backend."""
from __future__ import annotations
import argparse,copy,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def metrics(records,team='all',env='all'):
 def visible(s):return (team=='all' or s['team']==team) and (env=='all' or s['env']==env)
 def active(s):return s['observation'] not in {'not_observed','verified_remediated'}
 active_ids=set();decision_ids=set();priority_ids=set();unknown_ids=set()
 for r in records:
  scopes=[s for s in r['scopes'] if visible(s)]
  current=[s for s in scopes if active(s)]
  if current:
   active_ids.add(r['id'])
   if r['priority']==1:priority_ids.add(r['id'])
  if any(s['status'] in {'needs_review','investigating'} for s in scopes):decision_ids.add(r['id'])
  unknown_ids.update(s['id'] for s in current if s['exposure']=='Unknown')
 return {'active_cve_ids':sorted(active_ids),'decision_cve_ids':sorted(decision_ids),
    'priority_cve_ids':sorted(priority_ids),'unknown_exposure_scope_ids':sorted(unknown_ids)}
def main()->int:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'qa/results/fixture-contract.json');a=p.parse_args()
 fixture=json.loads((ROOT/'contracts/synthetic-fixture.json').read_text());expected=json.loads((ROOT/'contracts/fixture-expectations.json').read_text())
 results=[]
 def check(name,ok):results.append({'test':name,'passed':bool(ok)})
 rs=fixture['records'];check('Fixture is explicitly synthetic',fixture['synthetic'] is True)
 check('Fixture clock fixed',fixture['clock']=='2026-09-19T10:00:00.000Z')
 check('20unique advisory IDs',len(rs)==len({r['id'] for r in rs})==20)
 scopes=[s for r in rs for s in r['scopes']];check('Scope IDs are unique',len(scopes)==len({s['id'] for s in scopes}))
 for case in expected['cases']:
  got=metrics(rs,case['team'],case['environment'])
  for k,v in got.items():check(f'{case["team"]}/{case["environment"]}/{k}',v==case[k])
 base=metrics(rs);check('Default metric quantities',[len(v) for v in base.values()]==[18,12,3,10])
 # Model invariants on a COPY of the synthetic fixture only.
 changed=copy.deepcopy(rs);r=next(x for x in changed if x['id']=='DEMO-2026-001')
 next(s for s in r['scopes'] if s['id']=='s01')['status']='planned'
 check('Production-only sample plan leaves staging unresolved',next(s for s in r['scopes'] if s['id']=='s02')['status']=='needs_review')
 check('Production-only plan preserves active ID set',metrics(changed)['active_cve_ids']==base['active_cve_ids'])
 check('Staging keeps advisory in decision queue','DEMO-2026-001' in metrics(changed)['decision_cve_ids'])
 next(s for s in r['scopes'] if s['id']=='s01')['status']='accepted'
 check('Sample exception does not remove active CVE',metrics(changed)['active_cve_ids']==base['active_cve_ids'])
 all_ids={s['id'] for s in scopes}
 check('Event scopes reference known targets',all(set(ev.get('scope_ids',[]))<=all_ids for r in rs for ev in r['events']))
 report={'target':'synthetic fixture only; production semantic acceptance is separate','passed':sum(t['passed'] for t in results),'total':len(results),'tests':results}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['target','passed','total']},indent=2))
 return 0 if report['passed']==report['total'] else 1
if __name__=='__main__':raise SystemExit(main())
