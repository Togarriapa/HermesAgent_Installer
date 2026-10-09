#!/usr/bin/env python3
"""Validate planning coverage and frozen baseline integrity; never validate runtime readiness."""
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path

def load(path):return json.loads(path.read_text())
def check_coverage(base):
 data=load(base/'planning/traceability.json');items=load(base/'planning/component-contracts.json')
 source=base/'original-prompt.md' if (base/'original-prompt.md').exists() else base/'plans/2026-10-09-v1/original-prompt.md'
 raw=source.read_bytes();lines=raw.decode().splitlines()
 assert hashlib.sha256(raw).hexdigest()==data['source_sha256'],'Original prompt digest mismatch'
 req={x['id']:x for x in data['requirements']};tasks={x['id']:x for x in data['tasks']};ev={x['id']:x for x in data['evidence']}
 assert len(req)==len(data['requirements']) and len(tasks)==len(data['tasks']) and len(ev)==len(data['evidence']),'Duplicate identity'
 mapped={m['line']:m for m in data['source_line_mapping']}
 assert set(mapped)=={n for n,s in enumerate(lines,1) if s.strip()},'Source line dropped or invented'
 for m in mapped.values():assert m['requirement_ids'] and all(x in req for x in m['requirement_ids']),'Unmapped source context/obligation'
 specs='\n'.join(p.read_text() for p in (base/'openspec').rglob('spec.md'))
 tasktext='\n'.join(p.read_text() for p in (base/'openspec/changes').rglob('tasks.md'))
 for rid,r in req.items():
  assert 'Requirement: '+rid+' ' in specs,'Missing OpenSpec requirement '+rid
  assert r['task_id'] in tasks and r['test_id'] in ev,'Missing task/evidence '+rid
  assert rid in tasks[r['task_id']]['requirement_ids'] and rid in ev[r['test_id']]['requirement_ids'],'Broken trace link '+rid
  assert r['task_id'] in tasktext,'Missing tracked checkbox task '+r['task_id']
  assert r['verification_method'] and ev[r['test_id']]['assertion'],'Missing substantive verification '+rid
 itemids={i['id'] for i in items}
 for r in req.values():
  if r.get('component_id'):assert r['component_id'] in itemids,'Requested component omitted '+r['component_id']
 for item in items:
  assert item.get('class') and item.get('component_type'),'Missing component type '+item['id']
  assert item['aliases'] and item['requirement_ids'] and item['task_ids'] and item['evidence_ids'],'Incomplete item '+item['id']
  assert all(x in req for x in item['requirement_ids']) and all(x in tasks for x in item['task_ids']) and all(x in ev for x in item['evidence_ids']),'Broken item links'
  if item['source_selection']=='pending-user-selection':assert item['status']=='pending-source' and not item['states']['enabled'],'Unselected source activated'
 assert len({i['id'] for i in items})==len(items),'Duplicate component identity'
 for name,aliases in [('ecc',['affaan-m/ECC','ecc']),('omniroute',['OmniRoute','omniroute']),('playwright-mcp',['playright','Playwright MCP'])]:
  item=next(i for i in items if i['id']==name);assert set(aliases)<=set(item['aliases']),'Alias dropped'
 assert len(data['acceptance'])==12 and {a['id'] for a in data['acceptance']}=={f'AC{n:02}' for n in range(1,13)},'Missing acceptance criterion'
 for a in data['acceptance']:
  assert a['text'] and a['source_line'] and a['requirement_ids'] and a['task_ids'] and a['evidence_ids'],'Unlinked acceptance '+a['id']
  assert lines[a['source_line']-1].startswith(str(int(a['id'][2:]))+'. '),'Wrong acceptance source line'
 additional=data.get('additional_sources',[])
 expected={r['source_file'] for r in req.values() if r.get('source_file')}
 assert {a['file'] for a in additional}==expected,'Missing direct-user addition source mapping'
 for a in additional:
  ap=base/a['file'];araw=ap.read_bytes();alines=araw.decode().splitlines()
  assert hashlib.sha256(araw).hexdigest()==a['sha256'],'Additional user source digest changed'
  amap={m['line']:m for m in a['source_line_mapping']}
  assert set(amap)=={n for n,l in enumerate(alines,1) if l.strip()},'Direct-user addition line dropped'
  for m in amap.values():assert m['requirement_ids'] and all(i in req for i in m['requirement_ids']),'Unmapped direct-user addition'
 added=data.get('additional_acceptance',[])
 if expected:
  assert {a['id'] for a in added}>={'AC13','AC14','AC15'},'Missing remote acceptance criterion'
  for a in added:
   assert a['text'] and a['requirement_ids'] and a['task_ids'] and a['evidence_ids'],'Incomplete added acceptance mapping'
   assert all(i in req for i in a['requirement_ids']) and all(i in tasks for i in a['task_ids']) and all(i in ev for i in a['evidence_ids']),'Broken added acceptance links'
 active=set();done=set()
 def visit(tid):
  assert tid in tasks,'Unknown task dependency '+tid
  assert tid not in active,'Task dependency cycle '+tid
  if tid in done:return
  active.add(tid)
  for dep in tasks[tid]['depends_on']:visit(dep)
  active.remove(tid);done.add(tid)
 for tid in tasks:visit(tid)
 return {'requirements':len(req),'tasks':len(tasks),'inventory_records':len(items),'source_lines':len(mapped),'acceptance_criteria':12,'additional_acceptance_criteria':len(added),'additional_source_lines':sum(len(a['source_line_mapping']) for a in additional)}

def check_integrity(baseline):
 manifest=load(baseline/'hashes.json')
 observed={str(p.relative_to(baseline)):hashlib.sha256(p.read_bytes()).hexdigest() for p in baseline.rglob('*') if p.is_file() and p != baseline/'hashes.json'}
 assert observed==manifest['files'],'Frozen baseline file set or digest changed'
 return len(observed)

def main():
 p=argparse.ArgumentParser();p.add_argument('--baseline',type=Path,default=Path('plans/2026-10-09-v1'));p.add_argument('--live',action='store_true');p.add_argument('--tag');args=p.parse_args()
 try:
  stats=check_coverage(Path('.') if args.live else args.baseline)
  if not args.live:stats['hashed_files']=check_integrity(args.baseline)
  if args.tag:
   subprocess.run(['git','rev-parse','--verify','refs/tags/'+args.tag],check=True,capture_output=True)
   subprocess.run(['git','diff','--exit-code','refs/tags/'+args.tag,'--',str(args.baseline)],check=True)
   tracked=subprocess.run(['git','ls-tree','-r','--name-only','refs/tags/'+args.tag,'--',str(args.baseline)],check=True,capture_output=True,text=True).stdout.splitlines()
   assert tracked,'Tag lacks baseline'
  print(json.dumps({'planning_coverage':'pass','runtime_acceptance':'not-established',**stats},indent=2));return 0
 except (AssertionError,KeyError,ValueError,OSError,subprocess.CalledProcessError) as e:
  print('Planning validation failed: '+str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
