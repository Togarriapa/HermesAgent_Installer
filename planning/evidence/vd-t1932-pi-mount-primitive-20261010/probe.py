import datetime, errno, hashlib, json, os, pathlib, shutil, stat, subprocess, tempfile
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def mode(p): return oct(stat.S_IMODE(pathlib.Path(p).stat().st_mode))
stage=pathlib.Path(__file__).parent
ss=stage.lstat()
if not stat.S_ISDIR(ss.st_mode) or stat.S_ISLNK(ss.st_mode) or (ss.st_uid,ss.st_gid,stat.S_IMODE(ss.st_mode))!=(0,0,0o700): raise RuntimeError('UNTRUSTED_STAGE')
fix=stage/'fixture'; ev=stage/'evidence.json'
if fix.exists() or ev.exists(): raise RuntimeError('OWNED_PATH_EXISTS')
runroot=pathlib.Path(tempfile.mkdtemp(prefix='vd-t1932-',dir='/run'))
os.chmod(runroot,0o711)
target=runroot/'target'; target.mkdir(mode=0o711)
start=now()
src=fix/'source'; outside=fix/'outside'
fix.mkdir(mode=0o700); src.mkdir(mode=0o700); outside.mkdir(mode=0o700)
for i in range(5):
 p=src/f'f{i}'; p.write_bytes(('public-fixture-%d\n'%i).encode()); os.chmod(p,0o444)
(outside/'sentinel').write_text('foreign sentinel\n'); os.chmod(outside/'sentinel',0o444)
ssrc=src.stat(); starget=target.stat(); sr=runroot.stat()
sroot={'dev':ssrc.st_dev,'ino':ssrc.st_ino,'uid':ssrc.st_uid,'gid':ssrc.st_gid,'mode':mode(src)}
target_before={'dev':starget.st_dev,'ino':starget.st_ino,'uid':starget.st_uid,'gid':starget.st_gid,'mode':mode(target)}
runroot_before={'uid':sr.st_uid,'gid':sr.st_gid,'mode':mode(runroot)}
source_files=[{'name':f'f{i}','dev':(src/f'f{i}').stat().st_dev,'ino':(src/f'f{i}').stat().st_ino,'sha256':digest(src/f'f{i}'),'mode':mode(src/f'f{i}')} for i in range(5)]
code="""import pathlib,sys,hashlib
s=pathlib.Path(sys.argv[1]); o=pathlib.Path(sys.argv[2]); t=pathlib.Path(sys.argv[3])
ps=[t/('f%d'%i) for i in range(5)]
for i,p in enumerate(ps):
 q=p.read_bytes(); print('READ_OK',i,len(q),hashlib.sha256(q).hexdigest())
try: p=ps[0]; p.write_bytes(b'x'); raise AssertionError('NOBODY_WRITE_SUCCEEDED')
except OSError: print('NOBODY_WRITE_DENIED')
try: (t/'created').write_text('x'); raise AssertionError('NOBODY_CREATE_SUCCEEDED')
except OSError: print('NOBODY_CREATE_DENIED')
try: (s/'f0').read_bytes(); raise AssertionError('SOURCE_TRAVERSAL_SUCCEEDED')
except PermissionError: print('SOURCE_TRAVERSAL_DENIED')
try: (o/'sentinel').read_bytes(); raise AssertionError('FOREIGN_SENTINEL_SUCCEEDED')
except PermissionError: print('FOREIGN_SENTINEL_DENIED')
try: (t/'sentinel').read_bytes(); raise AssertionError('TARGET_SENTINEL_VISIBLE')
except FileNotFoundError: print('TARGET_SENTINEL_ABSENT')
"""
ns=stage/'namespace.py'
ns.write_text('''import os,sys,pathlib,subprocess,json,hashlib,stat,errno
s=pathlib.Path(sys.argv[1]); o=pathlib.Path(sys.argv[2]); t=pathlib.Path(sys.argv[3]); code=sys.argv[4]
def call(a): subprocess.run(a,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
call(["mount","--make-rprivate","/"])
call(["mount","-t","tmpfs","-o","size=1m,noexec,nosuid,nodev","tmpfs",str(t)])
os.chmod(t,0o711)
for i in range(5):
 p=t/("f%d"%i); p.touch(); call(["mount","--bind",str(s/("f%d"%i)),str(p)]); call(["mount","-o","remount,bind,ro,noexec,nosuid,nodev",str(s/("f%d"%i)),str(p)])
call(["mount","-o","remount,ro,noexec,nosuid,nodev",str(t)])
records=[]
for i in range(5):
 a=s/("f%d"%i); b=t/("f%d"%i); records.append({"name":a.name,"src_dev":a.stat().st_dev,"src_ino":a.stat().st_ino,"dst_dev":b.stat().st_dev,"dst_ino":b.stat().st_ino,"src_sha256":hashlib.sha256(a.read_bytes()).hexdigest(),"dst_sha256":hashlib.sha256(b.read_bytes()).hexdigest()})
mi=pathlib.Path("/proc/self/mountinfo").read_text().splitlines(); mounts=[x for x in mi if str(t) in x]
ss=s.stat(); st=t.stat(); print("SOURCE_ROOT",json.dumps({"dev":ss.st_dev,"ino":ss.st_ino,"uid":ss.st_uid,"gid":ss.st_gid,"mode":oct(stat.S_IMODE(ss.st_mode))})); print("TARGET_ROOT",json.dumps({"dev":st.st_dev,"ino":st.st_ino,"uid":st.st_uid,"gid":st.st_gid,"mode":oct(stat.S_IMODE(st.st_mode))})); assert (ss.st_dev,ss.st_ino)!=(st.st_dev,st.st_ino); print("ROOTS_DISTINCT True")
try: (t/"f0").write_bytes(b"root-write"); raise AssertionError("ROOT_WRITE_SUCCEEDED")
except OSError as e:
 if e.errno!=errno.EROFS: raise
 print("ROOT_WRITE_EROFS")
r=subprocess.run(["setpriv","--reuid=65534","--regid=65534","--clear-groups","/usr/bin/python3","-c",code,str(s),str(o),str(t)],capture_output=True,text=True,timeout=15)
print("NOBODY_EXIT",r.returncode); print(r.stdout,end=""); print(r.stderr,end="",file=sys.stderr)
print("TARGET_MOUNTS",json.dumps(mounts)); print("FILE_RECORDS",json.dumps(records))
raise SystemExit(r.returncode)
''')
os.chmod(ns,0o700)
cmd=['unshare','--mount','--fork','--propagation','private','/usr/bin/python3',str(ns),str(src),str(outside),str(target),code]
try:
 r=subprocess.run(cmd,capture_output=True,text=True,timeout=45); stdout=r.stdout; stderr=r.stderr; rc=r.returncode; timed=False
except subprocess.TimeoutExpired as e:
 stdout=e.stdout.decode(errors='replace') if isinstance(e.stdout,bytes) else (e.stdout or '')
 stderr=e.stderr.decode(errors='replace') if isinstance(e.stderr,bytes) else (e.stderr or '')
 rc=None; timed=True
end=now()
try:
 if target.is_symlink() or runroot.is_symlink() or any(target.iterdir()): raise RuntimeError('OWNED_TARGET_NOT_EMPTY_OR_SYMLINK')
 target.rmdir(); runroot.rmdir()
 shutil.rmtree(fix)
 cleanup='fixture_and_run_target_removed'
except Exception as e: cleanup='cleanup_error:'+type(e).__name__
record={'schema_version':1,'start_utc':start,'end_utc':end,'stage':str(stage),'uid':os.getuid(),'gid':os.getgid(),'source_root_before_namespace':sroot,'source_files_before_namespace':source_files,'run_parent_before_namespace':runroot_before,'target_placeholder_before_namespace':target_before,'argv':cmd,'exit_code':rc,'timed_out':timed,'stdout_bytes':len(stdout.encode()),'stdout_sha256':hashlib.sha256(stdout.encode()).hexdigest(),'stderr_bytes':len(stderr.encode()),'stderr_sha256':hashlib.sha256(stderr.encode()).hexdigest(),'stdout':stdout,'stderr':stderr,'cleanup':cleanup,'namespace_script_retained':ns.exists()}
ev.write_text(json.dumps(record,sort_keys=True,indent=2)+'\n'); os.chmod(ev,0o600)
print(json.dumps({'evidence':str(ev),'evidence_sha256':digest(ev),'exit_code':rc,'timed_out':timed,'cleanup':cleanup,'stdout':stdout,'stderr':stderr},sort_keys=True))
