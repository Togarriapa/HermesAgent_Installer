import sys,os
sys.path.insert(0,'/usr/lib/hermes-installer/releases/cc81abffe3cbb1df447889bca269d1e6c0be77ea/lib/python')
from hermes_installer.authority.installer_release import InstalledRootReleaseVerifier
r=None
try:
    r=InstalledRootReleaseVerifier.verify_installed_release()
    r.verify_current()
    print('PI_INSTALLED_RELEASE_FULL_READONLY_PASS')
    print('candidate',r.release_commit)
    print('closure_sha256',r.closure_manifest_sha256)
    print('members',len(r.files),'euid',os.geteuid())
except Exception as e:
    print('PI_INSTALLED_RELEASE_FULL_READONLY_DENIED',type(e).__name__)
finally:
    if r is not None:r.close()
