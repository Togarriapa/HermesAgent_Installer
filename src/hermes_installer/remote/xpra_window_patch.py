"""Apply the pinned Xpra allowlist patch before enabling the HTML5 bridge."""
from __future__ import annotations
import hashlib
from collections.abc import Iterable
PINNED_WINDOW_SOURCE_GIT_BLOB="a67b72eb2faef9fc53d218633a9ea7c979d0827b"
def _git_blob_id(source:str)->str:
 raw=source.encode("utf-8")
 return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def patch_can_send_window(method_source:str)->str:
 needle="""                    return v
        if self.window_enabled and self.system_tray:
"""
 replacement="""                    return v
            # Installer patch: filters are a security allowlist, unmatched denies.
            return False
        if self.window_enabled and self.system_tray:
"""
 if method_source.count(needle)!=1:raise ValueError("Xpra can_send_window source does not match pinned patch context")
 return method_source.replace(needle,replacement,1)
def apply_pinned_window_patch(source:str,allowed_classes:Iterable[str])->str:
 from re import fullmatch
 classes=tuple(sorted(set(allowed_classes)))
 if not classes or any(not isinstance(c,str) or not fullmatch(r"[A-Za-z0-9_.-]{1,128}",c) for c in classes):raise ValueError("invalid Hermes Desktop window class allowlist")
 if _git_blob_id(source)!=PINNED_WINDOW_SOURCE_GIT_BLOB:raise ValueError("Xpra window source differs from reviewed pinned revision")
 anchor="""        self.window_filters = window.window_filters
        self.readonly = server.readonly
"""
 replacement="""        # Rebuild filters from the installer-owned finite class allowlist.
        self.window_filters = [
            (self.uuid, get_window_filter("window", "class-instance", "=", value))
            for value in os.environ.get("HERMES_XPRA_ALLOWED_CLASSES", "").split(",")
            if value in {"""+", ".join(repr(c) for c in classes)+"""}
        ]
        if not self.window_filters:
            raise RuntimeError("Hermes Desktop window allowlist is empty")
        self.readonly = server.readonly
"""
 if source.count(anchor)!=1:raise ValueError("Xpra connection initialization differs from pinned patch context")
 result=source.replace(anchor,replacement,1)
 start=result.index("    def can_send_window(self, window) -> bool:")
 end=result.index("\n    ######################################################################",start)
 result=result[:start]+patch_can_send_window(result[start:end])+result[end:]
 return result
