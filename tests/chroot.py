# chroot: a directory of the rootfs becomes the root.
import os
import shutil
import sys
import tempfile

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


d = os.path.realpath(tempfile.mkdtemp(prefix="burrow-chroot."))
os.makedirs(d + "/etc")
with open(d + "/etc/marker", "w") as out:
    out.write("inner")
os.symlink("/etc/marker", d + "/link")
pid = os.fork()
if pid == 0:
    os.chroot(d)
    os.chdir("/")
    good = (sorted(os.listdir("/")) == ["etc", "link"] and open("/etc/marker").read() == "inner"
            and open("/link").read() == "inner" and os.listdir("/..") == os.listdir("/")
            and os.readlink("/link") == "/etc/marker")
    os._exit(0 if good else 1)
ok(os.waitpid(pid, 0)[1] == 0, "the new root, its symlinks and its ..")
ok(open("/etc/hostname").read() != "inner", "the parent keeps its root")
shutil.rmtree(d)
sys.exit(1 if fails else 0)
