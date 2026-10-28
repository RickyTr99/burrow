# Ids: the guest runs as root and can become another user.
import ctypes
import errno
import os
import shutil
import sys
import tempfile

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


def error_of(f):
    try:
        f()
    except OSError as e:
        return e.errno
    return 0


d = tempfile.mkdtemp(prefix="burrow-ids.")
os.chmod(d, 0o777)
ok(os.getuid() == 0 and os.geteuid() == 0 and os.getgid() == 0, "root")
with open(d + "/root-file", "w"):
    pass
ok(os.stat(d + "/root-file").st_uid == 0, "a new file is root's")
ok("Uid:\t0\t0\t0\t0\n" in open("/proc/%d/status" % os.getpid()).read(), "/proc/<pid>/status has root's uid")
ok(error_of(lambda: os.chown(d + "/root-file", 1000, 1000)) == 0, "chown")
ok(ctypes.CDLL(None, use_errno=True).prctl(8, 1, 0, 0, 0) == 0, "prctl(PR_SET_KEEPCAPS)")

r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    out = []

    def check(cond, what):
        out.append(("ok   " if cond else "FAIL ") + what)

    os.setgroups([1000, 24])
    os.setresgid(1000, 1000, 1000)
    os.setresuid(1000, 1000, 1000)
    check(os.getresuid() == (1000, 1000, 1000), "setresuid")
    check(os.getresgid() == (1000, 1000, 1000), "setresgid")
    check(sorted(os.getgroups()) == [24, 1000], "setgroups")
    with open(d + "/user-file", "w"):
        pass
    check(os.stat(d + "/user-file").st_uid == 1000, "a new file is the user's")
    status = open("/proc/self/status").read()
    check("Uid:\t1000\t1000\t1000\t1000\n" in status, "/proc/self/status has the user's uid")
    check("Gid:\t1000\t1000\t1000\t1000\n" in status, "/proc/self/status has the user's gid")
    check(error_of(lambda: os.setuid(0)) == errno.EPERM, "back to root: EPERM")
    check(error_of(lambda: os.chroot("/")) == errno.EPERM, "chroot as a user: EPERM")
    os.write(w, "\n".join(out).encode())
    os._exit(0)
os.close(w)
child = b""
while True:
    b = os.read(r, 4096)
    if not b:
        break
    child += b
os.waitpid(pid, 0)
for line in child.decode().splitlines():
    ok(line.startswith("ok"), "child: " + line[5:])

# The saved set-uid: a set-uid program is allowed back to its owner
pid = os.fork()
if pid == 0:
    os.setresuid(1000, 1000, 0)
    os.setuid(0)
    os._exit(0 if os.getresuid() == (1000, 0, 0) else 1)
ok(os.waitpid(pid, 0)[1] == 0, "setresuid with a saved 0, then setuid(0)")

shutil.rmtree(d)
sys.exit(1 if fails else 0)
