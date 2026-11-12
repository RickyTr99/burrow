# chroot: a directory of the rootfs becomes the root.
import ctypes
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
pid = os.fork()
if pid == 0:
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (0, 0))
    os.chroot(d)
    os.chdir("/")
    os._exit(0)
ok(os.waitpid(pid, 0)[1] == 0, "chroot and chdir without a free descriptor (Chromium's sandbox helper)")
pid = os.fork()
if pid == 0:
    libc = ctypes.CDLL(None, use_errno=True)
    child = libc.syscall(220, 0x200 | 17, 0, 0, 0, 0)  # clone(CLONE_FS | SIGCHLD)
    if child == 0:
        os.chroot(d)
        os._exit(0)
    os.waitpid(child, 0)
    os._exit(0 if os.path.exists("/etc/marker") and not os.path.exists("/proc/self/exe") else 1)
ok(os.waitpid(pid, 0)[1] == 0, "a chroot() of a clone(CLONE_FS) child is its parent's too, without /proc/self/exe")
pid = os.fork()
if pid == 0:
    proc = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY)
    os.chroot(d)
    try:
        os.close(os.open("self/status", os.O_RDONLY, dir_fd=proc))
        good = os.stat("self/task", dir_fd=proc) is not None
    except OSError:
        good = False
    os._exit(0 if good else 1)
ok(os.waitpid(pid, 0)[1] == 0, "paths relative to a directory opened before chroot() (Chromium's /proc)")
pid = os.fork()
if pid == 0:
    os.chdir(os.path.dirname(d))
    os.chroot(d)
    try:
        os.getcwd()
        os._exit(1)
    except FileNotFoundError:
        os._exit(0)
ok(os.waitpid(pid, 0)[1] == 0, "a directory outside the new root has no path (getcwd ENOENT)")
ready_r, ready_w = os.pipe()
done_r, done_w = os.pipe()
pid = os.fork()
if pid == 0:
    os.chroot(d)
    inner = os.fork()  # its child, which did not call chroot() itself
    if inner == 0:
        os.write(ready_w, b"%d\n" % os.getpid())
        os.read(done_r, 1)
        os._exit(0)
    os.waitpid(inner, 0)
    os._exit(0)
inner = int(os.read(ready_r, 32))
ok(open("/proc/%d/root/etc/marker" % pid).read() == "inner", "/proc/<pid>/root of a chroot()ed process")
ok(open("/proc/%d/root/etc/marker" % inner).read() == "inner", "/proc/<pid>/root of its child")
ok(os.path.exists("/proc/%d/root/etc/hostname" % os.getpid()), "/proc/<pid>/root of this one")
os.write(done_w, b"x")
os.waitpid(pid, 0)
libc = ctypes.CDLL(None, use_errno=True)
libc.shmat.restype = ctypes.c_void_p
segment = libc.shmget(0, 4096, 0o1600)  # IPC_PRIVATE, IPC_CREAT
ctypes.memmove(libc.shmat(segment, None, 0), b"shared", 6)
pid = os.fork()
if pid == 0:
    os.chroot(d)
    at = libc.shmat(segment, None, 0)
    os._exit(0 if at not in (None, ctypes.c_void_p(-1).value) and ctypes.string_at(at, 6) == b"shared" else 1)
ok(os.waitpid(pid, 0)[1] == 0, "SysV shm of the first root after chroot")
libc.shmctl(segment, 0, None)  # IPC_RMID
shutil.rmtree(d)
sys.exit(1 if fails else 0)
