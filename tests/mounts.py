# Mounts: bind mounts as bindings of the process (bwrap's sandboxes), unshare,
# the new mount API, an executable stack.
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


libc = ctypes.CDLL(None, use_errno=True)
MS_BIND, MS_REC, MS_REMOUNT, MS_RDONLY = 4096, 16384, 32, 1


def mount(source, target, fstype=None, flags=MS_BIND):
    r = libc.mount(source and source.encode(), target.encode(), fstype and fstype.encode(), flags, None)
    return 0 if r == 0 else ctypes.get_errno()


def in_child(f):
    """f() in a forked child; whether it returned true."""
    pid = os.fork()
    if pid == 0:
        try:
            good = f()
        except Exception as e:
            print("     " + repr(e))
            good = False
        os._exit(0 if good else 1)
    return os.waitpid(pid, 0)[1] == 0


d = os.path.realpath(tempfile.mkdtemp(prefix="burrow-mounts."))
os.makedirs(d + "/src/sub")
with open(d + "/src/sub/file", "w") as out:
    out.write("bound")
os.symlink("/etc/debian_version", d + "/src/abs")  # a guest path, also through the binding
os.link(d + "/src/sub/file", d + "/src/hard")  # link2symlink's on Android
os.makedirs(d + "/root/mnt")
os.makedirs(d + "/root/etc")
os.makedirs(d + "/empty")
release = open("/etc/debian_version").read()


def bind():
    if mount(d + "/src", d + "/empty") != 0:
        return False
    return (sorted(os.listdir(d + "/empty")) == sorted(os.listdir(d + "/src"))
            and open(d + "/empty/sub/file").read() == "bound" and open(d + "/empty/abs").read() == release
            and open(d + "/empty/hard").read() == "bound")


ok(in_child(bind), "bind mount, its guest symlinks and hard links")
ok(os.listdir(d + "/empty") == [], "the parent has no such binding")


def unmount():
    return mount(d + "/src", d + "/empty") == 0 and libc.umount2((d + "/empty").encode(), 0) == 0 \
        and os.listdir(d + "/empty") == []


ok(in_child(unmount), "umount2 drops the binding")


def child_sees():
    if mount(d + "/src", d + "/empty") != 0:
        return False
    pid = os.fork()
    if pid == 0:
        os.execv("/bin/sh", ["sh", "-c", "test \"$(cat %s/empty/sub/file)\" = bound" % d])
    return os.waitpid(pid, 0)[1] == 0


ok(in_child(child_sees), "children and exec keep the binding")


def sandbox():
    """bwrap's way: binds into a new root, then chroot."""
    if mount(d + "/src", d + "/root/mnt") or mount("/etc", d + "/root/etc") or mount("tmpfs", d, "tmpfs", 0):
        return False
    if mount(None, d + "/root/etc", None, MS_REMOUNT | MS_BIND | MS_RDONLY):
        return False
    os.chroot(d + "/root")
    os.chdir("/")
    return (sorted(os.listdir("/")) == ["etc", "mnt"] and open("/mnt/sub/file").read() == "bound"
            and open("/mnt/abs").read() == release and open("/mnt/hard").read() == "bound"
            and os.path.realpath("/mnt/sub/file") == "/mnt/sub/file")


ok(in_child(sandbox), "bindings into a new root, then chroot")


def as_user(unshare):
    def f():
        os.setgid(1000)
        os.setuid(1000)
        if unshare:
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
        return mount(d + "/src", d + "/empty") == (0 if unshare else errno.EPERM)
    return f


if os.getuid() == 0:
    ok(in_child(as_user(False)), "a user may not mount")
    ok(in_child(as_user(True)), "a user may in a namespace of its own")

syscall = libc.syscall
syscall.restype = ctypes.c_long
ctypes.set_errno(0)
r = syscall(428, -100, b"/", 0)  # open_tree(AT_FDCWD, "/", 0)
ok(r == -1 and ctypes.get_errno() == errno.ENOSYS, "open_tree is ENOSYS")
how = (ctypes.c_uint64 * 3)(0, 0, 0x08)  # O_RDONLY, RESOLVE_BENEATH
ctypes.set_errno(0)
r = syscall(437, -100, b"etc", ctypes.byref(how), 24)
ok(r == -1 and ctypes.get_errno() == errno.ENOSYS, "openat2 with resolve flags is ENOSYS")

# ld.so's request for an executable stack succeeds (the stack stays as it is on Android).
page = next(int(line.split("-")[0], 16) for line in open("/proc/self/maps") if line.rstrip().endswith("[stack]"))
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
ok(libc.mprotect(page, os.sysconf("SC_PAGE_SIZE"), 0x01000007) == 0, "mprotect of an executable stack")

shutil.rmtree(d)
sys.exit(1 if fails else 0)
