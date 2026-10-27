# Paths: guest symlinks, "..", dirfds, the /proc links, hard links.
import errno
import os
import shutil
import sys
import tempfile
import threading

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


d = os.path.realpath(tempfile.mkdtemp(prefix="burrow-paths."))
f = d + "/f"
with open(f, "w") as out:
    out.write("data")

# Symlinks are guest paths
os.symlink(f, d + "/abs")
os.symlink("f", d + "/rel")
os.symlink("/etc/os-release", d + "/etc")
ok(open(d + "/abs").read() == "data", "absolute symlink")
ok(open(d + "/rel").read() == "data", "relative symlink")
ok(os.readlink(d + "/abs") == f, "readlink gives the guest path")
ok(open(d + "/etc").read().startswith(open("/etc/os-release").read()[:20]), "symlink to a rootfs file")
ok(os.path.realpath(d + "/abs") == f, "realpath")
ok(os.path.islink(d + "/abs") and os.stat(d + "/abs").st_ino == os.stat(f).st_ino, "lstat and stat")
ok(error_of(lambda: os.open(d + "/abs", os.O_RDONLY | os.O_NOFOLLOW)) == errno.ELOOP, "O_NOFOLLOW: ELOOP")
os.symlink(d + "/loop2", d + "/loop1")
os.symlink(d + "/loop1", d + "/loop2")
ok(error_of(lambda: os.stat(d + "/loop1")) == errno.ELOOP, "symlink loop: ELOOP")
ok(error_of(lambda: os.stat(d + "/missing")) == errno.ENOENT, "missing: ENOENT")
ok(error_of(lambda: os.stat(f + "/x")) == errno.ENOTDIR, "file as a directory: ENOTDIR")

# The root stays the root
ok(os.stat("/..").st_ino == os.stat("/").st_ino, "/.. is /")
ok("etc" in os.listdir("/../../.."), "/../../.. lists the rootfs")
ok(os.path.realpath(d + "/../../../../..") == "/", "realpath above the root")

# Directory fds and the working directory
fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
ok(os.read(os.open("f", os.O_RDONLY, dir_fd=fd), 4) == b"data", "openat on a dirfd")
ok(os.readlink("abs", dir_fd=fd) == f, "readlinkat on a dirfd")
os.mkdir(d + "/sub")
os.symlink(d + "/sub", d + "/sublink")
os.chdir(d + "/sublink")
ok(os.getcwd() == d + "/sub", "getcwd after chdir through a symlink")
ok(os.readlink("/proc/self/cwd") == d + "/sub", "/proc/self/cwd")
ok(open("../f").read() == "data", "relative path from the cwd")
os.chdir(d)

# /proc links
ok(os.readlink("/proc/self/exe") == os.path.realpath(sys.executable), "/proc/self/exe is a guest path")
ok(os.readlink("/proc/self/fd/%d" % fd) == d, "/proc/self/fd/N is a guest path")
ok(os.path.realpath(sys.executable) in open("/proc/self/maps").read(), "/proc/self/maps has guest paths")

# Changes
os.rename(f, d + "/g")
ok(not os.path.exists(f) and open(d + "/g").read() == "data", "rename")
with open(f, "w") as out:
    out.write("new")
os.replace(f, d + "/g")
ok(open(d + "/g").read() == "new", "rename over a file")
os.chmod(d + "/g", 0o640)
ok(os.stat(d + "/g").st_mode & 0o777 == 0o640, "chmod")
os.utime(d + "/g", (1000000000, 1000000000))
ok(os.stat(d + "/g").st_mtime == 1000000000, "utimensat")
os.truncate(d + "/g", 1)
ok(os.stat(d + "/g").st_size == 1, "truncate")
ok(os.statvfs(d).f_bsize > 0, "statfs")

# Hard links (link2symlink)
os.link(d + "/g", d + "/h")
ok(os.stat(d + "/h").st_nlink == 2 and os.stat(d + "/g").st_nlink == 2, "link: two links")
ok(open(d + "/h").read() == "n", "link: same content")
ok(sorted(n for n in os.listdir(d) if not n.startswith(".l2s.")) == sorted(["abs", "etc", "g", "h", "loop1", "loop2", "rel", "sub", "sublink"]), "listing")
os.unlink(d + "/g")
ok(open(d + "/h").read() == "n" and os.stat(d + "/h").st_nlink == 1, "unlink one link: the other stays")

# Many threads trapping at once
errors = []


def worker():
    try:
        for _ in range(500):
            os.stat(d + "/rel", follow_symlinks=False)
            os.readlink(d + "/rel")
            os.path.exists(d + "/h")
    except OSError as e:
        errors.append(e)


threads = [threading.Thread(target=worker) for _ in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
ok(not errors, "8 threads x 1500 path calls")

shutil.rmtree(d)
ok(not os.path.exists(d), "rmtree")
sys.exit(1 if fails else 0)
