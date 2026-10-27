# Exec: programs, scripts and symlinks to them, as the guest names them.
import errno
import os
import shutil
import subprocess
import sys
import tempfile

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


def run(*argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw).stdout


def error_of(f):
    try:
        f()
    except OSError as e:
        return e.errno
    return 0


d = os.path.realpath(tempfile.mkdtemp(prefix="burrow-exec."))
ok(run("/bin/echo", "hi") == "hi\n", "a program")
ok(run("echo", "hi") == "hi\n", "a program from PATH")
ok(run("readlink", "/proc/self/exe") == "/usr/bin/readlink\n", "its /proc/self/exe")
ok(run("cat", "/proc/self/comm") == "cat\n", "its name")
ok("BURROW" not in run("env"), "Burrow's state is not in the environment")

with open(d + "/script", "w") as out:
    out.write('#!/bin/sh\necho "$0 $1"\n')
os.chmod(d + "/script", 0o755)
ok(run(d + "/script", "arg") == d + "/script arg\n", "a script")
with open(d + "/script2", "w") as out:
    out.write("#!/usr/bin/env python3\nimport sys; print(sys.argv[1])\n")
os.chmod(d + "/script2", 0o755)
ok(run(d + "/script2", "py") == "py\n", "a script through env")
os.symlink("/bin/echo", d + "/echo")
ok(run(d + "/echo", "link") == "link\n", "a symlink to a program")
ok(run("./script", "rel", cwd=d) == "./script rel\n", "a relative path")
ok(run("sh", "-c", 'echo "$0"', "name") == "name\n", "argv[0]")

with open(d + "/plain", "w") as out:
    out.write("#!/bin/sh\n")
ok(error_of(lambda: subprocess.run([d + "/plain"])) == errno.EACCES, "not executable: EACCES")
ok(error_of(lambda: subprocess.run([d + "/missing"])) == errno.ENOENT, "missing: ENOENT")
with open(d + "/junk", "w") as out:
    out.write("junk")
os.chmod(d + "/junk", 0o755)
ok(error_of(lambda: os.execv(d + "/junk", ["junk"])) == errno.ENOEXEC, "not a program: ENOEXEC")

pid = os.fork()
if pid == 0:
    os.execve("/bin/sh", ["sh", "-c", 'exit "$CODE"'], {"CODE": "7"})
ok(os.waitpid(pid, 0)[1] >> 8 == 7, "execve with an environment")

r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    os.dup2(w, 1)
    os.execve(os.open("/bin/echo", os.O_RDONLY), ["echo", "fd"], {})
os.close(w)
ok(os.read(r, 100) == b"fd\n", "fexecve (execveat on an fd)")
os.waitpid(pid, 0)

# Deep process trees exec in turn
ok(run("sh", "-c", "sh -c 'sh -c \"sh -c \\\"echo deep\\\"\"'") == "deep\n", "nested shells")

shutil.rmtree(d)
sys.exit(1 if fails else 0)
