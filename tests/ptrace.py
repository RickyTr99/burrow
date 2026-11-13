# Debuggers: the guest program's auxiliary vector in /proc, PTRACE_TRACEME.
import ctypes
import os
import shutil
import signal
import struct
import subprocess
import time

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


AT_PHDR, AT_BASE, AT_ENTRY = 3, 7, 9


def auxv(pid):
    data = open("/proc/%s/auxv" % pid, "rb").read()
    pairs = struct.unpack("<%dQ" % (len(data) // 8), data)
    return dict(zip(pairs[0::2], pairs[1::2]))


def mapped_from(pid, address):
    for line in open("/proc/%s/maps" % pid):
        fields = line.split()
        start, end = (int(a, 16) for a in fields[0].split("-"))
        if start <= address < end:
            return fields[5] if len(fields) > 5 else ""
    return None


def program_of(pid):
    return os.path.realpath(os.readlink("/proc/%s/exe" % pid))


a = auxv("self")
ok(a.get(AT_BASE, 0) != 0, "/proc/self/auxv: the interpreter's base")
ok(mapped_from("self", a.get(AT_PHDR, 0)) == program_of("self"), "its program headers in the program")
ok(mapped_from("self", a.get(AT_ENTRY, 0)) == program_of("self"), "its entry in the program")

child = subprocess.Popen(["sleep", "5"])
time.sleep(0.5)
a = auxv(child.pid)
ok(mapped_from(child.pid, a.get(AT_ENTRY, 0)) == program_of(child.pid), "another process's auxv")
child.kill()
child.wait()

# A fork() child that stops itself after PTRACE_TRACEME (gdb's check of ptrace) is traced at once.
libc = ctypes.CDLL(None, use_errno=True)
pid = os.fork()
if pid == 0:
    libc.ptrace(0, 0, None, None)
    os.kill(os.getpid(), signal.SIGSTOP)
    os._exit(0)
_, status = os.waitpid(pid, os.WUNTRACED)
ok(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP, "PTRACE_TRACEME, then a stop")
os.kill(pid, signal.SIGKILL)
os.waitpid(pid, 0)

# gdb's run: its vfork() child's execve(), then a stop with the program loaded.
if shutil.which("gdb"):
    out = subprocess.run(
        ["gdb", "-nx", "-batch", "-ex", "handle SIGSYS nostop noprint pass", "-ex", "set startup-with-shell off",
         "-ex", "break opendir", "-ex", "run", "-ex", "info sharedlibrary", "-ex", "kill", "--args", "ls", "/"],
        capture_output=True, text=True, timeout=60).stdout
    ok("Breakpoint 1, " in out and "libc.so" in out, "gdb: run to a breakpoint in libc")
else:
    print("skip gdb: not installed")

exit(1 if fails else 0)
