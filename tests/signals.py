# Signals: SIGSYS, which Burrow's traps need, never ends up blocked.
import ctypes
import os
import signal
import sys

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


libc = ctypes.CDLL(None, use_errno=True)
SIGSYS_BIT = 1 << (signal.SIGSYS - 1)
SIGUSR2_BIT = 1 << (signal.SIGUSR2 - 1)


class Sigaction(ctypes.Structure):  # glibc's struct sigaction on arm64
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_uint64 * 16), ("flags", ctypes.c_int),
                ("restorer", ctypes.c_void_p)]


HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)


@HANDLER
def put_in_frame(sig, info, uc):
    # uc_sigmask follows uc_flags, uc_link and uc_stack: what FEX's handler does.
    ctypes.c_uint64.from_address(uc + 40).value |= SIGSYS_BIT | SIGUSR2_BIT


def frame_mask():
    act = Sigaction(ctypes.cast(put_in_frame, ctypes.c_void_p), flags=4)  # SA_SIGINFO
    if libc.sigaction(signal.SIGUSR1, ctypes.byref(act), None) != 0:
        os._exit(2)
    os.kill(os.getpid(), signal.SIGUSR1)
    os.getuid()  # trapped: a blocked SIGSYS would kill
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    os._exit(0 if signal.SIGUSR2 in blocked and signal.SIGSYS not in blocked else 1)


pid = os.fork()
if pid == 0:
    frame_mask()
status = os.waitpid(pid, 0)[1]
ok(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
   "a mask with SIGSYS from a signal frame (FEX's handler) leaves SIGSYS unblocked, the rest blocked")
signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGSYS])
ok(signal.SIGSYS not in signal.pthread_sigmask(signal.SIG_BLOCK, []), "sigprocmask does not block SIGSYS")
sys.exit(1 if fails else 0)
