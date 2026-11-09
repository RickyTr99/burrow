#!/usr/bin/python3
# A stand-in x86 interpreter (make check's -x): prints its arguments and the
# file AT_EXECFD holds, for exec.py.
import ctypes
import os
import sys

fd = ctypes.CDLL(None).getauxval(2)  # AT_EXECFD
print("x86-interp", *sys.argv[1:], "exec_fd=" + os.readlink("/proc/self/fd/%d" % fd))
