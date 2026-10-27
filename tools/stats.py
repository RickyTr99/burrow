#!/usr/bin/env python3
"""Prints Burrow's per-syscall statistics: the file given with -s.

    tools/stats.py FILE [N]    # the N syscalls taking the most time (20)

"total" is the whole handler, stack switching included; "emulated" the
emulation alone, real syscalls included. The kernel's signal delivery and
return are in neither (about 0.4 us a trap on a Cortex-A715).
"""
import os
import re
import struct
import sys

SYSCALLS = 512
MAGIC = 0x31737473776F7262
STEPS = {500: "(path probe)", 501: "(path walk)", 502: "(direct open)"}


def names():
    header = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../src/burrow.h")
    found = {int(n): name for name, n in re.findall(r"NR_(\w+) = (\d+)", open(header).read())}
    found.update({61: "getdents64", 46: "ftruncate", 98: "futex"})
    found.update(STEPS)
    return found


data = open(sys.argv[1], "rb").read()
top = int(sys.argv[2]) if len(sys.argv) > 2 else 20
if len(data) < 16 + 3 * 8 * SYSCALLS or struct.unpack_from("<Q", data)[0] != MAGIC:
    sys.exit("no statistics in " + sys.argv[1])
frequency = struct.unpack_from("<Q", data, 8)[0]
count, total, emulated = (struct.unpack_from("<%dQ" % SYSCALLS, data, 16 + i * 8 * SYSCALLS) for i in range(3))
us = 1e6 / frequency
label = names()
traps = sum(count[:500])  # past 500: Burrow's own steps, inside the traps
print("%d traps, %.1f ms in the handler (%.1f ms emulating)" %
      (traps, sum(total[:500]) * us / 1000, sum(emulated[:500]) * us / 1000))
print("%-18s %10s %10s %9s %9s" % ("syscall", "traps", "total ms", "us/trap", "emul us"))
for i in sorted((i for i in range(SYSCALLS) if count[i]), key=lambda i: -total[i])[:top]:
    print("%-18s %10d %10.1f %9.2f %9.2f" % (label.get(i, str(i)), count[i], total[i] * us / 1000,
                                             total[i] * us / count[i], emulated[i] * us / count[i]))
