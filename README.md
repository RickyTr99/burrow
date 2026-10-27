# Burrow

Burrow runs the programs of a Linux rootfs (Debian, Arch, ...) as an
unprivileged user, without root, user namespaces or ptrace. It was written for
[DroidNux](https://github.com/RickyTr99/droidnux), which runs a KDE Plasma
desktop on Android this way, and is usable wherever proot is: Android apps,
Termux, locked-down arm64 Linux machines.

Like proot, it shows the guest a rootfs as `/`, bindings of host directories
into it, and a fake root user. Unlike proot, it does not stop the process for
every syscall it emulates: a seccomp filter traps them with `SIGSYS`, and
Burrow's handler emulates them in the guest process itself.

## How it works

Burrow is one freestanding static binary (no libc), linked at a fixed address.

- **Launcher.** It installs a seccomp filter that traps the syscalls Burrow
  emulates (paths, ids, exec, a few socket and SysV IPC calls) with `SIGSYS`,
  unless they come from Burrow's own syscall gadget, then executes the guest
  command.
- **Loader.** Every guest `execve()` is emulated as an `execve()` of Burrow
  itself, with Burrow's state in an environment variable. Burrow maps the guest
  program and its ELF interpreter, fixes the auxiliary vector and jumps to it.
  Its image stays mapped: the `SIGSYS` handler lives there.
- **Handler.** It runs on the trapping thread, on a stack of its own. Guest
  paths are resolved in the rootfs (symlinks are guest paths, `..` stops at the
  root); when the kernel can resolve a path the same way, one
  `openat2(RESOLVE_NO_SYMLINKS)` does it.

A trap costs about 1.1 us on a Snapdragon 8 Gen 2 (0.4 us of it is the
kernel's signal delivery), where a ptrace stop costs tens of microseconds.
Starting Plasma (90,000 trapped syscalls) spends 2-3% of its CPU time in
Burrow's overhead.

## What is emulated

- Paths: every syscall that takes one, `/proc/<pid>/{exe,cwd,fd,maps,root}`
  with guest paths, Unix socket paths (`bind`, `connect`, `sendto`, `sendmsg`,
  `getsockname`, `getpeername`), `chroot`.
- Ids: proot's fake_id0. The guest starts as root, `setuid()` and friends,
  supplementary groups and `SO_PEERCRED` work, and files owned by the real user
  show as the saved set-user-ID's: root's until a program drops its ids. Root
  gets read and write access to the real user's files whatever their mode.
- Hard links as symlinks, in proot's link2symlink format (rootfses written by
  proot keep working), where the host refuses them (Android).
- SysV shared memory, semaphores and message queues, as files in the rootfs's
  `/tmp/.burrow-ipc` (`fakeroot-sysv` works).
- On Android: the files of `/proc` SELinux refuses to apps, made up
  (`/proc/version`, `/proc/stat`, `/proc/uptime`...); the guest's nameserver
  127.0.0.53 sent to a DNS proxy of the app (`-d`); `DRM_IOCTL_VERSION` on the
  KGSL device.
- Go programs (goroutine stacks, async preemption) and programs with their own
  seccomp filters or `SIGSYS` handlers (Firefox, Chromium, Electron apps).

## Requirements

- arm64 (aarch64) only.
- Linux 5.10 or later (`openat2`, `faccessat2`); on Android, a device with such
  a kernel.

## Build

```sh
make                                   # clang and lld
make CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
```

On Android the binary must be in a directory the app may execute from: its
native library directory, so DroidNux ships it as `libburrow.so`.

## Use

```sh
burrow -r ROOTFS [-b HOST[:GUEST]]... [-w GUEST_DIR] [-d DNS_PORT] [-s STATS_FILE] [--] PROGRAM [ARG]...
```

- `-r ROOTFS`: the rootfs directory.
- `-b HOST[:GUEST]`: a binding (`-b /dev -b /proc -b /sys` for most programs).
- `-w GUEST_DIR`: the working directory (`/` by default).
- `-d DNS_PORT`: send DNS queries to 127.0.0.53 to `127.0.0.1:DNS_PORT`.
- `-s STATS_FILE`: count the traps and the handler's time per syscall, for all
  the guest's processes; `tools/stats.py STATS_FILE` prints them.

Burrow stays the parent of the guest's process tree: when the program exits,
or Burrow gets `SIGTERM`, it kills what is left and exits with the program's
status.

```sh
burrow -r ~/debian -b /dev -b /proc -b /sys -w /root -- /usr/bin/env -i HOME=/root \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -l
```

## Not a sandbox

Burrow is not a security boundary, no more than proot. The syscall gadget is at
a fixed address and a guest program can call it, or map the rootfs's host
paths, to reach the host as the real user. Use it to run programs you would run
as that user anyway.

## Limits

- `SEM_UNDO` is not kept: a process killed holding a semaphore leaves it taken.
- `O_TMPFILE` is refused (`EOPNOTSUPP`): programs fall back to a named file.
- After `chroot()`, SysV shared memory and link2symlink's links of the old root
  are not seen from the new one.
- Chromium's own sandbox does not work (`--no-sandbox`); Electron apps do.

## Tests

```sh
make check ROOTFS=/path/to/rootfs      # perl and python3 in the rootfs
```

The tests run inside a guest (`tests/run.sh`): paths, ids, exec, sockets,
chroot, SysV IPC, and a Go program when `tests/go/burrowtest` is built
(`GOOS=linux GOARCH=arm64 go build -o burrowtest main.go` in `tests/go`). The
CI runs them on GitHub's arm64 runners with a Debian rootfs.

## License

GPL-3.0, see [LICENSE](LICENSE).
