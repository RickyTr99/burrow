# Burrow: one freestanding static binary linked at a fixed address, since its
# SIGSYS handler and syscall gadget stay mapped in every guest process.
#
#   make                                  # clang and lld, for aarch64
#   make CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
#   make check ROOTFS=/path/to/rootfs     # the tests (perl and python3 in it)

CC ?= clang
TARGET ?= aarch64-linux-gnu
OUT ?= burrow

CFLAGS := --target=$(TARGET) -O2 -Wall -Wextra \
	-ffreestanding -fno-stack-protector -U_FORTIFY_SOURCE \
	-fno-pic -fno-pie -fno-asynchronous-unwind-tables -mno-outline-atomics \
	-ffixed-x28
# x28: Go keeps its g there and its signal handlers trust it, also when a
# signal comes in the middle of Burrow's.
LDFLAGS := --target=$(TARGET) -fuse-ld=lld -static -nostdlib -no-pie \
	-Wl,--image-base=0x5600000000 -Wl,--build-id=none -Wl,-z,noexecstack

SOURCES := $(wildcard src/*.c) src/start.S

$(OUT): $(SOURCES) src/burrow.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

check: $(OUT)
	@test -n "$(ROOTFS)" || { echo "make check ROOTFS=..."; exit 1; }
	./$(OUT) -r $(ROOTFS) -b /dev -b /proc -b /sys -b $(CURDIR)/tests:/tmp/burrow-tests -w /root -- \
		/usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh /tmp/burrow-tests/run.sh

clean:
	rm -f $(OUT)

.PHONY: check clean
