#!/bin/bash

mkdir -p examples-bin

# Mach-O examples (C) can only be built on an OSX machine.
if [[ "$(uname -s)" = Darwin ]]; then
	for i in examples/*.c ; do
		cc -o examples-bin/$(basename "${i%%.c}") "${i}"
	done
else
	echo "Not on OSX: skipping Mach-O examples." >&2
fi

# Linux ELF examples: static, no libc, non-PIE. Needs a Linux x86_64 (cross)
# toolchain; override with LINUX_CC=x86_64-linux-gnu-gcc for instance.
LINUX_CC="${LINUX_CC:-cc}"
if [[ "$(uname -s)" = Linux || "${LINUX_CC}" != cc ]]; then
	for i in examples/*.S ; do
		"${LINUX_CC}" -nostdlib -static -no-pie -Wl,--build-id=none \
			-o examples-bin/$(basename "${i%%.S}") "${i}"
	done
else
	echo "No Linux toolchain: skipping ELF examples (set LINUX_CC)." >&2
fi
