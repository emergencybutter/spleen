# Spleen - An x86_64 emulator written in bash

Spleen is a x86_64 CPU emulator written in bash.

## Overview

Spleen is a bash script that loads an x86_64 OSX (Mach-O) or Linux (ELF) binary from disk and run the binary without executing native code on host machine.
Consequently, you should be able to run the provided example binary on other hosts that have bash installed, such as most of the linux distributions out there.

## Demo

Running `/bin/bash --version` inside Spleen (Bash emulating an x86_64 CPU running `/bin/bash` — takes **~21 minutes 39 seconds**):

```shell
$ time bash ./spleen.bash /bin/bash --version
GNU bash, version 5.2.15(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

real    21m39s
```

**What happens under the hood:**
1. **ELF & interpreter loading**: The host `bash` process runs `spleen.bash`, which reads `/bin/bash` (`ET_DYN` PIE ELF) via `hexdump`/`od` and maps its `PT_LOAD` segments into a Bash integer array (`memory`) at `0x555555554000`. Because `/bin/bash` has a `PT_INTERP` header, Spleen also loads the dynamic linker (`/lib64/ld-linux-x86-64.so.2`) at `0x7ffff7fc0000`.
2. **SysV stack & auxv setup**: Spleen builds the initial stack at `0x7fffffffe000` with `argc=2`, `argv=("/bin/bash", "--version")`, an empty `envp`, and the ELF auxiliary vector (`AT_PHDR`, `AT_ENTRY`, `AT_BASE`, etc.), then sets `rip` to the dynamic linker's entry point.
3. **Dynamic linking & libc init**: Stepping instruction by instruction in pure Bash (including integer ops, SSE2 string routines, and TLS via `%fs`), Spleen emulates the Linux syscalls (`openat`, `fstat`, `read`, `mmap`, `arch_prctl`, `brk`, `getrandom`, etc.) that `ld-linux` uses to locate, map, and relocate shared libraries (`libtinfo`, `libc`, etc.) and run `glibc` startup code.
4. **Execution & exit**: Control jumps to `/bin/bash`'s entry point, which parses `--version`, writes the version banner to file descriptor 1 via the emulated `write` syscall, and terminates via `exit_group`.

## Usage

* Run the provided examples with:

`` ` ./run-examples.sh` ``

* Rebuild the examples with the command below. The Mach-O examples (`examples/*.c`) are only built on an OSX machine,
  the Linux ELF examples (`examples/*.S`) are built with `cc -nostdlib -static -no-pie` on Linux
  (or with the cross compiler given in `LINUX_CC`):

`` ` ./gen-examples.sh` ``

* Run tests with:

`` ` ./run-tests.bash` ``

## Supported binary formats

The format is detected from the magic number of the binary.

* **Mach-O** (`0xfeedfacf`): 64 bit `MH_EXECUTE` OSX executables, entry point from `LC_MAIN`. Only `__TEXT` is loaded.
* **ELF** (`0x7f 'E' 'L' 'F'`): `ELFCLASS64`, little endian, `EM_X86_64` executables.
  * `ET_EXEC` binaries are loaded at their link addresses; `ET_DYN` (PIE / static-pie) binaries at the fixed base `0x555555554000`.
  * Every `PT_LOAD` segment is mapped at `load_base + p_vaddr` (`p_filesz` bytes copied from the file, zero filled up to `p_memsz`).
  * For binaries without `PT_INTERP` (such as `-static-pie` / `ET_DYN` images), the loader parses `PT_DYNAMIC` and applies `DT_RELR`, `DT_RELA` and `DT_JMPREL` relocations (`R_X86_64_RELATIVE`, `R_X86_64_64`, `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`, `R_X86_64_PC32`/`PLT32`, `R_X86_64_32`/`32S`, `R_X86_64_COPY`).
  * Dynamically linked binaries with a `PT_INTERP` program header are supported: the main executable is mapped at `0x555555554000` (if `ET_DYN`), the dynamic linker (e.g. `/lib64/ld-linux-x86-64.so.2`) is mapped at `0x7ffff7fc0000`, `AT_BASE` is set to the interpreter base while `AT_ENTRY`/`AT_PHDR` describe the main executable, and execution starts at the interpreter entry point so `_dl_start` relocates and links shared libraries at runtime.
  * The initial stack follows the SysV ABI (at `0x7fffffffe000`): `argc`, `argv` (the binary path and extra arguments given to `spleen.bash`),
    an empty `envp` and an auxiliary vector (`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_BASE`, `AT_ENTRY`, `AT_UID`/`AT_EUID`, `AT_GID`/`AT_EGID`, `AT_RANDOM`, `AT_EXECFN`).

The loader sets `GLOBAL_os_abi` to `macos` or `linux` so that the syscall emulation knows which kernel ABI to emulate.
`examples/hi-linux.S` is a static, libc free Linux "Hello World!" (`examples-bin/hi-linux`).

## Supported instructions

Spleen implements the x86_64 integer instruction set and SSE/SSE2 SIMD subset used by C compilers, `glibc` and Linux binaries:

* Arithmetic/logic: `add`, `or`, `adc`, `sbb`, `and`, `sub`, `xor`, `cmp` in all
  their encodings (`00`-`3D`, `80`/`81`/`83`), `test`, `inc`, `dec`, `neg`, `not`,
  `mul`, `imul` (1, 2 and 3 operands), `div`, `idiv` (including 128 bit dividends).
* Atomic & byte-order: `cmpxchg`, `xadd`, `xchg`, `bswap` (`lock` prefix accepted).
* Shifts and rotates: `shl`/`sal`, `shr`, `sar`, `rol`, `ror`, `rcl`, `rcr`, `shld`, `shrd`.
* Bit scan & manipulation: `bsf`, `bsr`, `tzcnt`, `lzcnt`, `popcnt`, `bt`, `bts`, `btr`, `btc` (register, immediate and signed-offset memory bitstrings).
* Data movement & strings: `mov` (all forms, including `movabs` immediate and `moffs`),
  `movzx`, `movsx`, `movsxd`, `lea`, `push`, `pop`, `pushfq`, `popfq`, `lahf`, `sahf`,
  `xlatb`, `cbw`/`cwde`/`cdqe`, `cwd`/`cdq`/`cqo`, `cmovcc`, `setcc`, and string
  operations `movs`, `stos`, `lods`, `cmps`, `scas` (with `rep`, `repe`/`repz`, `repne`/`repnz`).
* Control flow: `jmp` (rel8, rel32, indirect), `jcc` (rel8, rel32), `jrcxz`/`jecxz`,
  `loop`/`loope`/`loopne`, `call` (rel32, indirect), `ret`, `enter`, `leave`.
* SSE / SSE2 (`XMM0`-`XMM15`, 128-bit):
  * Moves: `movdqa`, `movdqu`, `movaps`/`movapd`, `movups`/`movupd`, `movntps`/`movntpd`,
    `movntdq`, `lddqu`, `movss`, `movsd`, `movd`, `movq`, `movlps`/`movlpd`, `movhps`/`movhpd`,
    `movlhps`, `movhlps`, `movddup`, `movsldup`, `movshdup`, `pinsrw`, `pextrw`.
  * Bitwise & shuffles: `pand`, `pandn`, `por`, `pxor`, `andps`/`pd`, `andnps`/`pd`,
    `orps`/`pd`, `xorps`/`pd`, `punpcklbw`/`lwd`/`ldq`/`lqdq`, `punpckhbw`/`hwd`/`hdq`/`hqdq`,
    `unpcklps`/`pd`, `unpckhps`/`pd`, `pshufd`, `pshuflw`, `pshufhw`, `shufps`/`shufpd`.
  * Shifts, compares, masks & packed integer math: `psrlw`/`d`/`q`, `psraw`/`d`,
    `psllw`/`d`/`q`, `psrldq`, `pslldq`, `pcmpeqb`/`w`/`d`, `pcmpgtb`/`w`/`d`,
    `pmovmskb`, `movmskps`/`pd`, `paddb`/`w`/`d`/`q`, `psubb`/`w`/`d`/`q`,
    `paddusb`, `psubusb`, `pminub`, `pmaxub`.
* System & misc: `syscall`, `cpuid` (baseline x86_64 + SSE2), `rdtsc`, `rdtscp`, `xgetbv`,
  `ldmxcsr`/`stmxcsr`, `lfence`/`mfence`/`sfence`/`clflush`, `rdfsbase`/`rdgsbase`/`wrfsbase`/`wrgsbase`,
  `nop` (including multi-byte `0f 1f` forms), `endbr64`, `ud2`, `hlt`, `int3`, `clc`, `stc`, `cmc`, `cld`, `std`.
* Flags: CF, PF, AF, ZF, SF, OF are computed (DF is honored by string instructions).
* Addressing: all ModRM/SIB forms, RIP-relative addressing, `%fs:`/`%gs:` TLS segment
  overrides (`GLOBAL_fs_base`/`GLOBAL_gs_base`), `0x67` 32-bit address-size override,
  REX prefixes, 8-bit registers (`AH`-`BH` without REX, `SPL`-`DIL` with REX), operand size prefix.

`run-tests.bash` contains unit tests for these instructions. For reference, here is
the example program that `spleen.bash` runs:

```shell
nohar@pro ~/projects/hate% objdump -d examples-bin/hi

examples-bin/hi:     file format mach-o-x86-64

Disassembly of section .text:

0000000100000f70 <_main>:
   100000f70:   55                      push   %rbp
   100000f71:   48 89 e5                mov    %rsp,%rbp
   100000f74:   48 8d 35 22 00 00 00    lea    0x22(%rip),%rsi        # 100000f9d <_g_msg>
   100000f7b:   b8 04 00 00 02          mov    $0x2000004,%eax
   100000f80:   bf 01 00 00 00          mov    $0x1,%edi
   100000f85:   ba 0d 00 00 00          mov    $0xd,%edx
   100000f8a:   0f 05                   syscall 
   100000f8c:   48 89 45 f8             mov    %rax,-0x8(%rbp)
   100000f90:   b8 01 00 00 02          mov    $0x2000001,%eax
   100000f95:   31 d2                   xor    %edx,%edx
   100000f97:   0f 05                   syscall 
   100000f99:   31 c0                   xor    %eax,%eax
   100000f9b:   5d                      pop    %rbp
   100000f9c:   c3                      retq
```

## System calls

The `syscall` instruction dispatches on `GLOBAL_os_abi` (`macos` by default, `linux` for Linux binaries; set by the binary loader).

* macOS: `write` (0x2000004) and `exit` (0x2000001).
* Linux x86_64 (number in `rax`, arguments in `rdi rsi rdx r10 r8 r9`, result or negative errno in `rax`, `rcx`/`r11` clobbered):
  `read` (stdin on fd 0 and open read-only host files on fd >= 3), `pread64`, `write`/`writev` (fd 1 and 2), `open`/`openat` (read-only host files), `close`, `stat`/`fstat`/`lstat`/`newfstatat`, `lseek`, `access`/`faccessat`/`faccessat2`, `fcntl`, `dup`, `getcwd`, `readlink`/`readlinkat`, `brk` (emulated program break starting at `GLOBAL_linux_brk_start`), `mmap` (anonymous and read-only file-backed mappings), `munmap`/`mprotect` (no-ops), `ioctl` (`-ENOTTY`), `rt_sigaction`/`rt_sigprocmask` (no-ops), `getrlimit`/`prlimit64`, `getpid`, `gettid`, `getppid`, `getpgrp`, `getuid`, `getgid`, `geteuid`, `getegid`, `getresuid`, `getresgid`, `uname`, `arch_prctl` (FS/GS base is only stored), `futex`, `set_tid_address`, `set_robust_list`, `getrandom`, `rseq` (`-ENOSYS`), `clock_gettime`, `gettimeofday`, `time`, `exit`, `exit_group`.
  Unimplemented Linux syscalls return `-ENOSYS` (visible with `enable_debug_messages=true`), since libc start-up code probes optional syscalls.

## Technical notes

* `libx86_64.bash` uses `hexdump` to read the binary and transform it in something bash can load. Bash cannot natively deal with binary files that may have zeros in them. When `hexdump` is not installed, a small shim falls back to POSIX `od`. Apart from that, I don't call external binaries for anything, everything is bash.
* The RAM is emulated as an array of bytes, which in bash is an array if `integers` which are actually 64 bits, at least on my machine. `` `declare -ra memory` ``.
* `spleen.bash` uses dynamic scoping. meaning subfunction can alter the local variables of the parent (calling) functions.

## FAQ

### Why?

Là, tout n’est qu’ordre et beauté, 
Luxe, calme et volupté.

### Ok, seriouly though, why?

I came across a [awk-jvm](https://github.com/rethab/awk-jvm), a jvm implemented in awk. I chuckled and thought that this was the most useless thing ever made. Unfortunately, I then figured that I could probably write something even more useless. ```can + shouldn't = must```.

### Is everything ok?

I'm well thanks.

### Which bash version do I need?

Bash 3 or later (the script checks and refuses to run otherwise). I tested with bash 3 and 5.

### What else do I need?

Just bash and either `hexdump` or `od` to read the binary. `hexdump` is used when available; on systems without it (e.g. minimal Debian images where it lives in `bsdextrautils`), spleen falls back to `od`, which is part of POSIX coreutils and present pretty much everywhere.

### Why are there binaries in your git repository?

The emulator does not support every instruction, and building the Mach-O example requires a mac. It's fairly possible that a simple compiler change (or even some compiler options) would generate an unsupported binary. The provided binaries (`examples-bin/hi` for OSX, `examples-bin/hi-linux` for Linux) have been tested to work. You can validate that they correspond to their namesake source files (`examples/hi.c`, `examples/hi-linux.S`) by running `objdump -d` on them and reading the assembly code.

### Why an OSX binary (Mach-O)?

I was on a mac when I had this terrible idea. Linux ELF binaries are now supported as well, including static, static-pie and dynamically linked ones (spleen loads `ld-linux` and lets it do the linking).

### Can it run real programs?

Somewhat. The integer instruction set, the SSE/SSE2 subset that compilers and `glibc` use, and enough Linux syscalls to get through libc start-up and read files are implemented. No threads, signals, writable files or networking, though. And it's bash, so expect it to be slow. Very slow.

### Will you support more instructions, CPUs, binary formats?

I said "probably not" last time, and then added ELF, dynamic linking and SSE2. So: probably not; but who knows? I've seen weirder things on the internet.
