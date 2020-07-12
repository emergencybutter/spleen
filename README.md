# Spleen.bash

Spleen.bash is a x86_64 CPU emulator written in bash.

## Overview

spleen.bash is a bash script that loads an OSX binary (called Mach-O binaries) from disk and run the binary without resorting to executing native code on host machine.
Consequently you should be able to run the provided example binary on other hosts that have bash installed, such as most of the linux distributions out there.

## Example

``` shell
$ uname -a
Linux contrib-stretch 4.9.0-12-amd64 #1 SMP Debian 4.9.210-1 (2020-01-20) x86_64 GNU/Linux
$ file examples-bin/hi 
examples-bin/hi: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
$ bash ./spleen.bash examples-bin/hi
Hello World!
```

## Usage

* Run the provided examples with:

`` ` ./run-examples.sh` ``

* Rebuild the examples from C on an OSX machine with:

`` ` ./gen-examples.sh` ``

* Run tests with:

`` ` ./run-tests.bash` ``

## Supported instructions

Currently, spleen.bash supports only the instructions needed to run the single provide example.
For reference, here is the program that `spleen.bash` can run:

``` shell
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

## Technical notes

* `split.bash` uses hexdump to read the binary and transform it in something bash can load. Bash cannot natively deal with binary files that may have zeros in them. Apart from that, I don't call external binaries for anything, everything is bash.
* The RAM is emulated as an array of bytes, which in bash is an array if `integers` which are actually 64 bits, at least on my machine. `` `declare -ra memory` ``.
* `spleen.bash` uses dynamic scoping. meaning subfunction can alter the local variables of the parent (calling) functions.

## FAQ

### Why?

Là, tout n’est qu’ordre et beauté, 
Luxe, calme et volupté.

### Ok, seriouly though, why?

I came across a [awk-jvm](https://github.com/rethab/awk-jvm), a jvm implemented in awk. I first though this was the most useless thing ever. But then, I figure I could probably write something even more useless. So I had to do it.

### Is everything ok?

I'm well thanks.

### Which bash version do I need?

I tested with bash 3 and 5.

### Why is there a binary in your git repository?

The emulator supports a limited number of instructions. It's fairly possible that compiler change (or even some compiler options) generate an unsupported binary. The provided binary has been tested to work. You can validate that it corresponds to the namesake C file by running `objdump -d ./examples-bin/hi` and reading the assembly code.

### Why and OSX binary (Mach-O)?

I was on a mac when I had this terrible idea.

### Will you support more instructions, CPUs, binary formats?

Probably not; but who knows? I've seen weirder things on the internet.
