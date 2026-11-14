#!/bin/bash

source ./libx86_64.bash


function test_set_get_register() {
	set_register 1 $((RAX)) 128
	test $(get_register 1 $((RAX))) = 128 || die "$(get_register 1 $((RAX))) is not 128"

	set_register 2 $((RBX)) 0xabcd
	set_register 1 $((RBX)) 0xef
	test $(get_register 2 $((RBX))) = $((0xabef)) ||
		die "%02x is not 0xabef" $(get_register 2 $((RBX)))
}

function test_set_get_memory() {
	set_memory 1 123456789 128
	test $(get_memory 1 123456789) = 128 || die "$(get_memory 1 123456789) is not 128"

	set_memory 2 123456789 0xabcd
	set_memory 1 123456789 0xef
	test $(get_memory 2 123456789) = $((0xabef)) ||
		die "%02x is not 0xabef" $(get_memory 2 123456789)

	set_memory 8 123456789 $((0x1234567abcdef01))
	set_memory 1 123456790 0xff
	test $(get_memory 8 123456789) = $((0x1234567abcdff01)) ||
		die "%02x is not 0x1234567abcdff01" $(get_memory 8 123456789)
}

function test_xor() {
	declare -i rip=1234
	declare -i rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 operand_size_prefix=0

	set_register $((WIDTH32)) $((RAX)) $((0xabababab))
	set_register $((WIDTH32)) $((RDX)) $((0xabcdef12))

	inst_binary_op $((0x31)) $((0xd2))
	(($(get_register $((WIDTH32)) $((RDX))) == 0)) ||
		die "RDX != 0 0x%x" $(get_register $((WIDTH64)) $((RDX)))

	inst_binary_op $((0x31)) $((0xc0))
	(($(get_register $((WIDTH32)) $((RAX))) == 0)) ||
		die "RAX != 0 0x%x" $(get_register $((WIDTH32)) $((RAX)))
}

### Linux syscall tests ###

declare TEST_tmpdir

function check_eq() {
	declare -r actual="$1" expected="$2" what="$3"
	[[ "${actual}" == "${expected}" ]] ||
		die "%s: got '%s', expected '%s'" "${what}" "${actual}" "${expected}"
}

# Places the bytes of a printf format string in emulated memory.
function put_bytes() {
	declare -i address="$1"
	declare -r format="$2"
	declare byte
	while read byte; do
		memory[address]=$((byte))
		((address++)) || :
	done < <(printf "${format}" | hexdump -v -e '/1 "%u\n"')
}

# linux_syscall nr [args...]: runs the syscall instruction handler with the
# Linux ABI. Leaves the result in rax.
function linux_syscall() {
	declare -ra regs=($((RAX)) $((RDI)) $((RSI)) $((RDX)) $((R10)) $((R8)) $((R9)))
	declare -i i
	for ((i = 0; i < 7; i++)); do
		set_register 8 $((regs[i])) $((${1:-0}))
		shift || :
	done
	inst_syscall
}

function rax() {
	echo $((registers[RAX]))
}

function test_linux_write() {
	GLOBAL_os_abi=linux
	declare -ri buf=$((0x5000))
	# NUL, newline, printf format characters and a backslash.
	put_bytes $((buf)) 'Hi\0\n%%s\\\xff'
	linux_syscall 1 1 $((buf)) 8 >"${TEST_tmpdir}/out"
	check_eq "$(rax)" 8 "write return value"
	printf 'Hi\0\n%%s\\\xff' >"${TEST_tmpdir}/expected"
	cmp -s "${TEST_tmpdir}/out" "${TEST_tmpdir}/expected" ||
		die "write output mismatch: $(hexdump -C "${TEST_tmpdir}/out")"

	linux_syscall 1 2 $((buf)) 2 2>"${TEST_tmpdir}/err"
	check_eq "$(cat "${TEST_tmpdir}/err")" "Hi" "write to stderr"

	linux_syscall 1 7 $((buf)) 2
	check_eq "$(rax)" -9 "write to bad fd"

	# writev with two iovecs: "Hi" and "%s"
	declare -ri iov=$((0x6000))
	set_memory 8 $((iov)) $((buf))
	set_memory 8 $((iov + 8)) 2
	set_memory 8 $((iov + 16)) $((buf + 4))
	set_memory 8 $((iov + 24)) 2
	linux_syscall 20 1 $((iov)) 2 >"${TEST_tmpdir}/out"
	check_eq "$(rax)" 4 "writev return value"
	check_eq "$(cat "${TEST_tmpdir}/out")" "Hi%s" "writev output"
}

function test_linux_read() {
	GLOBAL_os_abi=linux
	declare -ri buf=$((0x7000))
	printf 'a\0b\nrest' >"${TEST_tmpdir}/in"
	linux_syscall 0 0 $((buf)) 100 <"${TEST_tmpdir}/in"
	check_eq "$(rax)" 4 "read stops after newline"
	check_eq "$(get_memory 4 $((buf)))" $((0x0a620061)) "read bytes"

	linux_syscall 0 0 $((buf)) 2 <"${TEST_tmpdir}/in"
	check_eq "$(rax)" 2 "read honours count"

	linux_syscall 0 0 $((buf)) 10 </dev/null
	check_eq "$(rax)" 0 "read at end of file"

	linux_syscall 0 5 $((buf)) 10
	check_eq "$(rax)" -9 "read from bad fd"
}

function test_linux_memory() {
	GLOBAL_os_abi=linux
	linux_syscall 12 0
	declare -ri start=$(rax)
	((start > 0)) || die "brk(0) returned %d" $((start))
	linux_syscall 12 $((start + 0x2000))
	check_eq "$(rax)" $((start + 0x2000)) "brk grow"
	set_memory 1 $((start + 0x1000)) 0x42
	linux_syscall 12 $((start + 0x1000))
	check_eq "$(rax)" $((start + 0x1000)) "brk shrink"
	linux_syscall 12 $((start + 0x2000))
	check_eq "$(get_memory 1 $((start + 0x1000)))" 0 "brk regrown memory is zeroed"
	linux_syscall 12 $((start - 0x1000))
	check_eq "$(rax)" $((start + 0x2000)) "brk below start fails"

	# mmap(NULL, 100, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
	linux_syscall 9 0 100 3 $((0x22)) -1 0
	declare -ri map1=$(rax)
	((map1 > 0 && (map1 & 0xfff) == 0)) || die "bad mmap address %x" $((map1))
	linux_syscall 9 0 100 3 $((0x22)) -1 0
	check_eq "$(rax)" $((map1 + 0x1000)) "second mmap"
	linux_syscall 9 0 100 3 2 3 0
	check_eq "$(rax)" -19 "file mmap unsupported"
	linux_syscall 9 0 0 3 $((0x22)) -1 0
	check_eq "$(rax)" -22 "zero length mmap"
	linux_syscall 11 $((map1)) 100
	check_eq "$(rax)" 0 "munmap"
}

function test_linux_misc() {
	GLOBAL_os_abi=linux
	linux_syscall 39
	check_eq "$(rax)" $$ "getpid"
	linux_syscall 102
	check_eq "$(rax)" "${UID}" "getuid"
	linux_syscall 218 $((0x8000))
	check_eq "$(rax)" $$ "set_tid_address"
	linux_syscall 16 1 $((0x5401)) 0
	check_eq "$(rax)" -25 "ioctl"
	linux_syscall 424242
	check_eq "$(rax)" -38 "unknown syscall"

	# uname
	declare -ri uts=$((0x9000))
	linux_syscall 63 $((uts))
	check_eq "$(rax)" 0 "uname"
	print_memory_bytes $((uts)) $((65 * 6)) >"${TEST_tmpdir}/uts"
	check_eq "$(tr '\0' ' ' <"${TEST_tmpdir}/uts" | tr -s ' ')" \
		"Linux spleen 6.1.0-spleen #1 SMP bash x86_64 (none) " "uname fields"
	check_eq "$(get_memory 1 $((uts + 4 * 65)))" $((0x78)) "utsname.machine"

	# arch_prctl(ARCH_SET_FS) then ARCH_GET_FS
	linux_syscall 158 $((0x1002)) $((0x12345000))
	check_eq "$(rax)" 0 "arch_prctl set fs"
	check_eq "${GLOBAL_fs_base}" $((0x12345000)) "fs base"
	linux_syscall 158 $((0x1003)) $((0xa000))
	check_eq "$(get_memory 8 $((0xa000)))" $((0x12345000)) "arch_prctl get fs"

	linux_syscall 228 0 $((0xb000))
	check_eq "$(rax)" 0 "clock_gettime"
	(($(get_memory 8 $((0xb000))) > 1600000000)) || die "clock_gettime seconds"
	linux_syscall 201 0
	(($(rax) > 1600000000)) || die "time"
}

function test_linux_syscall_instruction() {
	GLOBAL_os_abi=linux
	# rcx and r11 are clobbered with the return address and rflags.
	declare -i rip=$((0x1000)) advance=2
	linux_syscall 39
	check_eq "$(get_register 8 $((RCX)))" $((0x1002)) "rcx after syscall"
	check_eq "$(get_register 8 $((R11)))" $((0x202)) "r11 after syscall"

	# Hand-placed program: syscall (write); mov $60, %eax; syscall (exit)
	declare -ri code=$((0x400000)) msg=$((0x400100))
	put_bytes $((code)) '\x0f\x05\xb8\x3c\x00\x00\x00\x0f\x05'
	put_bytes $((msg)) 'Hello\0Linux\n'
	set_register 8 $((RAX)) 1
	set_register 8 $((RDI)) 1
	set_register 8 $((RSI)) $((msg))
	set_register 8 $((RDX)) 12
	declare -i rc=0
	(
		GLOBAL_text_vmaddr=$((code))
		GLOBAL_entryoff=0
		run
	) >"${TEST_tmpdir}/out" || rc=$?
	check_eq "${rc}" 1 "exit code of emulated program"
	printf 'Hello\0Linux\n' >"${TEST_tmpdir}/expected"
	cmp -s "${TEST_tmpdir}/out" "${TEST_tmpdir}/expected" ||
		die "program output mismatch: $(hexdump -C "${TEST_tmpdir}/out")"

	# exit_group status is taken from rdi
	set_register 8 $((RAX)) 231
	set_register 8 $((RDI)) 300
	rc=0
	(inst_syscall) || rc=$?
	check_eq "${rc}" $((300 & 0xff)) "exit_group status"
}

function test_macos_syscall_dispatch() {
	GLOBAL_os_abi=macos
	declare -ri buf=$((0x5000))
	put_bytes $((buf)) 'mac'
	set_register 8 $((RAX)) $((0x2000004))
	set_register 8 $((RDI)) 1
	set_register 8 $((RSI)) $((buf))
	set_register 8 $((RDX)) 3
	check_eq "$(inst_syscall)" "mac" "macOS write"
}

# Loads examples-bin/hi-linux and checks memory, entry point and stack.
function test_load_elf() {
	declare -r binary_file=examples-bin/hi-linux
	init
	load_elf_file "${binary_file}" arg1
	test "${GLOBAL_os_abi}" = linux || die "GLOBAL_os_abi is ${GLOBAL_os_abi}"
	((GLOBAL_text_vmaddr + GLOBAL_entryoff == 0x401000)) ||
		die "entry is 0x%x, not 0x401000" $((GLOBAL_text_vmaddr + GLOBAL_entryoff))
	# lea 0xff9(%rip),%rsi
	(($(get_memory 4 $((0x401000))) == 0xf9358d48)) ||
		die "unexpected code at entry: 0x%x" $(get_memory 4 $((0x401000)))
	(($(get_memory 4 $((0x401003))) == 0xff9)) ||
		die "unexpected lea displacement: 0x%x" $(get_memory 4 $((0x401003)))
	# "Hell" in .rodata
	(($(get_memory 4 $((0x402000))) == 0x6c6c6548)) ||
		die "unexpected .rodata: 0x%x" $(get_memory 4 $((0x402000)))
	# ELF magic of the first segment (headers)
	(($(get_memory 4 $((0x400000))) == 0x464c457f)) ||
		die "unexpected ELF header in memory"
	# Stack: 16 bytes aligned, argc, argv[0], argv[1], NULL, envp NULL, auxv.
	declare -ri sp=$((registers[RSP]))
	((sp % 16 == 0)) || die "RSP 0x%x is not 16 bytes aligned" $((sp))
	(($(get_memory 8 $((sp))) == 2)) || die "argc is not 2"
	declare -ri argv1=$(get_memory 8 $((sp + 16)))
	(($(get_memory 4 $((argv1))) == 0x31677261)) || die "argv[1] is not arg1"
	(($(get_memory 1 $((argv1 + 4))) == 0)) || die "argv[1] is not NUL terminated"
	(($(get_memory 8 $((sp + 24))) == 0)) || die "argv is not NULL terminated"
	(($(get_memory 8 $((sp + 32))) == 0)) || die "envp is not NULL terminated"
	(($(get_memory 8 $((sp + 40))) == AT_PHDR)) || die "auxv does not start with AT_PHDR"
	(($(get_memory 8 $((sp + 48))) == 0x400040)) || die "AT_PHDR is not 0x400040"
}

# Runs examples-bin/hi-linux until its first syscall and checks the registers.
function test_run_elf_until_syscall() {
	declare -r binary_file=examples-bin/hi-linux
	declare -r result=$(
		function inst_syscall() {
			printf '%x %x %x %x' $((registers[RAX])) $((registers[RDI])) \
				$((registers[RSI])) $((registers[RDX]))
			exit 0
		}
		init
		load_elf_file "${binary_file}"
		run
	)
	test "${result}" = "1 1 402000 d" ||
		die "unexpected registers at first syscall: ${result}"
}

# A binary with a PT_INTERP program header must be refused.
function test_refuse_dynamic_elf() {
	declare -r binary_file=$(mktemp)
	cp examples-bin/hi-linux "${binary_file}"
	# Turn the first program header (at e_phoff = 64) into PT_INTERP.
	printf '\003' | dd of="${binary_file}" bs=1 seek=64 conv=notrunc 2>/dev/null
	declare -r output=$( (init && load_elf_file "${binary_file}") 2>&1 || :)
	rm -f "${binary_file}"
	[[ "${output}" == *PT_INTERP* ]] ||
		die "dynamic ELF was not refused: ${output}"
}

function test_binary_format() {
	declare binary_file=examples-bin/hi
	test "$(binary_format)" = macho || die "examples-bin/hi is not detected as Mach-O"
	binary_file=examples-bin/hi-linux
	test "$(binary_format)" = elf || die "examples-bin/hi-linux is not detected as ELF"
}

### Helpers for instruction tests ###

declare -ri CODE=$((0x1000))
declare current_test=""

# Writes the given hex bytes at CODE and executes one instruction there.
# Example: exec_insn 48 01 d8  # add %rbx,%rax
function exec_insn() {
	declare -i a=$((CODE))
	declare byte
	for byte in "$@"; do
		memory[a]=$((16#${byte}))
		((a++)) || :
	done
	rip=$((CODE))
	step
}

# Sets registers: set_regs RAX 1 RBX 0x10 ...
function set_regs() {
	while (($# > 0)); do
		registers[$(($1))]=$(($2))
		shift 2
	done
}

function check() {
	declare -r what="$1"
	declare -ri actual="$2" expected="$3"
	((actual == expected)) ||
		die "%s: %s is 0x%x, expected 0x%x" "${current_test}" "${what}" $((actual)) $((expected))
}

function check_reg() {
	check "$(register_name $(($1)))" $((registers[$1])) "$2"
}

# check_flags "CF=1 ZF=0 SF=0 OF=0 PF=1"
function check_flags() {
	declare f
	for f in $1; do
		declare name="${f%%=*}"
		declare lname=$(echo "${name}" | tr '[:upper:]' '[:lower:]')
		check "${name}" $((flag_${lname})) "${f##*=}"
	done
}

function check_rip() {
	check "RIP" $((rip)) "$1"
}

### Instruction tests ###

function test_alu() {
	current_test=alu
	set_regs RAX 5 RBX 7
	exec_insn 48 01 d8 # add %rbx,%rax
	check_reg RAX 12
	check_flags "CF=0 ZF=0 SF=0 OF=0 PF=1"
	check_rip $((CODE + 3))

	# 32-bit ops zero the upper half; carry out of bit 31.
	set_regs RAX 0x1ffffffff
	exec_insn 83 c0 ff # add $-1,%eax
	check_reg RAX 0xfffffffe
	check_flags "CF=1 ZF=0 SF=1 OF=0"

	set_regs RAX 0x1280
	exec_insn 04 80 # add $0x80,%al
	check_reg RAX 0x1200
	check_flags "CF=1 ZF=1 OF=1 PF=1"

	set_regs RAX 0x7fffffffffffffff RBX 1
	exec_insn 48 01 d8 # add %rbx,%rax
	check_reg RAX $((1 << 63))
	check_flags "CF=0 SF=1 OF=1"

	set_regs RAX 1 RCX 2
	exec_insn 29 c8 # sub %ecx,%eax
	check_reg RAX 0xffffffff
	check_flags "CF=1 ZF=0 SF=1 OF=0 PF=1"

	set_regs RAX 5
	exec_insn 48 83 f8 05 # cmp $5,%rax
	check_reg RAX 5
	check_flags "CF=0 ZF=1 SF=0 OF=0"

	# Unsigned comparison on 64 bits: -1 > 1 so no borrow.
	set_regs RAX -1
	exec_insn 48 83 f8 05 # cmp $5,%rax
	check_flags "CF=0 ZF=0 SF=1 OF=0"

	set_regs RAX -1 RDX 0
	flag_cf=1
	exec_insn 48 11 d0 # adc %rdx,%rax
	check_reg RAX 0
	check_flags "CF=1 ZF=1"

	set_regs RCX 0
	flag_cf=1
	exec_insn 83 d9 00 # sbb $0,%ecx
	check_reg RCX 0xffffffff
	check_flags "CF=1 SF=1"

	set_regs RAX 0x12345678
	exec_insn 66 25 0f 0f # and $0xf0f,%ax
	check_reg RAX 0x12340608

	set_regs RAX 0x1100 RBX 0x22
	exec_insn 08 dc # or %bl,%ah
	check_reg RAX 0x3300

	set_regs R8 -1
	exec_insn 45 31 c0 # xor %r8d,%r8d
	check_reg R8 0
	check_flags "ZF=1 CF=0 OF=0 PF=1"
}

function test_test_inc_dec_neg_not() {
	current_test=test_inc_dec_neg_not
	set_regs RAX 0
	exec_insn 48 85 c0 # test %rax,%rax
	check_flags "ZF=1 SF=0 CF=0"

	set_regs RDI 0x1301
	exec_insn 40 f6 c7 01 # test $1,%dil
	check_flags "ZF=0"

	set_regs RAX 0x7fffffffffffffff
	flag_cf=1
	exec_insn 48 ff c0 # inc %rax
	check_reg RAX $((1 << 63))
	check_flags "CF=1 OF=1 SF=1"

	set_regs RCX 0x100
	flag_cf=0
	exec_insn fe c9 # dec %cl
	check_reg RCX 0x1ff
	check_flags "CF=0 SF=1 ZF=0"

	set_regs RAX 5
	exec_insn 48 f7 d8 # neg %rax
	check_reg RAX -5
	check_flags "CF=1 SF=1"

	set_regs RDX 0x0f0f
	exec_insn 48 f7 d2 # not %rdx
	check_reg RDX $((~0x0f0f))
}

function test_mul_div() {
	current_test=mul_div
	set_regs RAX -1 RCX -1
	exec_insn 48 f7 e1 # mul %rcx
	check_reg RAX 1
	check_reg RDX -2
	check_flags "CF=1 OF=1"

	set_regs RAX -1 RCX -1
	exec_insn 48 f7 e9 # imul %rcx
	check_reg RAX 1
	check_reg RDX 0
	check_flags "CF=0 OF=0"

	set_regs RAX 0x100000000 RCX 0x100000000
	exec_insn 48 0f af c1 # imul %rcx,%rax
	check_reg RAX 0
	check_flags "CF=1 OF=1"

	set_regs RDX 7
	exec_insn 48 6b c2 fd # imul $-3,%rdx,%rax
	check_reg RAX -21
	check_flags "CF=0"

	set_regs RDX 3
	exec_insn 48 69 c2 e8 03 00 00 # imul $1000,%rdx,%rax
	check_reg RAX 3000

	# 128-bit by 64-bit unsigned division.
	set_regs RDX 1 RAX 0 RCX 3
	exec_insn 48 f7 f1 # div %rcx
	check_reg RAX 0x5555555555555555
	check_reg RDX 1

	set_regs RDX -1 RAX -7 RCX 2
	exec_insn 48 f7 f9 # idiv %rcx
	check_reg RAX -3
	check_reg RDX -1

	set_regs RDX 0xffffffff RAX 0xfffffff9 RCX 2
	exec_insn f7 f9 # idiv %ecx
	check_reg RAX 0xfffffffd
	check_reg RDX 0xffffffff

	set_regs RAX 0x12340ff3 RCX 0x10
	exec_insn f6 f1 # div %cl
	check_reg RAX 0x123403ff
}

function test_addressing() {
	current_test=addressing
	set_memory 8 $((0x5000 + 0x10 + 4 * 0x20)) $((0x1122334455667788))
	set_regs R12 0x5000 R13 0x20
	exec_insn 4b 8b 44 ac 10 # mov 0x10(%r12,%r13,4),%rax
	check_reg RAX 0x1122334455667788

	set_memory 8 $((0x1000 * 0 + 0x1000 + 8 * 0x100)) 42
	set_regs RCX 0x100
	exec_insn 48 8b 04 cd 00 10 00 00 # mov 0x1000(,%rcx,8),%rax
	check_reg RAX 42

	set_memory 8 $((0x6000 - 8)) 43
	set_regs RBP 0x6000
	exec_insn 48 8b 45 f8 # mov -0x8(%rbp),%rax
	check_reg RAX 43

	set_memory 8 $((0x6008)) 44
	set_regs R13 0x6000
	exec_insn 49 8b 45 08 # mov 0x8(%r13),%rax
	check_reg RAX 44

	set_memory 8 $((0x6100)) 45
	set_regs R12 0x6100
	exec_insn 49 8b 04 24 # mov (%r12),%rax
	check_reg RAX 45

	set_memory 8 $((0x6200)) 46
	set_regs RSP 0x6200
	exec_insn 48 8b 04 24 # mov (%rsp),%rax
	check_reg RAX 46

	# RIP relative addressing is relative to the end of the instruction,
	# which includes the immediate.
	set_memory 4 $((CODE + 7 + 0x10)) 5
	exec_insn 83 3d 10 00 00 00 05 # cmpl $5,0x10(%rip)
	check_flags "ZF=1"
	check_rip $((CODE + 7))

	set_memory 4 $((CODE + 6 + 0x10)) 0x99
	exec_insn 8b 05 10 00 00 00 # mov 0x10(%rip),%eax
	check_reg RAX 0x99

	set_regs RAX 0x100 RBX 0x30
	exec_insn 48 8d 4c 58 10 # lea 0x10(%rax,%rbx,2),%rcx
	check_reg RCX 0x170
}

function test_byte_registers() {
	current_test=byte_registers
	set_regs RAX 0x1111 RSP 0x2233
	exec_insn 40 88 e0 # mov %spl,%al
	check_reg RAX 0x1133

	set_regs RAX 0xab12
	exec_insn 88 e0 # mov %ah,%al
	check_reg RAX 0xabab

	set_regs RAX 0x8000
	exec_insn 0f b6 c4 # movzbl %ah,%eax
	check_reg RAX 0x80

	set_regs RAX 0x80
	exec_insn 48 0f be c0 # movsbq %al,%rax
	check_reg RAX -128

	set_memory 2 $((0x7000)) 0xfffe
	set_regs RAX 0x7000 RCX -1
	exec_insn 0f bf 08 # movswl (%rax),%ecx
	check_reg RCX 0xfffffffe

	set_regs RAX 0x80000000
	exec_insn 48 63 d8 # movslq %eax,%rbx
	check_reg RBX $((-0x80000000))
}

function test_mov() {
	current_test=mov
	exec_insn 49 ba f0 de bc 9a 78 56 34 12 # movabs $0x123456789abcdef0,%r10
	check_reg R10 0x123456789abcdef0

	set_regs RDI -1
	exec_insn bf 01 00 00 00 # mov $1,%edi
	check_reg RDI 1

	set_regs RAX 0x7100
	exec_insn 48 c7 00 fe ff ff ff # movq $-2,(%rax)
	check "mem" $(get_memory 8 $((0x7100))) -2

	set_regs RAX 0x7100 RBX 3
	exec_insn c6 04 18 7f # movb $0x7f,(%rax,%rbx,1)
	check "mem" $(get_memory 1 $((0x7103))) 0x7f

	set_regs RAX 1 RBX 2
	exec_insn 48 93 # xchg %rax,%rbx
	check_reg RAX 2
	check_reg RBX 1

	set_memory 4 $((0x7200)) 5
	set_regs RAX 0x7200 RCX 9
	exec_insn 87 08 # xchg %ecx,(%rax)
	check_reg RCX 5
	check "mem" $(get_memory 4 $((0x7200))) 9

	set_regs RAX 0x80000000
	exec_insn 48 98 # cltq
	check_reg RAX $((-0x80000000))

	set_regs RAX -5 RDX 0
	exec_insn 48 99 # cqto
	check_reg RDX -1

	set_regs RAX 5 RDX -1
	exec_insn 99 # cltd
	check_reg RDX 0
}

function test_setcc_cmov() {
	current_test=setcc_cmov
	set_regs RAX 0x1234
	flag_zf=1
	exec_insn 0f 94 c0 # sete %al
	check_reg RAX 0x1201

	set_regs R9 0xff
	flag_sf=1 flag_of=0
	exec_insn 41 0f 9c c1 # setl %r9b
	check_reg R9 1

	set_regs RAX 1 RBX 2
	exec_insn 48 0f 4d c3 # cmovge %rbx,%rax (SF != OF: not taken)
	check_reg RAX 1

	# 32-bit cmov clears the upper half even when not taken.
	set_regs RAX 0x100000001 RBX 2
	flag_sf=0
	exec_insn 0f 4c c3 # cmovl %ebx,%eax
	check_reg RAX 1
}

function test_shifts() {
	current_test=shifts
	set_regs RAX 0x1800000000000001
	exec_insn 48 c1 e0 04 # shl $4,%rax
	check_reg RAX 0x8000000000000010
	check_flags "CF=1 SF=1"

	set_regs RAX 0x80000001
	exec_insn d1 e8 # shr %eax
	check_reg RAX 0x40000000
	check_flags "CF=1 OF=1"

	set_regs RDX $((1 << 63)) RCX 63
	exec_insn 48 d3 fa # sar %cl,%rdx
	check_reg RDX -1

	set_regs RAX 0x1234
	exec_insn 66 c1 c0 08 # rol $8,%ax
	check_reg RAX 0x3412

	set_regs RAX 1
	exec_insn d1 c8 # ror %eax
	check_reg RAX 0x80000000
	check_flags "CF=1"

	set_regs RAX $((1 << 63))
	flag_cf=1
	exec_insn 48 d1 d0 # rcl %rax
	check_reg RAX 1
	check_flags "CF=1"

	set_regs RBX 0x05
	flag_cf=0
	exec_insn c0 db 03 # rcr $3,%bl
	check_reg RBX 0x40
	check_flags "CF=1"

	set_regs RAX 0x0123456789abcdef RBX $((0xf << 60))
	exec_insn 48 0f a4 d8 04 # shld $4,%rbx,%rax
	check_reg RAX 0x123456789abcdeff

	set_regs RAX 0x12345678 RDX 0xabcd RCX 16
	exec_insn 0f ad d0 # shrd %cl,%edx,%eax
	check_reg RAX 0xabcd1234

	set_regs RAX 0x00f0
	exec_insn 48 0f bd c8 # bsr %rax,%rcx
	check_reg RCX 7
	exec_insn 48 0f bc c8 # bsf %rax,%rcx
	check_reg RCX 4
}

function test_control_flow() {
	current_test=control_flow
	set_regs RSP 0x8000
	exec_insn e8 0b 00 00 00 # call .+0x10
	check_rip $((CODE + 0x10))
	check_reg RSP $((0x8000 - 8))
	check "return address" $(get_memory 8 $((0x8000 - 8))) $((CODE + 5))

	exec_insn c3 # ret
	check_rip $((CODE + 5))
	check_reg RSP 0x8000

	set_regs RAX 0x4242
	exec_insn ff e0 # jmp *%rax
	check_rip 0x4242

	set_memory 8 $((0x7300)) 0x4343
	set_regs RAX 0x7300
	exec_insn ff 10 # call *(%rax)
	check_rip 0x4343
	check "return address" $(get_memory 8 $((0x8000 - 8))) $((CODE + 2))

	set_memory 8 $((0x7400)) 0x99
	set_regs RBP 0x7400 RSP 0x10
	exec_insn c9 # leave
	check_reg RBP 0x99
	check_reg RSP 0x7408

	flag_zf=0
	exec_insn 75 0e # jne .+0x10
	check_rip $((CODE + 0x10))
	flag_zf=1
	exec_insn 75 0e # jne .+0x10
	check_rip $((CODE + 2))

	flag_sf=1 flag_of=0
	exec_insn 0f 8c fa fe ff ff # jl .-0x100
	check_rip $((CODE - 0x100))

	exec_insn eb fe # jmp .
	check_rip $((CODE))
}

function test_stack() {
	current_test=stack
	set_regs RSP 0x8000
	exec_insn 68 78 56 34 12 # push $0x12345678
	exec_insn 6a ff # push $-1
	check_reg RSP $((0x8000 - 16))
	exec_insn 41 5f # pop %r15
	check_reg R15 -1
	exec_insn 41 5f # pop %r15
	check_reg R15 0x12345678
	check_reg RSP 0x8000
}

function test_nops_and_strings() {
	current_test=nops_and_strings
	exec_insn 66 0f 1f 04 00 # nopw (%rax,%rax,1)
	check_rip $((CODE + 5))
	exec_insn f3 0f 1e fa # endbr64
	check_rip $((CODE + 4))
	exec_insn 90 # nop
	check_rip $((CODE + 1))

	set_regs RAX 0x0102030405060708 RDI 0x9000 RCX 3
	exec_insn f3 48 ab # rep stos %rax,%es:(%rdi)
	check_reg RCX 0
	check_reg RDI $((0x9000 + 24))
	check "mem" $(get_memory 8 $((0x9010))) 0x0102030405060708

	set_regs RSI 0x9000 RDI 0x9100 RCX 5
	exec_insn f3 a4 # rep movsb
	check "mem" $(get_memory 4 $((0x9101))) 0x04050607
}

function check_xmm() {
	check "XMM$1.lo" $((xmm_lo[$1])) "$2"
	check "XMM$1.hi" $((xmm_hi[$1])) "$3"
}

function test_tls_and_addr32() {
	current_test=tls_and_addr32
	GLOBAL_fs_base=$((0x20000))
	GLOBAL_gs_base=$((0x30000))

	# 0x64 FS override BEFORE REX.W: mov %fs:0x28, %rax
	set_memory 8 $((0x20028)) $((0xdeadbeefcafebabe))
	set_regs RAX 0
	exec_insn 64 48 8b 04 25 28 00 00 00
	check_reg RAX $((0xdeadbeefcafebabe))

	# Store and read-modify-write on %fs:0x30 (seg_base must be added once, not twice)
	set_regs RAX 100
	exec_insn 64 48 89 04 25 30 00 00 00 # mov %rax, %fs:0x30
	check "fs:0x30" $(get_memory 8 $((0x20030))) 100
	exec_insn 64 48 83 04 25 30 00 00 00 05 # addq $5, %fs:0x30
	check "fs:0x30 after add" $(get_memory 8 $((0x20030))) 105

	# %gs override: mov %gs:0x10, %ebx
	set_memory 4 $((0x30010)) $((0x12345678))
	set_regs RBX -1
	exec_insn 65 8b 1c 25 10 00 00 00
	check_reg RBX $((0x12345678))

	# CRITICAL: lea ignores %fs: segment base!
	set_regs RAX -1
	exec_insn 64 48 8d 04 25 28 00 00 00 # lea %fs:0x28, %rax
	check_reg RAX $((0x28))

	# Legacy prefix AFTER REX cancels REX (32-bit load instead of 64-bit)
	set_memory 8 $((0x20028)) $((0x1122334455667788))
	set_regs RAX -1
	exec_insn 48 64 8b 04 25 28 00 00 00
	check_reg RAX $((0x55667788))

	# 0x67 addr32 prefix: masks effective address to 32 bits BEFORE adding seg_base
	set_memory 8 $((0x7500)) $((0xabcdef0123456789))
	set_regs RAX $((0x100007500))
	exec_insn 67 48 8b 00 # mov (%eax), %rax
	check_reg RAX $((0xabcdef0123456789))

	set_memory 4 $((0x20010)) $((0x55aa55aa))
	set_regs RAX $((0x200000010))
	exec_insn 67 64 8b 00 # mov %fs:(%eax), %eax
	check_reg RAX $((0x55aa55aa))

	# 0x67 lea (%eax), %rax
	set_regs RAX $((0x300001234))
	exec_insn 67 48 8d 00
	check_reg RAX $((0x1234))

	GLOBAL_fs_base=0
	GLOBAL_gs_base=0
}

function test_system_and_atomic() {
	current_test=system_and_atomic

	# cpuid leaf 0 ("GenuineIntel") + upper 32-bit zeroing
	set_regs RAX $((0x100000000)) RBX -1 RCX -1 RDX -1
	exec_insn 0f a2
	check_reg RAX 7
	check_reg RBX $((0x756e6547))
	check_reg RDX $((0x49656e69))
	check_reg RCX $((0x6c65746e))

	# cpuid leaf 1: SSE + SSE2 present, SSSE3/SSE4/AVX disabled
	set_regs RAX 1 RCX 0
	exec_insn 0f a2
	check_reg RDX $((0x078bfbfd))
	check "no AVX/SSE4" $((registers[RCX] & ~ (1 << 23))) 0

	# cpuid leaf 7: BMI/AVX2/AVX512 disabled
	set_regs RAX 7 RCX 0
	exec_insn 0f a2
	check_reg RBX 0
	check_reg RCX 0
	check_reg RDX 0

	# cpuid leaf 0x80000001: LM + NX + SYSCALL + LAHF_LM
	set_regs RAX $((0x80000001))
	exec_insn 0f a2
	check_reg RCX 1
	check_reg RDX $(((1 << 29) | (1 << 20) | (1 << 11)))

	# rdtsc / rdtscp / xgetbv
	GLOBAL_tsc=$((0x200000000))
	set_regs RAX -1 RDX -1
	exec_insn 0f 31 # rdtsc
	check_reg RAX 100
	check_reg RDX 2

	set_regs RAX -1 RDX -1 RCX -1
	exec_insn 0f 01 f9 # rdtscp
	check_reg RAX 200
	check_reg RDX 2
	check_reg RCX 0

	set_regs RAX -1 RDX -1 RCX 0
	exec_insn 0f 01 d0 # xgetbv
	check_reg RAX 3
	check_reg RDX 0

	# cmpxchg: equal case (memory)
	set_memory 8 $((0x9200)) 42
	set_regs RAX 42 RCX 99 RDI $((0x9200))
	exec_insn f0 48 0f b1 0f # lock cmpxchg %rcx, (%rdi)
	check_flags "ZF=1"
	check "cmpxchg mem eq" $(get_memory 8 $((0x9200))) 99
	check_reg RAX 42

	# cmpxchg: unequal 32-bit case zeroes upper 32 bits of RAX!
	set_memory 4 $((0x9200)) $((0x87654321))
	set_regs RAX $((0xdeadbeef00000001)) RCX 55 RDI $((0x9200))
	exec_insn 0f b1 0f # cmpxchg %ecx, (%rdi)
	check_flags "ZF=0"
	check_reg RAX $((0x87654321))
	check "cmpxchg mem neq" $(get_memory 4 $((0x9200))) $((0x87654321))

	# xadd: memory + register, and same-register xadd %rax, %rax
	set_memory 8 $((0x9200)) 10
	set_regs RCX 25 RDI $((0x9200))
	exec_insn f0 48 0f c1 0f # lock xadd %rcx, (%rdi)
	check_reg RCX 10
	check "xadd mem" $(get_memory 8 $((0x9200))) 35

	set_regs RAX 21
	exec_insn 48 0f c1 c0 # xadd %rax, %rax
	check_reg RAX 42

	# bswap 32-bit (zeroes upper 32 bits) and 64-bit
	set_regs RAX $((0xffeeddcc11223344))
	exec_insn 0f c8 # bswap %eax
	check_reg RAX $((0x44332211))

	set_regs R11 $((0x0102030405060708))
	exec_insn 49 0f cb # bswap %r11
	check_reg R11 $((0x0807060504030201))
}

function test_bit_ops() {
	current_test=bit_ops

	# Register bt / bts / btr / btc (64-bit)
	set_regs RAX 0 RCX 40
	exec_insn 48 0f ab c8 # bts %rcx, %rax
	check_flags "CF=0"
	check_reg RAX $((1 << 40))

	exec_insn 48 0f a3 c8 # bt %rcx, %rax
	check_flags "CF=1"

	exec_insn 48 0f bb c8 # btc %rcx, %rax
	check_flags "CF=1"
	check_reg RAX 0

	set_regs RAX $((1 << 63))
	exec_insn 48 0f ba f0 3f # btr $63, %rax
	check_flags "CF=1"
	check_reg RAX 0

	# Memory bt / bts / btr with positive AND negative bit offsets!
	# Base at 0x9310: bit -1 is bit 31 of dword at 0x930c; bit -33 is bit 31 of dword at 0x9308;
	# bit 35 is bit 3 of dword at 0x9314.
	set_memory 8 $((0x9308)) 0
	set_memory 8 $((0x9310)) 0
	set_regs RDI $((0x9310)) RCX -1
	exec_insn 0f ab 0f # bts %ecx, (%rdi)
	check_flags "CF=0"
	check "bts bit -1" $(get_memory 4 $((0x930c))) $((0x80000000))

	set_regs RCX -33
	exec_insn 0f ab 0f # bts %ecx, (%rdi)
	check "bts bit -33" $(get_memory 4 $((0x9308))) $((0x80000000))
	exec_insn 0f b3 0f # btr %ecx, (%rdi)
	check_flags "CF=1"
	check "btr bit -33" $(get_memory 4 $((0x9308))) 0

	set_regs RCX 35
	exec_insn 0f ab 0f # bts %ecx, (%rdi)
	check "bts bit 35" $(get_memory 4 $((0x9314))) 8

	# tzcnt / lzcnt / popcnt
	set_regs RAX 0 RCX 99
	exec_insn f3 48 0f bc c8 # tzcnt %rax, %rcx
	check_reg RCX 64
	check_flags "CF=1 ZF=0"

	set_regs RAX 0 RCX 99
	exec_insn f3 0f bd c8 # lzcnt %eax, %ecx
	check_reg RCX 32
	check_flags "CF=1 ZF=0"

	set_regs RAX $((0x8000000000000100))
	exec_insn f3 48 0f bc c8 # tzcnt %rax, %rcx
	check_reg RCX 8
	check_flags "CF=0 ZF=0"
	exec_insn f3 48 0f bd c8 # lzcnt %rax, %rcx
	check_reg RCX 0
	check_flags "CF=0 ZF=1"

	set_regs RAX 0
	flag_cf=1 flag_of=1 flag_sf=1 flag_pf=1
	exec_insn f3 48 0f b8 c8 # popcnt %rax, %rcx
	check_reg RCX 0
	check_flags "ZF=1 CF=0 OF=0 SF=0 PF=0"

	set_regs RAX -1
	exec_insn f3 48 0f b8 c8 # popcnt %rax, %rcx
	check_reg RCX 64
	check_flags "ZF=0 CF=0"
}

function test_strings_and_misc() {
	current_test=strings_and_misc
	flag_df=0

	# repne scasb (strlen pattern)
	put_bytes $((0x9400)) 'hello\0world'
	set_regs RAX 0 RDI $((0x9400)) RCX 16
	exec_insn f2 ae # repne scasb
	check_flags "ZF=1"
	check_reg RDI $((0x9406))
	check_reg RCX 10

	# repne scasb with RCX=0 does 0 iterations
	flag_zf=0
	set_regs RDI $((0x9400)) RCX 0
	exec_insn f2 ae
	check_reg RDI $((0x9400))
	check_flags "ZF=0"

	# repe cmpsb: mismatch at index 3 ('d' - 'x' < 0 -> CF=1, ZF=0)
	put_bytes $((0x9420)) 'abcdef'
	put_bytes $((0x9430)) 'abcxef'
	set_regs RSI $((0x9420)) RDI $((0x9430)) RCX 6
	exec_insn f3 a6 # repe cmpsb
	check_flags "ZF=0 CF=1"
	check_reg RSI $((0x9424))
	check_reg RDI $((0x9434))
	check_reg RCX 2

	# lodsb + %fs: lodsq
	GLOBAL_fs_base=$((0x9500))
	set_memory 8 $((0x9508)) $((0x0123456789abcdef))
	set_regs RSI 8 RAX 0
	exec_insn 64 48 ad # lodsq %fs:(%rsi), %rax
	check_reg RAX $((0x0123456789abcdef))
	check_reg RSI 16

	# mov moffs with %fs: override
	exec_insn 64 48 a3 20 00 00 00 00 00 00 00 # movabs %rax, %fs:0x20
	check "moffs store" $(get_memory 8 $((0x9520))) $((0x0123456789abcdef))
	set_regs RAX 0
	exec_insn 64 48 a1 20 00 00 00 00 00 00 00 # movabs %fs:0x20, %rax
	check_reg RAX $((0x0123456789abcdef))
	GLOBAL_fs_base=0

	# pushfq / popfq & lahf / sahf
	set_regs RSP $((0x8000))
	flag_cf=1 flag_zf=1 flag_sf=0 flag_of=1 flag_df=0
	exec_insn 9c # pushfq
	flag_cf=0 flag_zf=0 flag_of=0
	exec_insn 9d # popfq
	check_flags "CF=1 ZF=1 SF=0 OF=1"

	set_regs RAX 0
	flag_cf=1 flag_zf=0 flag_sf=1 flag_pf=1 flag_af=0
	exec_insn 9f # lahf
	flag_cf=0 flag_sf=0 flag_pf=0
	exec_insn 9e # sahf
	check_flags "CF=1 ZF=0 SF=1 PF=1"

	# stmxcsr / ldmxcsr / mfence
	exec_insn 0f ae 1c 25 40 94 00 00 # stmxcsr 0x9440
	check "mxcsr" $(get_memory 4 $((0x9440))) $((0x1f80))
	exec_insn 0f ae f0 # mfence
}

function test_sse2() {
	current_test=sse2

	# movdqa / movdqu / movups / XMM8-XMM15 with REX
	set_memory 8 $((0x9600)) $((0x0807060504030201))
	set_memory 8 $((0x9608)) $((0x100f0e0d0c0b0a09))
	set_regs RDI $((0x9600)) RSI $((0x9620))
	exec_insn f3 0f 6f 07    # movdqu (%rdi), %xmm0
	check_xmm 0 $((0x0807060504030201)) $((0x100f0e0d0c0b0a09))
	exec_insn 66 44 0f 6f 0f # movdqa (%rdi), %xmm9
	check_xmm 9 $((0x0807060504030201)) $((0x100f0e0d0c0b0a09))
	exec_insn 66 44 0f 7f 0e # movdqa %xmm9, (%rsi)
	check "movdqa store lo" $(get_memory 8 $((0x9620))) $((0x0807060504030201))
	check "movdqa store hi" $(get_memory 8 $((0x9628))) $((0x100f0e0d0c0b0a09))

	# movsd / movss: memory loads zero upper bits; reg-to-reg preserves upper bits!
	xmm_lo[1]=$((0xaaaaaaaaaaaaaaaa)) xmm_hi[1]=$((0xbbbbbbbbbbbbbbbb))
	exec_insn f2 0f 10 0f # movsd (%rdi), %xmm1 (mem -> zeroes hi)
	check_xmm 1 $((0x0807060504030201)) 0
	xmm_hi[1]=$((0xbbbbbbbbbbbbbbbb))
	xmm_lo[2]=$((0x1111222233334444)) xmm_hi[2]=$((0xcccccccccccccccc))
	exec_insn f2 0f 10 ca # movsd %xmm2, %xmm1 (reg -> preserves hi)
	check_xmm 1 $((0x1111222233334444)) $((0xbbbbbbbbbbbbbbbb))
	xmm_lo[2]=$((0x99999999deadbeef))
	exec_insn f3 0f 10 ca # movss %xmm2, %xmm1 (reg -> copies low 32b only)
	check_xmm 1 $((0x11112222deadbeef)) $((0xbbbbbbbbbbbbbbbb))
	exec_insn f3 0f 10 0f # movss (%rdi), %xmm1 (mem -> zeroes 32..127)
	check_xmm 1 $((0x04030201)) 0

	# movq / movd with 66 + REX.W prefix ordering (66 48 0f 6e / 7e)
	set_regs RAX $((0xfedcba9876543210))
	xmm_hi[3]=-1
	exec_insn 66 48 0f 6e d8 # movq %rax, %xmm3
	check_xmm 3 $((0xfedcba9876543210)) 0
	set_regs RBX 0
	exec_insn 66 48 0f 7e db # movq %xmm3, %rbx
	check_reg RBX $((0xfedcba9876543210))
	exec_insn 66 0f 7e da # movd %xmm3, %edx (zeroes upper 32b)
	check_reg RDX $((0x76543210))

	# movhps / movlps / movlhps / movhlps / movddup
	xmm_lo[4]=$((0x1111111111111111)) xmm_hi[4]=$((0x2222222222222222))
	exec_insn 0f 16 27 # movhps (%rdi), %xmm4
	check_xmm 4 $((0x1111111111111111)) $((0x0807060504030201))
	exec_insn 0f 12 67 08 # movlps 8(%rdi), %xmm4
	check_xmm 4 $((0x100f0e0d0c0b0a09)) $((0x0807060504030201))
	exec_insn f2 0f 12 e4 # movddup %xmm4, %xmm4
	check_xmm 4 $((0x100f0e0d0c0b0a09)) $((0x100f0e0d0c0b0a09))

	# pxor / por / pand / pandn
	exec_insn 66 0f ef c0 # pxor %xmm0, %xmm0
	check_xmm 0 0 0
	xmm_lo[0]=$((0xff00ff00ff00ff00)) xmm_hi[0]=$((0x00ff00ff00ff00ff))
	xmm_lo[1]=$((0x0f0f0f0f0f0f0f0f)) xmm_hi[1]=$((0x0f0f0f0f0f0f0f0f))
	exec_insn 66 0f df c1 # pandn %xmm1, %xmm0 (~xmm0 & xmm1)
	check_xmm 0 $((0x000f000f000f000f)) $((0x0f000f000f000f00))
	exec_insn 66 0f eb c1 # por %xmm1, %xmm0
	check_xmm 0 $((0x0f0f0f0f0f0f0f0f)) $((0x0f0f0f0f0f0f0f0f))

	# glibc SSE2 strlen idiom: pxor + pcmpeqb + pmovmskb + bsf
	put_bytes $((0x9700)) '0123456789ab\0def'
	set_regs RDI $((0x9700)) RAX -1
	exec_insn 66 0f ef c0 # pxor %xmm0, %xmm0
	exec_insn f3 0f 6f 0f # movdqu (%rdi), %xmm1
	exec_insn 66 0f 74 c8 # pcmpeqb %xmm0, %xmm1
	exec_insn 66 0f d7 c1 # pmovmskb %xmm1, %eax
	check_reg RAX $((1 << 12))
	exec_insn 0f bc c0    # bsf %eax, %eax
	check_reg RAX 12

	# pminub / pmaxub / paddb / psubb / paddq / psubq
	xmm_lo[0]=$((0x0080ff1005040302)) xmm_hi[0]=$((0x1020304050607080))
	xmm_lo[1]=$((0x0180fe2005010900)) xmm_hi[1]=$((0x1510352055407560))
	exec_insn 66 0f da c1 # pminub %xmm1, %xmm0
	check_xmm 0 $((0x0080fe1005010300)) $((0x1010302050407060))
	exec_insn 66 0f f8 c1 # psubb %xmm1, %xmm0
	check_xmm 0 $((0xff0000f00000fa00)) $((0xfb00fb00fb00fb00))
	xmm_lo[2]=-1 xmm_hi[2]=10
	xmm_lo[3]=2 xmm_hi[3]=32
	exec_insn 66 0f d4 d3 # paddq %xmm3, %xmm2
	check_xmm 2 1 42

	# punpcklbw / punpcklqdq / pshufd
	xmm_lo[0]=$((0x0807060504030201)) xmm_hi[0]=0
	xmm_lo[1]=$((0xf8f7f6f5f4f3f2f1)) xmm_hi[1]=0
	exec_insn 66 0f 60 c1 # punpcklbw %xmm1, %xmm0
	check_xmm 0 $((0xf404f303f202f101)) $((0xf808f707f606f505))
	xmm_lo[0]=$((0x1111111122222222)) xmm_hi[0]=$((0x3333333344444444))
	exec_insn 66 0f 70 c8 1b # pshufd $0x1b, %xmm0, %xmm1 (reverse 4 dwords)
	check_xmm 1 $((0x4444444433333333)) $((0x2222222211111111))
	exec_insn 66 0f 6c c1 # punpcklqdq %xmm1, %xmm0
	check_xmm 0 $((0x1111111122222222)) $((0x4444444433333333))

	# Byte shifts pslldq / psrldq across 64-bit lane boundary, plus psllq / psrlq
	xmm_lo[0]=$((0x0807060504030201)) xmm_hi[0]=$((0x100f0e0d0c0b0a09))
	exec_insn 66 0f 73 f8 03 # pslldq $3, %xmm0 (shifts out 10,0f,0e)
	check_xmm 0 $((0x0504030201000000)) $((0x0d0c0b0a09080706))
	exec_insn 66 0f 73 d8 03 # psrldq $3, %xmm0
	check_xmm 0 $((0x0807060504030201)) $((0x0000000d0c0b0a09))
	exec_insn 66 0f 73 f8 0a # pslldq $10, %xmm0 (>= 8 bytes)
	check_xmm 0 0 $((0x0605040302010000))
	exec_insn 66 0f 73 d8 0a # psrldq $10, %xmm0 (>= 8 bytes)
	check_xmm 0 $((0x0000060504030201)) 0

	xmm_lo[0]=-1 xmm_hi[0]=$((0x8000000000000000))
	exec_insn 66 0f 73 d0 04 # psrlq $4, %xmm0 (must zero-shift, not sign-extend!)
	check_xmm 0 $((0x0fffffffffffffff)) $((0x0800000000000000))
	exec_insn 66 0f 73 f0 04 # psllq $4, %xmm0
	check_xmm 0 $((-16)) $((0x8000000000000000))

	# XMM shift by XMM count >= 64 -> 0
	xmm_lo[1]=64 xmm_hi[1]=0
	exec_insn 66 0f d3 c1 # psrlq %xmm1, %xmm0
	check_xmm 0 0 0

	# Word/dword shifts, compares, pinsrw/pextrw, movmskps/pd
	xmm_lo[0]=$((0x80007fff0001fffe)) xmm_hi[0]=0
	exec_insn 66 0f 71 e0 04 # psraw $4, %xmm0
	check_xmm 0 $((0xf80007ff0000ffff)) 0

	set_regs RAX $((0xabcd))
	exec_insn 66 0f c4 c0 05 # pinsrw $5, %eax, %xmm0
	exec_insn 66 0f c5 d0 05 # pextrw $5, %xmm0, %edx
	check_reg RDX $((0xabcd))

	xmm_lo[0]=$((0x8000000000000001)) xmm_hi[0]=$((0x7fffffff80000000))
	exec_insn 0f 50 c0 # movmskps %xmm0, %eax (dwords 1 and 2 negative -> 0b0110 = 6)
	check_reg RAX 6
	exec_insn 66 0f 50 c0 # movmskpd %xmm0, %eax (qword 0 negative -> 0b01 = 1)
	check_reg RAX 1
}

function run_tests() {
	info "Running self tests."
	init
	test_set_get_register
	test_set_get_memory
	test_xor
	TEST_tmpdir=$(mktemp -d)
	trap 'rm -rf "${TEST_tmpdir}"' EXIT
	test_linux_write
	test_linux_read
	test_linux_memory
	test_linux_misc
	test_linux_syscall_instruction
	test_macos_syscall_dispatch
	test_binary_format
	(test_load_elf)
	(test_run_elf_until_syscall)
	test_refuse_dynamic_elf
	test_alu
	test_test_inc_dec_neg_not
	test_mul_div
	test_addressing
	test_byte_registers
	test_mov
	test_setcc_cmov
	test_shifts
	test_control_flow
	test_stack
	test_nops_and_strings
	test_tls_and_addr32
	test_system_and_atomic
	test_bit_ops
	test_strings_and_misc
	test_sse2
	info "done."
}

run_tests
