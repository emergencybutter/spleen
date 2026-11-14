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

	inst_binary_op binary_op_xor $((0x31)) $((0xd2))
	(($(get_register $((WIDTH32)) $((RDX))) == 0)) ||
		die "RDX != 0 0x%x" $(get_register $((WIDTH64)) $((RDX)))

	inst_binary_op binary_op_xor $((0x31)) $((0xc0))
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
	info "done."
}

run_tests