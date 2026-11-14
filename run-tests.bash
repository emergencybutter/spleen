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
	linux_syscall 9 0 100 3 2 1 0
	check_eq "$(rax)" -19 "file mmap on non-mmapable fd"
	linux_syscall 9 0 100 3 2 99 0
	check_eq "$(rax)" -9 "file mmap on closed fd"
	linux_syscall 9 0 0 3 $((0x22)) -1 0
	check_eq "$(rax)" -22 "zero length mmap"
	linux_syscall 11 $((map1)) 100
	check_eq "$(rax)" 0 "munmap"
}

function test_linux_file_syscalls() {
	GLOBAL_os_abi=linux
	declare -ri path_buf=$((0xc000)) data_buf=$((0xc400)) stat_buf=$((0xc800))
	printf '0123456789abcdefHELLO_MMAP' >"${TEST_tmpdir}/sample"
	ln -s "${TEST_tmpdir}/sample" "${TEST_tmpdir}/sample_link"

	# Write-mode openat is refused; missing file returns -ENOENT.
	put_string $((path_buf)) "${TEST_tmpdir}/sample"
	linux_syscall 257 -100 $((path_buf)) 1 0
	check_eq "$(rax)" -13 "openat O_WRONLY refused"
	put_string $((path_buf)) "${TEST_tmpdir}/does_not_exist"
	linux_syscall 257 $((0xffffff9c)) $((path_buf)) 0 0
	check_eq "$(rax)" -2 "openat missing file (32-bit AT_FDCWD)"

	# Read-only openat with 32-bit zero-extended AT_FDCWD (0xffffff9c).
	put_string $((path_buf)) "${TEST_tmpdir}/sample"
	linux_syscall 257 $((0xffffff9c)) $((path_buf)) 0 0
	declare -ri fd=$(rax)
	((fd >= 3)) || die "openat returned %d" $((fd))

	# read, pread64 (must not advance fd_pos), lseek.
	linux_syscall 0 $((fd)) $((data_buf)) 4
	check_eq "$(rax)" 4 "read 4 bytes from file"
	check_eq "$(get_memory 4 $((data_buf)))" $((0x33323130)) "read '0123'"

	linux_syscall 17 $((fd)) $((data_buf + 16)) 5 16
	check_eq "$(rax)" 5 "pread64 5 bytes at offset 16"
	check_eq "$(get_memory 4 $((data_buf + 16)))" $((0x4c4c4548)) "pread64 'HELL'"

	linux_syscall 0 $((fd)) $((data_buf)) 4
	check_eq "$(rax)" 4 "read continues from offset 4 after pread64"
	check_eq "$(get_memory 4 $((data_buf)))" $((0x37363534)) "read '4567'"

	linux_syscall 8 $((fd)) -4 2 # SEEK_END - 4 -> "MMAP"
	check_eq "$(rax)" 22 "lseek SEEK_END - 4"
	linux_syscall 0 $((fd)) $((data_buf)) 10
	check_eq "$(rax)" 4 "read until EOF"
	check_eq "$(get_memory 4 $((data_buf)))" $((0x50414d4d)) "read 'MMAP'"

	# fstat on regular file and stdout, plus newfstatat AT_EMPTY_PATH.
	linux_syscall 5 $((fd)) $((stat_buf))
	check_eq "$(rax)" 0 "fstat on open file"
	check_eq "$(get_memory 8 $((stat_buf + 48)))" 26 "fstat st_size"
	((($(get_memory 4 $((stat_buf + 24))) & 0xf000) == 0x8000)) ||
		die "fstat st_mode is not S_IFREG"

	linux_syscall 5 1 $((stat_buf))
	check_eq "$(rax)" 0 "fstat on stdout"
	((($(get_memory 4 $((stat_buf + 24))) & 0xf000) == 0x2000)) ||
		die "stdout st_mode is not S_IFCHR"

	put_string $((path_buf)) ""
	linux_syscall 262 $((fd)) $((path_buf)) $((stat_buf)) $((0x1000))
	check_eq "$(rax)" 0 "newfstatat AT_EMPTY_PATH"
	check_eq "$(get_memory 8 $((stat_buf + 48)))" 26 "newfstatat st_size"

	# File-backed mmap (PROT_READ, MAP_PRIVATE) + MAP_FIXED sub-mapping.
	linux_syscall 9 0 8192 1 2 $((fd)) 0
	declare -ri fmap=$(rax)
	((fmap > 0 && (fmap & 0xfff) == 0)) || die "bad file mmap %x" $((fmap))
	check_eq "$(get_memory 4 $((fmap + 16)))" $((0x4c4c4548)) "mmap file bytes"
	check_eq "$(get_memory 1 $((fmap + 100)))" 0 "mmap trailing zero byte"
	linux_syscall 9 $((fmap + 0x1000)) 4096 5 $((0x12)) $((fd)) 4096
	check_eq "$(rax)" $((fmap + 0x1000)) "mmap MAP_FIXED fast path"

	# access, fcntl, readlink, getcwd, prlimit64, getresuid, getrandom, close.
	put_string $((path_buf)) "${TEST_tmpdir}/sample"
	linux_syscall 21 $((path_buf)) 4 # R_OK
	check_eq "$(rax)" 0 "access R_OK"
	linux_syscall 21 $((path_buf)) 2 # W_OK
	check_eq "$(rax)" -13 "access W_OK refused"

	linux_syscall 72 $((fd)) 1030 10 # F_DUPFD_CLOEXEC >= 10
	declare -ri dupfd=$(rax)
	((dupfd >= 10)) || die "F_DUPFD_CLOEXEC returned %d" $((dupfd))
	linux_syscall 3 $((dupfd))
	check_eq "$(rax)" 0 "close dupfd"

	put_string $((path_buf)) "${TEST_tmpdir}/sample_link"
	linux_syscall 89 $((path_buf)) $((data_buf)) 256
	declare -ri link_len=$((${#TEST_tmpdir} + 7))
	check_eq "$(rax)" $((link_len)) "readlink length"

	linux_syscall 79 $((data_buf)) 4096
	check_eq "$(rax)" $((${#PWD} + 1)) "getcwd length"

	linux_syscall 302 0 3 0 $((stat_buf)) # prlimit64 RLIMIT_STACK
	check_eq "$(rax)" 0 "prlimit64"
	check_eq "$(get_memory 8 $((stat_buf)))" $((8 * 1024 * 1024)) "RLIMIT_STACK cur"
	check_eq "$(get_memory 8 $((stat_buf + 8)))" -1 "RLIMIT_STACK max"

	linux_syscall 118 $((stat_buf)) $((stat_buf + 4)) $((stat_buf + 8))
	check_eq "$(rax)" 0 "getresuid"
	check_eq "$(get_memory 4 $((stat_buf)))" "${UID}" "getresuid ruid"
	check_eq "$(get_memory 4 $((stat_buf + 4)))" "${EUID}" "getresuid euid"

	linux_syscall 318 $((data_buf)) 16 0
	check_eq "$(rax)" 16 "getrandom"

	linux_syscall 3 $((fd))
	check_eq "$(rax)" 0 "close file fd"
	linux_syscall 0 $((fd)) $((data_buf)) 4
	check_eq "$(rax)" -9 "read after close fails with EBADF"
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

# A binary with an invalid/unreadable PT_INTERP interpreter must be refused.
function test_refuse_dynamic_elf() {
	declare -r binary_file=$(mktemp)
	cp examples-bin/hi-linux "${binary_file}"
	# Turn the first program header (at e_phoff = 64) into PT_INTERP; its bytes
	# start with 0x7f 'E' 'L' 'F', which is not an existing interpreter path.
	printf '\003' | dd of="${binary_file}" bs=1 seek=64 conv=notrunc 2>/dev/null
	declare -r output=$( (init && load_elf_file "${binary_file}") 2>&1 || :)
	rm -f "${binary_file}"
	[[ "${output}" == *PT_INTERP* ]] ||
		die "broken PT_INTERP ELF was not refused: ${output}"
}

# Tests apply_elf_relocations on DT_RELR (including bit 62 of a bitmap entry),
# DT_RELA (R_X86_64_RELATIVE, R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_PC32),
# and DT_JMPREL (R_X86_64_JUMP_SLOT), plus end-to-end execution of compiled
# nostdlib static-PIE / ET_DYN binaries when a Linux x86_64 C compiler exists.
function test_elf_relocations() {
	(
		init
		declare -ri base=$((0x555555554000))
		declare -ri dyn=$((base + 0x1000))
		declare -ri symtab=$((base + 0x1200))
		declare -ri rela=$((base + 0x1300))
		declare -ri jmprel=$((base + 0x1400))
		declare -ri relr=$((base + 0x1500))
		declare -ri data=$((base + 0x2000))

		# Populate DT_RELR:
		#   entry 0: even offset 0x2000 -> relocates data+0, where becomes data+8
		#   entry 1: bitmap with bit 0 and bit 62 set ((1<<63) | 3)
		#            -> relocates data+8 and data+8+62*8 = data+0x1f8,
		#               where becomes data+8+63*8 = data+0x200
		#   entry 2: bitmap with bit 0 set (3) -> relocates data+0x200
		elf_mem_write64 $((data + 0)) $((0x111))
		elf_mem_write64 $((data + 8)) $((0x222))
		elf_mem_write64 $((data + 0x1f8)) $((0x333))
		elf_mem_write64 $((data + 0x200)) $((0x444))
		elf_mem_write64 $((relr + 0)) $((0x2000))
		elf_mem_write64 $((relr + 8)) $(((1 << 63) | 3))
		elf_mem_write64 $((relr + 16)) 3

		# Populate symbol #1 in DT_SYMTAB (st_shndx = 1 at +6, st_value = 0x3456 at +8).
		set_memory 2 $((symtab + 24 + 6)) 1
		elf_mem_write64 $((symtab + 24 + 8)) $((0x3456))

		# DT_RELA entries:
		#   0: R_X86_64_RELATIVE (8) at 0x2020, addend 0x2500
		#   1: R_X86_64_64 (1) sym 1 at 0x2028, addend 0x10
		#   2: R_X86_64_GLOB_DAT (6) sym 1 at 0x2030, addend 0
		#   3: R_X86_64_PC32 (2) sym 1 at 0x2038, addend -4
		elf_mem_write64 $((rela + 0)) $((0x2020))
		elf_mem_write64 $((rela + 8)) $((R_X86_64_RELATIVE))
		elf_mem_write64 $((rela + 16)) $((0x2500))

		elf_mem_write64 $((rela + 24)) $((0x2028))
		elf_mem_write64 $((rela + 32)) $(((1 << 32) | R_X86_64_64))
		elf_mem_write64 $((rela + 40)) $((0x10))

		elf_mem_write64 $((rela + 48)) $((0x2030))
		elf_mem_write64 $((rela + 56)) $(((1 << 32) | R_X86_64_GLOB_DAT))
		elf_mem_write64 $((rela + 64)) 0

		elf_mem_write64 $((rela + 72)) $((0x2038))
		elf_mem_write64 $((rela + 80)) $(((1 << 32) | R_X86_64_PC32))
		elf_mem_write64 $((rela + 88)) -4

		# DT_JMPREL entry: R_X86_64_JUMP_SLOT (7) sym 1 at 0x2040.
		elf_mem_write64 $((jmprel + 0)) $((0x2040))
		elf_mem_write64 $((jmprel + 8)) $(((1 << 32) | R_X86_64_JUMP_SLOT))
		elf_mem_write64 $((jmprel + 16)) 0

		# Build PT_DYNAMIC with relative vaddrs (ET_DYN).
		declare -ia dtags=(
			$((DT_SYMTAB)) $((0x1200))
			$((DT_SYMENT)) 24
			$((DT_RELR)) $((0x1500))
			$((DT_RELRSZ)) 24
			$((DT_RELRENT)) 8
			$((DT_RELA)) $((0x1300))
			$((DT_RELASZ)) 96
			$((DT_RELAENT)) 24
			$((DT_PLTREL)) $((DT_RELA))
			$((DT_JMPREL)) $((0x1400))
			$((DT_PLTRELSZ)) 24
			$((DT_NULL)) 0
		)
		declare -i di
		for ((di = 0; di < ${#dtags[@]}; di++)); do
			elf_mem_write64 $((dyn + di * 8)) $((dtags[di]))
		done

		apply_elf_relocations $((base)) $((ET_DYN)) $((dyn)) $((${#dtags[@]} * 8))

		check_eq "$(get_memory 8 $((data + 0)))" $((base + 0x111)) "DT_RELR even entry"
		check_eq "$(get_memory 8 $((data + 8)))" $((base + 0x222)) "DT_RELR bitmap bit 0"
		check_eq "$(get_memory 8 $((data + 0x1f8)))" $((base + 0x333)) "DT_RELR bitmap bit 62"
		check_eq "$(get_memory 8 $((data + 0x200)))" $((base + 0x444)) "DT_RELR next bitmap word"
		check_eq "$(get_memory 8 $((data + 0x20)))" $((base + 0x2500)) "R_X86_64_RELATIVE"
		check_eq "$(get_memory 8 $((data + 0x28)))" $((base + 0x3466)) "R_X86_64_64"
		check_eq "$(get_memory 8 $((data + 0x30)))" $((base + 0x3456)) "R_X86_64_GLOB_DAT"
		check_eq "$(get_memory 4 $((data + 0x38)))" $(((0x3456 - 0x2038 - 4) & 0xffffffff)) "R_X86_64_PC32"
		check_eq "$(get_memory 8 $((data + 0x40)))" $((base + 0x3456)) "R_X86_64_JUMP_SLOT"
	)

	# End-to-end execution of real compiler-generated static-PIE (RELA + RELR)
	# and symbol-relocated ET_DYN binaries when running on Linux x86_64 with cc.
	if [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] && command -v cc >/dev/null 2>&1; then
		cat >"${TEST_tmpdir}/reloc_test.c" <<-'EOF'
			const char msg[] = "reloc-ok\n";
			const char *ptrs[3] = { msg, msg + 6, msg };
			__attribute__((noinline)) long msg_len(void) { return 9; }
			void _start(void) {
				long len = msg_len();
				register long rax __asm__("rax") = 1;
				register long rdi __asm__("rdi") = 1;
				register const char *rsi __asm__("rsi") = ptrs[0];
				register long rdx __asm__("rdx") = len;
				__asm__ volatile("syscall"
					: "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "rcx", "r11", "memory");
				rax = 60;
				rdi = (ptrs[1][0] == 'o') ? 0 : 1;
				__asm__ volatile("syscall" : "+r"(rax) : "r"(rdi) : "rcx", "r11");
			}
		EOF
		cc -O1 -fno-stack-protector -fPIE -static-pie -nostdlib -Wl,--build-id=none \
			-o "${TEST_tmpdir}/pie_rela" "${TEST_tmpdir}/reloc_test.c"
		check_eq "$(main "${TEST_tmpdir}/pie_rela")" "reloc-ok" "run static-pie RELA binary"

		if cc -O1 -fno-stack-protector -fPIE -static-pie -nostdlib \
			-Wl,-z,pack-relative-relocs -Wl,--build-id=none \
			-o "${TEST_tmpdir}/pie_relr" "${TEST_tmpdir}/reloc_test.c" 2>/dev/null; then
			check_eq "$(main "${TEST_tmpdir}/pie_relr")" "reloc-ok" "run static-pie RELR binary"
		fi

		cc -O1 -fno-stack-protector -fPIC -shared -nostdlib -e _start -Wl,--build-id=none \
			-o "${TEST_tmpdir}/et_dyn_sym" "${TEST_tmpdir}/reloc_test.c"
		check_eq "$(main "${TEST_tmpdir}/et_dyn_sym")" "reloc-ok" \
			"run ET_DYN with R_X86_64_64/GLOB_DAT/JUMP_SLOT"
	fi
}

# Verifies PT_INTERP dynamic ELF loading (/bin/bash + ld-linux-x86-64.so.2):
# both images mapped at their respective bases, RSP raised, AT_BASE/AT_ENTRY
# set properly in auxv, and execution starting at the interpreter entry point.
function test_load_dynamic_elf() {
	if [[ ! -r /bin/bash || ! -r /lib64/ld-linux-x86-64.so.2 ]]; then
		return
	fi
	declare -r magic=$(hexdump -n 5 -v -e '5/1 "%02x"' /bin/bash)
	[[ "${magic}" == "7f454c4602" ]] || return

	(
		declare -r binary_file=/bin/bash
		init
		load_elf_file "${binary_file}" --help

		# Both main executable and PT_INTERP dynamic linker are mapped.
		check_eq "$(get_memory 4 $((ELF_DYN_BASE)))" $((0x464c457f)) "/bin/bash ELF magic at ELF_DYN_BASE"
		check_eq "$(get_memory 4 $((ELF_INTERP_BASE)))" $((0x464c457f)) "ld-linux ELF magic at ELF_INTERP_BASE"

		declare -ri bash_e_entry=$(get_memory 8 $((ELF_DYN_BASE + 24)))
		declare -ri ld_e_entry=$(get_memory 8 $((ELF_INTERP_BASE + 24)))
		declare -ri actual_start=$((GLOBAL_text_vmaddr + GLOBAL_entryoff))
		check_eq "${actual_start}" $((ELF_INTERP_BASE + ld_e_entry)) \
			"execution starts at PT_INTERP entry point"

		# Stack should be near LINUX_INITIAL_RSP and contain AT_BASE and AT_ENTRY.
		declare -ri sp=$((registers[RSP]))
		((sp > 0x7fffffff0000 && sp % 16 == 0)) ||
			die "unexpected Linux RSP: 0x%x" $((sp))
		check_eq "$(get_memory 8 $((sp)))" 2 "argc for /bin/bash --help"

		# Walk past argc, argv[0..1], NULL, envp NULL to inspect auxv.
		declare -i auxp=$((sp + 8 * (1 + 2 + 1 + 1)))
		declare -i at_type at_val got_base=-1 got_entry=-1 got_phdr=-1
		while true; do
			at_type=$(get_memory 8 $((auxp)))
			at_val=$(get_memory 8 $((auxp + 8)))
			((at_type == AT_NULL)) && break
			case $((at_type)) in
			$((AT_BASE))) got_base=$((at_val)) ;;
			$((AT_ENTRY))) got_entry=$((at_val)) ;;
			$((AT_PHDR))) got_phdr=$((at_val)) ;;
			esac
			((auxp += 16)) || :
		done
		check_eq "${got_base}" $((ELF_INTERP_BASE)) "auxv AT_BASE is ELF_INTERP_BASE"
		check_eq "${got_entry}" $((ELF_DYN_BASE + bash_e_entry)) "auxv AT_ENTRY is main entry"
		check_eq "${got_phdr}" $((ELF_DYN_BASE + 64)) "auxv AT_PHDR is main phdr"
	)
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
	test_linux_file_syscalls
	test_linux_misc
	test_linux_syscall_instruction
	test_macos_syscall_dispatch
	test_binary_format
	(test_load_elf)
	(test_run_elf_until_syscall)
	test_refuse_dynamic_elf
	test_elf_relocations
	test_load_dynamic_elf
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
	info "done."
}

run_tests
