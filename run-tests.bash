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
	test_binary_format
	(test_load_elf)
	(test_run_elf_until_syscall)
	test_refuse_dynamic_elf
	info "done."
}

run_tests