#!/bin/bash

# bash integer type is a signed int64 so unsigned int32 fits. unsigned 64 does
# not, so we should avoid doing shell arithmetic evaluation and resort to
# calling out to bc.  OR we go the wrong route and assume all the uint64 values
# we manipulate are smaller than INT64_MAX Obviously we're following the way of
# the YOLO. I'm writing a x86 emulator in bash after all.

# set -e generally allows to detect programming mistakes early. However it does
# not play well with arightmetic expressions. With arithmetic expressions, a
# line like `((a=b&0x1))` will evaluate to false if a results to 0. This would
# terminate the program with set -e.
# This is why all the arithmetic expressions end with || :
set -eu

### Options ###
enable_debug_messages=false

### Early functions ###
# Those may be executed before we even validated the version of bash
# that we're running, so they come before even the constant definitions

function debug_level() {
	declare level="$1"
	declare format="$2"
	if [[ ${level} = "DEBUG" && ! "${enable_debug_messages}" = true ]]; then
		return
	fi
	shift 2
	printf "${level}: ${format}\n" "$@" >&2
}

function die() {
	debug_level FATAL_ERROR "$@"
	exit 127
}

function debug() {
	debug_level "DEBUG" "$@"
}

function info() {
	debug_level "INFO" "$@"
}

function check_version() {
	[[ -n "${BASH_VERSION}" ]] || die "$0 needs bash to run"
	declare -ri bash_major="${BASH_VERSION%%.*}"
	((bash_major >= 3)) || die "$0 needs bash version 3 or higher"
}

# Check the version before initializing constants.
check_version

### Constants ###

declare -ri RAX=0
declare -ri RCX=1
declare -ri RDX=2
declare -ri RBX=3
declare -ri RSP=4
declare -ri RBP=5
declare -ri RSI=6
declare -ri RDI=7
declare -ri R8=8
declare -ri R9=9
declare -ri R10=10
declare -ri R11=11
declare -ri R12=12
declare -ri R13=13
declare -ri R14=14
declare -ri R15=15

declare -ri WIDTH64=8
declare -ri WIDTH32=4
declare -ri WIDTH16=2
declare -ri WIDTH8=1

### Mach-O constants
declare -ri MH_MAGIC=$((0xfeedface))
declare -ri MH_MAGIC_64=$((0xfeedfacf))
declare -ri MH_OBJECT=$((0x1))
declare -ri MH_EXECUTE=$((0x2))
declare -ri MH_FVMLIB=$((0x3))
declare -ri MH_CORE=$((0x4))
declare -ri MH_PRELOAD=$((0x5))
declare -ri MH_DYLIB=$((0x6))
declare -ri MH_DYLINKER=$((0x7))
declare -ri MH_BUNDLE=$((0x8))
declare -ri MH_DYLIB_STUB=$((0x9))
declare -ri MH_DSYM=$((0xa))
declare -ri MH_KEXT_BUNDLE=$((0xb))
# Mach-O commands
declare -ri LC_SEGMENT=$((0x1))
declare -ri LC_SYMTAB=$((0x2))
declare -ri LC_SYMSEG=$((0x3))
declare -ri LC_THREAD=$((0x4))
declare -ri LC_UNIXTHREAD=$((0x5))
declare -ri LC_LOADFVMLIB=$((0x6))
declare -ri LC_IDFVMLIB=$((0x7))
declare -ri LC_IDENT=$((0x8))
declare -ri LC_FVMFILE=$((0x9))
declare -ri LC_PREPAGE=$((0xa))
declare -ri LC_DYSYMTAB=$((0xb))
declare -ri LC_LOAD_DYLIB=$((0xc))
declare -ri LC_ID_DYLIB=$((0xd))
declare -ri LC_LOAD_DYLINKER=$((0xe))
declare -ri LC_ID_DYLINKER=$((0xf))
declare -ri LC_PREBOUND_DYLIB=$((0x10))
declare -ri LC_ROUTINES=$((0x11))
declare -ri LC_SUB_FRAMEWORK=$((0x12))
declare -ri LC_SUB_UMBRELLA=$((0x13))
declare -ri LC_SUB_CLIENT=$((0x14))
declare -ri LC_SUB_LIBRARY=$((0x15))
declare -ri LC_TWOLEVEL_HINTS=$((0x16))
declare -ri LC_PREBIND_CKSUM=$((0x17))
declare -ri LC_REQ_DYLD=$((0x80000000))
declare -ri LC_LOAD_WEAK_DYLIB=$((0x18 | LC_REQ_DYLD))
declare -ri LC_SEGMENT_64=$((0x19))
declare -ri LC_ROUTINES_64=$((0x1a))
declare -ri LC_UUID=$((0x1b))
declare -ri LC_RPATH=$((0x1c | LC_REQ_DYLD))
declare -ri LC_CODE_SIGNATURE=$((0x1d))
declare -ri LC_SEGMENT_SPLIT_INFO=$((0x1e))
declare -ri LC_REEXPORT_DYLIB=$((0x1f | LC_REQ_DYLD))
declare -ri LC_LAZY_LOAD_DYLIB=$((0x20))
declare -ri LC_ENCRYPTION_INFO=$((0x21))
declare -ri LC_DYLD_INFO=$((0x22))
declare -ri LC_DYLD_INFO_ONLY=$((0x22 | LC_REQ_DYLD))
declare -ri LC_LOAD_UPWARD_DYLIB=$((0x23 | LC_REQ_DYLD))
declare -ri LC_VERSION_MIN_MACOSX=$((0x24))
declare -ri LC_VERSION_MIN_IPHONEOS=$((0x25))
declare -ri LC_FUNCTION_STARTS=$((0x26))
declare -ri LC_DYLD_ENVIRONMENT=$((0x27))
declare -ri LC_MAIN=$((0x28 | LC_REQ_DYLD))
declare -ri LC_DATA_IN_CODE=$((0x29))
declare -ri LC_SOURCE_VERSION=$((0x2A))
declare -ri LC_DYLIB_CODE_SIGN_DRS=$((0x2B))

### ELF constants
declare -ri ELFCLASS64=2
declare -ri ELFDATA2LSB=1
declare -ri ET_EXEC=2
declare -ri ET_DYN=3
declare -ri EM_X86_64=62
declare -ri PT_LOAD=1
declare -ri PT_DYNAMIC=2
declare -ri PT_INTERP=3
declare -ri PT_PHDR=6
# Load address used for ET_DYN (PIE / static-pie) binaries and PT_INTERP loader.
declare -ri ELF_DYN_BASE=$((0x555555554000))
declare -ri ELF_INTERP_BASE=$((0x7ffff7fc0000))
declare -ri LINUX_INITIAL_RSP=$((0x7fffffffe000))
# Dynamic section tags
declare -ri DT_NULL=0
declare -ri DT_PLTRELSZ=2
declare -ri DT_STRTAB=5
declare -ri DT_SYMTAB=6
declare -ri DT_RELA=7
declare -ri DT_RELASZ=8
declare -ri DT_RELAENT=9
declare -ri DT_SYMENT=11
declare -ri DT_PLTREL=20
declare -ri DT_JMPREL=23
declare -ri DT_RELRSZ=35
declare -ri DT_RELR=36
declare -ri DT_RELRENT=37
# x86_64 ELF relocation types
declare -ri R_X86_64_NONE=0
declare -ri R_X86_64_64=1
declare -ri R_X86_64_PC32=2
declare -ri R_X86_64_PLT32=4
declare -ri R_X86_64_COPY=5
declare -ri R_X86_64_GLOB_DAT=6
declare -ri R_X86_64_JUMP_SLOT=7
declare -ri R_X86_64_RELATIVE=8
declare -ri R_X86_64_32=10
declare -ri R_X86_64_32S=11
declare -ri R_X86_64_IRELATIVE=37
# Auxiliary vector entries
declare -ri AT_NULL=0
declare -ri AT_PHDR=3
declare -ri AT_PHENT=4
declare -ri AT_PHNUM=5
declare -ri AT_PAGESZ=6
declare -ri AT_BASE=7
declare -ri AT_ENTRY=9
declare -ri AT_UID=11
declare -ri AT_EUID=12
declare -ri AT_GID=13
declare -ri AT_EGID=14
declare -ri AT_RANDOM=25
declare -ri AT_EXECFN=31

### Runtime global variables ###

declare -i GLOBAL_text_vmaddr
declare -i GLOBAL_entryoff
declare -i GLOBAL_stacksize
# Operating system ABI of the loaded binary: "macos" (default) or "linux".
# Selects the system call table used by the `syscall` instruction. Binary
# loaders are expected to set it (e.g. an ELF loader sets it to "linux").
declare GLOBAL_os_abi="${GLOBAL_os_abi:-macos}"

# Linux emulation state.
# GLOBAL_linux_brk_start: initial program break. A loader should set it to the
# (page aligned) end of the loaded image; 0 means use LINUX_DEFAULT_BRK_START.
declare -i GLOBAL_linux_brk_start=0
declare -i GLOBAL_linux_brk=0 # current program break, 0 = not initialised yet
# Next address handed out by anonymous/file mmap (bump allocator, never reused).
declare -i GLOBAL_linux_mmap_next=$((0x7f0000000000))
# FS/GS segment bases as set by arch_prctl. Nothing uses them for memory
# addressing (yet); they are only stored.
declare -i GLOBAL_fs_base=0
declare -i GLOBAL_gs_base=0
# Open read-only host file descriptors (fd >= 3).
declare -a LINUX_fd_path=()
declare -ia LINUX_fd_pos=()
declare -ia LINUX_fd_size=()
declare -ia LINUX_fd_flags=()
# Last read-only file-backed mmap reservation (fast path for ld.so MAP_FIXED).
declare LINUX_ro_mmap_path=""
declare -i LINUX_ro_mmap_base=0 LINUX_ro_mmap_size=0 LINUX_ro_mmap_reqlen=0 LINUX_ro_mmap_off=0

# Insanity
declare -a memory

declare -a registers

# Instruction decoding state. Shadowed by run(), declared globally so that the
# instruction helpers can be used directly (e.g. by the tests).
declare -i rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 operand_size_prefix=0
declare -i rip=0 advance=0 val=0 cond=0

# RFLAGS, one variable per flag.
declare -i flag_cf=0 flag_pf=0 flag_af=0 flag_zf=0 flag_sf=0 flag_of=0 flag_df=0
declare -ri INT64_MIN=$((1 << 63))

# parity_table[byte] is 1 when byte has an even number of bits set (PF).
declare -a parity_table
function init_parity_table() {
	declare -i i b p
	for ((i = 0; i < 256; i++)); do
		p=1
		for ((b = i; b; b >>= 1)); do
			((p ^= b & 1)) || :
		done
		parity_table[i]=$((p))
	done
}
init_parity_table

function register_name() {
	declare -ri reg="$1"
	case $((reg)) in
	0)
		echo RAX
		;;
	1)
		echo RCX
		;;
	2)
		echo RDX
		;;
	3)
		echo RBX
		;;
	4)
		echo RSP
		;;
	5)
		echo RBP
		;;
	6)
		echo RSI
		;;
	7)
		echo RDI
		;;
	8)
		echo R8
		;;
	9)
		echo R9
		;;
	10)
		echo R10
		;;
	11)
		echo R11
		;;
	12)
		echo R12
		;;
	13)
		echo R13
		;;
	14)
		echo R14
		;;
	15)
		echo R15
		;;
	*)
		die "Unknown register: %x" $((reg))
		;;
	esac
}

function command_nr_to_name() {
	case "$1" in
	$((0x1)))
		echo "LC_SEGMENT"
		;;
	$((0x2)))
		echo "LC_SYMTAB"
		;;
	$((0x3)))
		echo "LC_SYMSEG"
		;;
	$((0x4)))
		echo "LC_THREAD"
		;;
	$((0x5)))
		echo "LC_UNIXTHREAD"
		;;
	$((0x6)))
		echo "LC_LOADFVMLIB"
		;;
	$((0x7)))
		echo "LC_IDFVMLIB"
		;;
	$((0x8)))
		echo "LC_IDENT"
		;;
	$((0x9)))
		echo "LC_FVMFILE"
		;;
	$((0xa)))
		echo "LC_PREPAGE"
		;;
	$((0xb)))
		echo "LC_DYSYMTAB"
		;;
	$((0xc)))
		echo "LC_LOAD_DYLIB"
		;;
	$((0xd)))
		echo "LC_ID_DYLIB"
		;;
	$((0xe)))
		echo "LC_LOAD_DYLINKER"
		;;
	$((0xf)))
		echo "LC_ID_DYLINKER"
		;;
	$((0x10)))
		echo "LC_PREBOUND_DYLIB"
		;;
	$((0x11)))
		echo "LC_ROUTINES"
		;;
	$((0x12)))
		echo "LC_SUB_FRAMEWORK"
		;;
	$((0x13)))
		echo "LC_SUB_UMBRELLA"
		;;
	$((0x14)))
		echo "LC_SUB_CLIENT"
		;;
	$((0x15)))
		echo "LC_SUB_LIBRARY"
		;;
	$((0x16)))
		echo "LC_TWOLEVEL_HINTS"
		;;
	$((0x17)))
		echo "LC_PREBIND_CKSUM"
		;;
	$((0x19)))
		echo "LC_SEGMENT_64"
		;;
	$((0x1a)))
		echo "LC_ROUTINES_64"
		;;
	$((0x1b)))
		echo "LC_UUID"
		;;
	$((0x1d)))
		echo "LC_CODE_SIGNATURE"
		;;
	$((0x1e)))
		echo "LC_SEGMENT_SPLIT_INFO"
		;;
	$((0x20)))
		echo "LC_LAZY_LOAD_DYLIB"
		;;
	$((0x21)))
		echo "LC_ENCRYPTION_INFO"
		;;
	$((0x22)))
		echo "LC_DYLD_INFO"
		;;
	$((0x22)))
		echo "LC_DYLD_INFO_ONLY"
		;;
	$((0x23)))
		echo "LC_LOAD_UPWARD_DYLIB"
		;;
	$((0x24)))
		echo "LC_VERSION_MIN_MACOSX"
		;;
	$((0x25)))
		echo "LC_VERSION_MIN_IPHONEOS"
		;;
	$((0x26)))
		echo "LC_FUNCTION_STARTS"
		;;
	$((0x27)))
		echo "LC_DYLD_ENVIRONMENT"
		;;
	$((0x28)))
		echo "LC_MAIN"
		;;
	$((0x29)))
		echo "LC_DATA_IN_CODE"
		;;
	$((0x2A)))
		echo "LC_SOURCE_VERSION"
		;;
	$((0x2B)))
		echo "LC_DYLIB_CODE_SIGN_DRS"
		;;
	*)
		echo "UNKOWNN"
		;;
	esac
}

function dump_file() {
	hexdump -v -e '/1 "%u\n"' "${binary_file}"
}

function dump_at() {
	declare -ri offset="$1"
	declare -ri size="$2"
	hexdump -v -e '/1 "%u\n"' "${binary_file}" | (
		consume $((offset))
		head -n $((size))
	)
}

function consume_uint8() {
	declare -i i0
	read i0
	echo $((i0))
}

function print_le32() {
	declare -ri i0="$1"
	declare -ri i1="$2"
	declare -ri i2="$3"
	declare -ri i3="$4"
	echo $((i0 | i1 << 8 | i2 << 16 | i3 << 24))
}

function consume_uint32() {
	declare -i i0
	declare -i i1
	declare -i i2
	declare -i i3
	read i0
	read i1
	read i2
	read i3
	print_le32 $((i0)) $((i1)) $((i2)) $((i3))
}

function consume_vmprot_t() {
	consume_uint32
}

function consume_string() {
	declare -ri size="$1"
	declare print="true"
	declare -i i
	for ((i = 0; i < size; i++)); do
		declare -i i0
		read i0
		if ((i0 == 0)); then
			print=false
		fi
		if [[ ${print} == true ]]; then
			# To convert an integer to the corresponding ascii character in bash,
			# we use printf '\x123' where 123 is an hex representation of the integer.
			# We generate the '\x123' string with a printf. Everything is fine.
			printf "$(printf '\\x%x' $((i0)))"
		fi
	done
}

# Bash integer type is a signed 64 bit integer
# We resort to bc if we overflow
function consume_uint64() {
	declare -ri i0=$(consume_uint32)
	declare -ri i1=$(consume_uint32)
	if (((i1 & (1 << 31)) == 0)); then
		echo $((i0 | i1 << 32))
	else
		echo "(2^32)*$((i1)) + $((i0))" | bc -l
	fi
}

function load_macho_file() {
	#struct mach_header_64 {
	#	uint32_t      magic;
	#	cpu_type_t    cputype;
	#	cpu_subtype_t cpusubtype;
	#	uint32_t      filetype;
	#	uint32_t      ncmds;
	#	uint32_t      sizeofcmds;
	#	uint32_t      flags;
	#	uint32_t      reserved;
	#};
	declare -ri mach_header_magic=$(consume_uint32)
	declare -ri mach_header_cputype=$(consume_uint32)
	declare -ri mach_header_cpu_subtype=$(consume_uint32)
	declare -ri mach_header_filetype=$(consume_uint32)
	declare -ri mach_header_ncmds=$(consume_uint32)
	declare -ri mach_header_sizeofcmds=$(consume_uint32)
	declare -ri mach_header_flags=$(consume_uint32)
	declare -ri mach_header_reserved=$(consume_uint32)

	((mach_header_magic == MH_MAGIC_64)) ||
		die "Can't find magic number"
	((mach_header_filetype == MH_EXECUTE)) ||
		die "Unknown filetype"
	GLOBAL_os_abi="macos"
	declare -i i
	for ((i = 0; i < mach_header_ncmds; i++)); do
		consume_command
	done
}

function command_name() {
	typeset -i cmd="$1"
	typeset req_dyld=""
	if ((cmd & LC_REQ_DYLD)); then
		((cmd = cmd & ~LC_REQ_DYLD)) || :
		req_dyld="|LC_REQ_DYLD"
	fi
	echo "$(command_nr_to_name $((cmd)))${req_dyld}"
}

function consume() {
	declare -ri size="$1"
	declare -i i
	for ((i = 0; i < size; i++)); do
		consume_uint8 >/dev/null
	done
}

function consume_section_64() {
	typeset -r sectname=$(consume_string 16) # name of this section
	typeset -r segname=$(consume_string 16)  # segment this section goes in
	typeset -ri addr=$(consume_uint64)       # memory address of this section
	typeset -ri size=$(consume_uint64)       # size in bytes of this section
	typeset -ri offset=$(consume_uint32)     # file offset of this section
	typeset -ri align=$(consume_uint32)      # section alignment (power of 2)
	typeset -ri reloff=$(consume_uint32)     # file offset of relocation entries
	typeset -ri nreloc=$(consume_uint32)     # number of relocation entries
	typeset -ri flags=$(consume_uint32)      # flags (section type and attributes
	typeset -ri reserved1=$(consume_uint32)  # reserved (for offset or index)
	typeset -ri reserved2=$(consume_uint32)  # reserved (for count or sizeof)
	typeset -ri reserved3=$(consume_uint32)  # reserved

	debug "Segment.Section: ${segname}.${sectname} addr: %x size: %x offset: %x align: %x" \
		$((addr)) $((size)) $((offset)) $((align))

	if [[ "${segname}" = __TEXT ]]; then
		typeset -i i=$((vmaddr))
		typeset -i value
		while read value; do
			memory[$((i + offset))]=$((value))
			((i++)) || :
		done < <(dump_at $((offset)) $((size)))
	else
		debug "Not loading: ${segname}.${sectname} vmaddr: %x offset: %x\n" \
			$((vmaddr)) $((offset))
	fi
}

function consume_segment_64() {
	declare -ri load_command_cmdsize="$1"

	declare segname=$(consume_string 16)
	declare -ri vmaddr=$(consume_uint64)   # memory address of this segment
	declare -ri vmsize=$(consume_uint64)   # memory size of this segment
	declare -ri fileoff=$(consume_uint64)  # file offset of this segment
	declare -ri filesize=$(consume_uint64) # amount to map from the file

	declare -ri maxprot=$(consume_vmprot_t)  # maximum VM protection
	declare -ri initprot=$(consume_vmprot_t) # initial VM protection
	declare -ri nsects=$(consume_uint32)     # number of sections in segment
	declare -ri flags=$(consume_uint32)      # flags

	debug "SEGMENT: ${segname} vmaddr: %x vmsize: %x" \
		$((vmaddr)) $((vmsize))
	debug "	fileoff: %x filesize: %x maxprot: %x nsects: %x flags: %x" \
		$((fileoff)) $((filesize)) $((maxprot)) $((nsects)) $((flags))
	if [[ ${segname} = "__TEXT" ]]; then
		((GLOBAL_text_vmaddr = vmaddr)) || :
	fi

	declare -i i
	for ((i = 0; i < nsects; i++)); do
		consume_section_64 $((i))
	done
}

function consume_entry_point() {
	declare -ri load_command_cmdsize="$1"
	GLOBAL_entryoff=$(consume_uint64)  # file (__TEXT) offset of main()
	GLOBAL_stacksize=$(consume_uint64) # if not zero, initial stack size
	debug "Found entry point: %x" $((GLOBAL_entryoff))
}

function consume_command() {
	declare -ri load_command_cmd=$(consume_uint32)
	declare -ri load_command_cmdsize=$(consume_uint32)

	declare req_dyld=""

	debug "Command: ${load_command_cmd}: $(command_name "${load_command_cmd}") ${LC_MAIN}"

	case ${load_command_cmd} in
	$((LC_SEGMENT_64)))
		consume_segment_64 $((load_command_cmdsize))
		;;
	$((LC_MAIN)))
		consume_entry_point $((load_command_cmdsize))
		;;
	*)
		consume $((load_command_cmdsize - 8))
		;;
	esac
}

### ELF loader ###

# Reads the whole binary in the `file_bytes` array (declared by the caller),
# one integer per byte. A single hexdump call, no per byte subshell.
function read_file_bytes() {
	# hexdump does not print a trailing newline, so read returns 1 at EOF.
	read -r -a file_bytes < <(hexdump -v -e '/1 "%u "' "${binary_file}") || :
}

# Copies `len` bytes from `filepath` starting at `offset` directly into
# emulated `memory` starting at `dst_addr`, using chunked hexdump + compound
# array assignment for speed on multi-megabyte ELF binaries and shared libs.
function load_file_slice_to_memory() {
	declare -r filepath="$1"
	declare -ri dst_addr="$2" offset="$3" len="$4"
	[[ -n "${memory[@]+x}" ]] || memory=()
	if ((len <= 0)); then
		return
	fi
	declare -ri chunk=512
	declare -i addr=$((dst_addr))
	declare line
	while IFS= read -r line || [[ -n "${line}" ]]; do
		[[ -z "${line}" ]] && continue
		eval "memory+=([${addr}]=${line})"
		((addr += chunk)) || :
	done < <(hexdump -s $((offset)) -n $((len)) -v -e "${chunk}/1 \"%u \" \"\n\"" "${filepath}")
}

# Usage: le_bytes <variable name> <offset> <size>
# Stores the little endian unsigned integer of `size` bytes found at `offset`
# in `file_bytes` in the variable named `variable name`.
# uint64 values >= 2^63 wrap to negative values. YOLO.
function le_bytes() {
	declare -r le_var="$1"
	declare -ri le_offset="$2" le_size="$3"
	declare -i le_value=0 le_i
	((le_offset >= 0 && le_offset + le_size <= ${#file_bytes[@]})) ||
		die "ELF: read of %d bytes at offset 0x%x is out of file bounds" \
			$((le_size)) $((le_offset))
	for ((le_i = le_size - 1; le_i >= 0; le_i--)); do
		((le_value = le_value << 8 | file_bytes[le_offset + le_i])) || :
	done
	printf -v "${le_var}" '%d' $((le_value))
}

# Fast non-subshell little-endian memory accessors for ELF relocation and kernel
# struct population. `elf_mem_read64` sets `mem_val` in the caller's scope.
function elf_mem_read64() {
	declare -ri a="$1"
	((mem_val = memory[a] | memory[a + 1] << 8 | memory[a + 2] << 16 |
		memory[a + 3] << 24 | memory[a + 4] << 32 | memory[a + 5] << 40 |
		memory[a + 6] << 48 | memory[a + 7] << 56)) || :
}

function elf_mem_write64() {
	declare -ri a="$1" v="$2"
	((memory[a] = v & 0xff,
		memory[a + 1] = (v >> 8) & 0xff,
		memory[a + 2] = (v >> 16) & 0xff,
		memory[a + 3] = (v >> 24) & 0xff,
		memory[a + 4] = (v >> 32) & 0xff,
		memory[a + 5] = (v >> 40) & 0xff,
		memory[a + 6] = (v >> 48) & 0xff,
		memory[a + 7] = (v >> 56) & 0xff)) || :
}

function elf_mem_write32() {
	declare -ri a="$1" v="$2"
	((memory[a] = v & 0xff,
		memory[a + 1] = (v >> 8) & 0xff,
		memory[a + 2] = (v >> 16) & 0xff,
		memory[a + 3] = (v >> 24) & 0xff)) || :
}

# Copies `filesz` bytes of the segment from `filepath` at `offset` into memory
# at `vaddr`, and zeroes `.bss` up to `memsz`.
function load_elf_segment() {
	declare -r filepath="$1"
	declare -ri vaddr="$2" offset="$3" filesz="$4" memsz="$5" total_file_size="$6"
	((offset >= 0 && offset + filesz <= total_file_size)) ||
		die "ELF: segment at offset 0x%x (size 0x%x) is out of file bounds" \
			$((offset)) $((filesz))
	((filesz <= memsz)) ||
		die "ELF: segment at 0x%x has p_filesz > p_memsz" $((vaddr))
	debug "ELF: loading segment vaddr: %x offset: %x filesz: %x memsz: %x" \
		$((vaddr)) $((offset)) $((filesz)) $((memsz))
	[[ -n "${memory[@]+x}" ]] || memory=()
	if ((filesz > 0)); then
		load_file_slice_to_memory "${filepath}" $((vaddr)) $((offset)) $((filesz))
	fi
	if ((memsz > filesz)); then
		zero_memory_range $((vaddr + filesz)) $((memsz - filesz))
	fi
}

# Applies an Elf64_Rela table (`DT_RELA` or `DT_JMPREL`) in memory.
function apply_elf_rela_table() {
	declare -ri load_base="$1" e_type="$2" table_addr="$3" table_size="$4"
	declare -ri ent_size="$5" symtab_addr="$6" syment="$7"
	declare -i off r_offset r_info r_addend r_type r_sym target
	declare -i sym_addr st_shndx st_value st_size sym_s mem_val copy_i

	for ((off = 0; off + ent_size <= table_size; off += ent_size)); do
		elf_mem_read64 $((table_addr + off))
		r_offset=$((mem_val))
		elf_mem_read64 $((table_addr + off + 8))
		r_info=$((mem_val))
		elf_mem_read64 $((table_addr + off + 16))
		r_addend=$((mem_val))
		((r_type = r_info & 0xffffffff)) || :
		((r_sym = (r_info >> 32) & 0xffffffff)) || :
		((target = (e_type == ET_DYN ? load_base + r_offset : r_offset))) || :

		sym_s=0
		st_size=0
		if ((r_sym != 0 && symtab_addr != 0)); then
			((sym_addr = symtab_addr + r_sym * syment)) || :
			((st_shndx = memory[sym_addr + 6] | memory[sym_addr + 7] << 8)) || :
			elf_mem_read64 $((sym_addr + 8))
			st_value=$((mem_val))
			elf_mem_read64 $((sym_addr + 16))
			st_size=$((mem_val))
			if ((st_shndx == 0)); then
				sym_s=0
			elif ((st_shndx == 0xfff1)); then
				sym_s=$((st_value))
			else
				((sym_s = (e_type == ET_DYN ? load_base + st_value : st_value))) || :
			fi
		fi

		case $((r_type)) in
		$((R_X86_64_NONE))) ;;
		$((R_X86_64_RELATIVE)))
			elf_mem_write64 $((target)) $((load_base + r_addend))
			;;
		$((R_X86_64_64)) | $((R_X86_64_GLOB_DAT)) | $((R_X86_64_JUMP_SLOT)))
			elf_mem_write64 $((target)) $((sym_s + r_addend))
			;;
		$((R_X86_64_PC32)) | $((R_X86_64_PLT32)))
			elf_mem_write32 $((target)) $(((sym_s + r_addend - target) & 0xffffffff))
			;;
		$((R_X86_64_32)) | $((R_X86_64_32S)))
			elf_mem_write32 $((target)) $(((sym_s + r_addend) & 0xffffffff))
			;;
		$((R_X86_64_COPY)))
			if ((sym_s != 0 && st_size > 0)); then
				for ((copy_i = 0; copy_i < st_size; copy_i++)); do
					((memory[target + copy_i] = memory[sym_s + copy_i])) || :
				done
			fi
			;;
		$((R_X86_64_IRELATIVE)))
			debug "ELF: skipping R_X86_64_IRELATIVE at 0x%x (resolver 0x%x)" \
				$((target)) $((load_base + r_addend))
			;;
		*)
			die "ELF: unsupported relocation type %d at 0x%x" $((r_type)) $((target))
			;;
		esac
	done
}

# Parses PT_DYNAMIC at `dyn_addr` (size `dyn_size`) and applies DT_RELR,
# DT_RELA, and DT_JMPREL relocations for non-PT_INTERP ELF binaries.
function apply_elf_relocations() {
	declare -ri load_base="$1" e_type="$2" dyn_addr="$3" dyn_size="$4"
	declare -i off d_tag d_val mem_val
	declare -i strtab=0 symtab=0 syment=24
	declare -i rela=0 relasz=0 relaent=24 has_rela=0
	declare -i jmprel=0 pltrelsz=0 pltrel=0 has_jmprel=0
	declare -i relr=0 relrsz=0 relrent=8 has_relr=0

	for ((off = 0; off + 16 <= dyn_size; off += 16)); do
		elf_mem_read64 $((dyn_addr + off))
		d_tag=$((mem_val))
		elf_mem_read64 $((dyn_addr + off + 8))
		d_val=$((mem_val))
		((d_tag == DT_NULL)) && break
		case $((d_tag)) in
		$((DT_STRTAB))) strtab=$((d_val)) ;;
		$((DT_SYMTAB))) symtab=$((d_val)) ;;
		$((DT_SYMENT))) syment=$((d_val)) ;;
		$((DT_RELA)))
			rela=$((d_val))
			has_rela=1
			;;
		$((DT_RELASZ))) relasz=$((d_val)) ;;
		$((DT_RELAENT))) relaent=$((d_val)) ;;
		$((DT_PLTREL))) pltrel=$((d_val)) ;;
		$((DT_JMPREL)))
			jmprel=$((d_val))
			has_jmprel=1
			;;
		$((DT_PLTRELSZ))) pltrelsz=$((d_val)) ;;
		$((DT_RELR)))
			relr=$((d_val))
			has_relr=1
			;;
		$((DT_RELRSZ))) relrsz=$((d_val)) ;;
		$((DT_RELRENT))) relrent=$((d_val)) ;;
		esac
	done

	declare -i symtab_addr=0
	if ((symtab != 0)); then
		((symtab_addr = (e_type == ET_DYN ? load_base + symtab : symtab))) || :
	fi
	((syment > 0)) || syment=24
	((relaent > 0)) || relaent=24
	((relrent > 0)) || relrent=8

	# DT_RELR compact relative relocations.
	if ((has_relr && relrsz > 0)); then
		declare -i relr_addr=$((e_type == ET_DYN ? load_base + relr : relr))
		declare -i where=0 entry bitmap b
		for ((off = 0; off + relrent <= relrsz; off += relrent)); do
			elf_mem_read64 $((relr_addr + off))
			entry=$((mem_val))
			if (((entry & 1) == 0)); then
				((where = load_base + entry)) || :
				elf_mem_read64 $((where))
				elf_mem_write64 $((where)) $((mem_val + load_base))
				((where += 8)) || :
			else
				((bitmap = (entry >> 1) & ~(1 << 63))) || :
				for ((b = 0; b < 63 && bitmap != 0; b++, bitmap >>= 1)); do
					if ((bitmap & 1)); then
						elf_mem_read64 $((where + b * 8))
						elf_mem_write64 $((where + b * 8)) $((mem_val + load_base))
					fi
				done
				((where += 63 * 8)) || :
			fi
		done
	fi

	# DT_RELA explicit addend relocations.
	if ((has_rela && relasz > 0)); then
		declare -i rela_addr=$((e_type == ET_DYN ? load_base + rela : rela))
		apply_elf_rela_table $((load_base)) $((e_type)) $((rela_addr)) \
			$((relasz)) $((relaent)) $((symtab_addr)) $((syment))
	fi

	# DT_JMPREL PLT relocations (when using Elf64_Rela).
	if ((has_jmprel && pltrelsz > 0 && (pltrel == DT_RELA || pltrel == 0))); then
		declare -i jmprel_addr=$((e_type == ET_DYN ? load_base + jmprel : jmprel))
		apply_elf_rela_table $((load_base)) $((e_type)) $((jmprel_addr)) \
			$((pltrelsz)) 24 $((symtab_addr)) $((syment))
	fi
}

# Writes the NUL terminated string "$2" at address "$1" in memory.
function put_string() {
	declare -ri address="$1"
	declare -r string="$2"
	declare LC_ALL=C
	declare -i i c
	for ((i = 0; i < ${#string}; i++)); do
		printf -v c '%d' "'${string:i:1}"
		((memory[address + i] = c & 0xff)) || :
	done
	((memory[address + i] = 0)) || :
}

# Builds the initial process stack of the SysV x86_64 ABI below the current
# RSP and points RSP at argc:
#
#   RSP -> argc
#          argv[0] .. argv[argc - 1], NULL
#          envp: NULL (empty environment)
#          auxv: (type, value) pairs terminated by AT_NULL
#          padding, AT_RANDOM bytes, argument strings.
#
# Usage: setup_linux_stack <entry> <phdr address> <phentsize> <phnum> [argv...]
# Optional caller variable `elf_at_base` sets AT_BASE (0 if unset).
function setup_linux_stack() {
	declare -ri entry="$1" phdr="$2" phentsize="$3" phnum="$4"
	shift 4
	declare -a args=("$@")
	declare -ri argc=$#
	declare -i sp=$((registers[RSP]))
	declare -ia argv_ptrs=()
	declare -i i

	[[ -n "${memory[@]+x}" ]] || memory=()

	# Argument strings, last one first so that argv[0] ends up lowest.
	for ((i = argc - 1; i >= 0; i--)); do
		((sp -= ${#args[i]} + 1)) || :
		put_string $((sp)) "${args[i]}"
		argv_ptrs[i]=$((sp))
	done
	declare -ri execfn=$((argc > 0 ? argv_ptrs[0] : 0))

	# 16 "random" bytes for AT_RANDOM (used by libc for stack canaries).
	((sp = (sp - 16) & ~0xf)) || :
	declare -ri random=$((sp))
	for ((i = 0; i < 16; i++)); do
		((memory[random + i] = RANDOM & 0xff)) || :
	done

	declare -ria auxv=(
		$((AT_PHDR)) $((phdr))
		$((AT_PHENT)) $((phentsize))
		$((AT_PHNUM)) $((phnum))
		$((AT_PAGESZ)) 4096
		$((AT_BASE)) $((${elf_at_base:-0}))
		$((AT_ENTRY)) $((entry))
		$((AT_UID)) ${UID}
		$((AT_EUID)) ${EUID}
		$((AT_GID)) ${GROUPS[0]:-0}
		$((AT_EGID)) ${GROUPS[0]:-0}
		$((AT_RANDOM)) $((random))
		$((AT_EXECFN)) $((execfn))
		$((AT_NULL)) 0
	)
	# argc + argv + argv NULL + envp NULL + auxv
	declare -ri nwords=$((1 + argc + 1 + 1 + ${#auxv[@]}))
	# RSP must be 16 byte aligned at process entry.
	((sp = (sp - nwords * 8) & ~0xf)) || :
	registers[RSP]=$((sp))

	set_memory 8 $((sp)) $((argc))
	((sp += 8)) || :
	for ((i = 0; i < argc; i++)); do
		set_memory 8 $((sp)) $((argv_ptrs[i]))
		((sp += 8)) || :
	done
	set_memory 8 $((sp)) 0 # argv NULL
	((sp += 8)) || :
	set_memory 8 $((sp)) 0 # envp NULL
	((sp += 8)) || :
	for ((i = 0; i < ${#auxv[@]}; i++)); do
		set_memory 8 $((sp)) $((auxv[i]))
		((sp += 8)) || :
	done
	debug "ELF: stack set up, RSP: %x argc: %d" $((registers[RSP])) $((argc))
}

# Maps an ELF64 x86_64 image (`elf_path`) into emulated memory, using `dyn_base`
# if the image is ET_DYN. Populates caller variables:
#   img_e_type, img_e_entry, img_e_phentsize, img_e_phnum,
#   img_load_base, img_phdr_addr, img_text_vmaddr, img_end,
#   img_dyn_addr, img_dyn_size, img_interp_path
function load_elf_image() {
	declare -r elf_path="$1"
	declare -ri dyn_base="$2"
	[[ -r "${elf_path}" ]] || die "ELF: cannot read '%s'" "${elf_path}"

	declare -i img_file_size
	img_file_size=$(wc -c <"${elf_path}")
	((img_file_size >= 64)) || die "ELF: file too small"

	declare -a file_bytes=()
	read -r -a file_bytes < <(hexdump -n 64 -v -e '/1 "%u "' "${elf_path}") || :
	((${#file_bytes[@]} >= 64)) || die "ELF: file too small"
	((file_bytes[0] == 0x7f && file_bytes[1] == 0x45 &&
		file_bytes[2] == 0x4c && file_bytes[3] == 0x46)) ||
		die "ELF: can't find magic number"
	((file_bytes[4] == ELFCLASS64)) ||
		die "ELF: only 64 bit (ELFCLASS64) binaries are supported"
	((file_bytes[5] == ELFDATA2LSB)) ||
		die "ELF: only little endian binaries are supported"

	declare -i e_machine e_phoff
	le_bytes img_e_type 16 2
	le_bytes e_machine 18 2
	le_bytes img_e_entry 24 8
	le_bytes e_phoff 32 8
	le_bytes img_e_phentsize 54 2
	le_bytes img_e_phnum 56 2

	((e_machine == EM_X86_64)) ||
		die "ELF: unsupported machine %d, only x86_64 (%d) is supported" \
			$((e_machine)) $((EM_X86_64))

	img_load_base=0
	case $((img_e_type)) in
	$((ET_EXEC))) ;;
	$((ET_DYN)))
		img_load_base=$((dyn_base))
		;;
	*)
		die "ELF: unsupported type %d, not an executable" $((img_e_type))
		;;
	esac

	((img_e_phnum > 0)) || die "ELF: no program headers"
	((img_e_phentsize >= 56)) || die "ELF: invalid e_phentsize %d" $((img_e_phentsize))
	declare -ri ph_table_size=$((img_e_phnum * img_e_phentsize))
	((e_phoff >= 0 && e_phoff + ph_table_size <= img_file_size)) ||
		die "ELF: program headers are out of file bounds"

	file_bytes=()
	read -r -a file_bytes < <(hexdump -s $((e_phoff)) -n $((ph_table_size)) -v -e '/1 "%u "' "${elf_path}") || :

	img_phdr_addr=0
	img_text_vmaddr=-1
	img_end=0
	img_dyn_addr=0
	img_dyn_size=0
	img_interp_path=""
	declare -i has_interp=0

	declare -i i ph p_type p_flags p_offset p_vaddr p_filesz p_memsz
	for ((i = 0; i < img_e_phnum; i++)); do
		((ph = i * img_e_phentsize)) || :
		le_bytes p_type $((ph)) 4
		le_bytes p_flags $((ph + 4)) 4
		le_bytes p_offset $((ph + 8)) 8
		le_bytes p_vaddr $((ph + 16)) 8
		le_bytes p_filesz $((ph + 32)) 8
		le_bytes p_memsz $((ph + 40)) 8
		debug "ELF: program header type: %x flags: %x offset: %x vaddr: %x filesz: %x memsz: %x" \
			$((p_type)) $((p_flags)) $((p_offset)) $((p_vaddr)) $((p_filesz)) $((p_memsz))
		case $((p_type)) in
		$((PT_LOAD)))
			load_elf_segment "${elf_path}" $((img_load_base + p_vaddr)) \
				$((p_offset)) $((p_filesz)) $((p_memsz)) $((img_file_size))
			if ((img_load_base + p_vaddr + p_memsz > img_end)); then
				((img_end = img_load_base + p_vaddr + p_memsz)) || :
			fi
			if ((p_flags & 0x1 && img_text_vmaddr < 0)); then
				((img_text_vmaddr = img_load_base + p_vaddr)) || :
			fi
			if ((img_phdr_addr == 0 && e_phoff >= p_offset &&
				e_phoff < p_offset + p_filesz)); then
				((img_phdr_addr = img_load_base + p_vaddr + e_phoff - p_offset)) || :
			fi
			;;
		$((PT_PHDR)))
			((img_phdr_addr = img_load_base + p_vaddr)) || :
			;;
		$((PT_DYNAMIC)))
			((img_dyn_addr = img_load_base + p_vaddr)) || :
			((img_dyn_size = p_memsz > 0 ? p_memsz : p_filesz)) || :
			;;
		$((PT_INTERP)))
			((p_offset >= 0 && p_filesz > 0 && p_offset + p_filesz <= img_file_size)) ||
				die "ELF: invalid PT_INTERP segment"
			has_interp=1
			declare -a interp_bytes=()
			declare -i ib
			declare escaped="" ch
			read -r -a interp_bytes < <(hexdump -s $((p_offset)) -n $((p_filesz)) -v -e '/1 "%u "' "${elf_path}") || :
			for ((ib = 0; ib < ${#interp_bytes[@]}; ib++)); do
				((interp_bytes[ib] == 0)) && break
				printf -v ch '\\x%02x' $((interp_bytes[ib] & 0xff))
				escaped+="${ch}"
			done
			if [[ -n "${escaped}" ]]; then
				printf -v img_interp_path '%b' "${escaped}"
			fi
			[[ -n "${img_interp_path}" ]] || die "ELF: empty PT_INTERP path"
			;;
		esac
	done

	if ((has_interp)) && [[ ! -f "${img_interp_path}" || ! -r "${img_interp_path}" ]]; then
		die "ELF: cannot read PT_INTERP interpreter '%s'" "${img_interp_path}"
	fi
	((img_text_vmaddr >= 0)) || die "ELF: no executable PT_LOAD segment"
}

# Loads a static, static-pie, or dynamically linked (PT_INTERP) Linux ELF64
# x86_64 executable from `binary_file`. Arguments are the guest argv (argv[0]
# included).
function load_elf_file() {
	declare -i img_e_type=0 img_e_entry=0 img_e_phentsize=0 img_e_phnum=0
	declare -i img_load_base=0 img_phdr_addr=0 img_text_vmaddr=-1 img_end=0
	declare -i img_dyn_addr=0 img_dyn_size=0
	declare img_interp_path=""

	load_elf_image "${binary_file}" $((ELF_DYN_BASE))

	declare -ri main_e_type=$((img_e_type))
	declare -ri main_load_base=$((img_load_base))
	declare -ri main_entry=$((img_load_base + img_e_entry))
	declare -ri main_phdr_addr=$((img_phdr_addr))
	declare -ri main_phentsize=$((img_e_phentsize))
	declare -ri main_phnum=$((img_e_phnum))
	declare -ri main_text_vmaddr=$((img_text_vmaddr))
	declare -ri main_image_end=$((img_end))
	declare -ri main_dyn_addr=$((img_dyn_addr))
	declare -ri main_dyn_size=$((img_dyn_size))
	declare -r interp_path="${img_interp_path}"

	declare -i elf_at_base=0
	declare -i start_entry=$((main_entry))
	declare -i start_text_vmaddr=$((main_text_vmaddr))

	if [[ -n "${interp_path}" ]]; then
		# Dynamically linked binary: load the PT_INTERP dynamic linker and let
		# _dl_start relocate both itself and the main executable.
		debug "ELF: loading PT_INTERP interpreter '%s' at 0x%x" \
			"${interp_path}" $((ELF_INTERP_BASE))
		load_elf_image "${interp_path}" $((ELF_INTERP_BASE))
		elf_at_base=$((img_load_base))
		start_entry=$((img_load_base + img_e_entry))
		start_text_vmaddr=$((img_text_vmaddr))
	elif ((main_dyn_addr != 0 && main_dyn_size > 0)); then
		# Static-PIE / ET_DYN without PT_INTERP: apply loader relocations now.
		apply_elf_relocations $((main_load_base)) $((main_e_type)) \
			$((main_dyn_addr)) $((main_dyn_size))
	fi

	GLOBAL_os_abi="linux"
	# Page aligned end of the main executable image.
	((GLOBAL_linux_brk_start = (main_image_end + 0xfff) & ~0xfff)) || :
	# run() starts at GLOBAL_text_vmaddr + GLOBAL_entryoff.
	((GLOBAL_text_vmaddr = start_text_vmaddr)) || :
	((GLOBAL_entryoff = start_entry - start_text_vmaddr)) || :
	debug "ELF: entry point: %x (AT_ENTRY: %x, AT_BASE: %x)" \
		$((start_entry)) $((main_entry)) $((elf_at_base))

	if ((registers[RSP] == 0x10000)); then
		registers[RSP]=$((LINUX_INITIAL_RSP))
	fi
	setup_linux_stack $((main_entry)) $((main_phdr_addr)) \
		$((main_phentsize)) $((main_phnum)) "$@"
}

### Instruction decoding and execution ###
#
# Conventions used by the helpers below (we use bash dynamic scoping a lot):
# * Values of 1, 2 and 4 bytes are kept zero-extended. 8 byte values are kept
#   as (signed) bash integers, the bit pattern is what matters.
# * Helpers avoid subshells ($(...)) for speed. They return values by setting
#   well known variables: `val` (operand values), `cond` (condition codes),
#   `displacement` (immediates and displacements), `modrm_*` (decoded operands).
# * `rip` points to the first byte of the current instruction while it
#   executes, `advance` is the number of bytes consumed so far. Branches
#   modify `advance` so that `rip += advance` lands on the target.

function unknown_insruction() {
	declare instruction="$1"
	declare msg="$2"
	die "Unknown instruction at 0x%x: ${instruction} (${msg})\n" $((rip))
}

# Unsigned 64-bit comparisons. Bash integers are signed, flipping the sign bit
# turns an unsigned comparison into a signed one.
function ult() {
	(((($1) ^ INT64_MIN) < (($2) ^ INT64_MIN)))
}

function ule() {
	(((($1) ^ INT64_MIN) <= (($2) ^ INT64_MIN)))
}

# Sets `val` to `value` (of `width` bytes) sign-extended to 64 bits.
function sign_extend() {
	declare -ri width="$1" value="$2"
	case $((width)) in
	1) ((val = ((value & 0xff) ^ 0x80) - 0x80)) || : ;;
	2) ((val = ((value & 0xffff) ^ 0x8000) - 0x8000)) || : ;;
	4) ((val = ((value & 0xffffffff) ^ 0x80000000) - 0x80000000)) || : ;;
	*) ((val = value)) || : ;;
	esac
}

# Modifies variables `displacement` and `advance`
function disp64() {
	declare -ri a=$((rip + advance))
	((displacement = memory[a] | memory[a + 1] << 8 | memory[a + 2] << 16 |
		memory[a + 3] << 24 | memory[a + 4] << 32 | memory[a + 5] << 40 |
		memory[a + 6] << 48 | memory[a + 7] << 56)) || :
	((advance += 8)) || :
}

# Modifies variables `displacement` and `advance`. Sign-extended.
function disp32() {
	declare -ri a=$((rip + advance))
	((displacement = memory[a] | memory[a + 1] << 8 | memory[a + 2] << 16 | memory[a + 3] << 24)) || :
	((displacement = (displacement ^ 0x80000000) - 0x80000000)) || :
	((advance += 4)) || :
}

# Modifies variables `displacement` and `advance`. Sign-extended.
function disp16() {
	declare -ri a=$((rip + advance))
	((displacement = ((memory[a] | memory[a + 1] << 8) ^ 0x8000) - 0x8000)) || :
	((advance += 2)) || :
}

# Modifies variables `displacement` and `advance`. Sign-extended.
function disp8() {
	((displacement = (memory[rip + advance] ^ 0x80) - 0x80)) || :
	((advance += 1)) || :
}

# Modifies variables `displacement` and `advance`
function disp_width() {
	declare -i width="$1"
	case $((width)) in
	$((WIDTH8))) disp8 ;;
	$((WIDTH16))) disp16 ;;
	$((WIDTH32))) disp32 ;;
	$((WIDTH64))) disp64 ;;
	*) die "Invalid width for immediate value or displacement." ;;
	esac
}

# Sets modrm_mod modrm_reg modrm_rm modrm_address.
# Reads SIB and displacement bytes at rip + advance and updates `advance`.
# `imm_size` is the number of immediate bytes that follow the modrm operand:
# RIP-relative addresses are relative to the end of the instruction.
function operands_modrm() {
	declare -i modrm="$1"
	declare -i imm_size="${2:-0}"
	declare -i displacement=0 sib base index
	((modrm_mod = modrm >> 6 & 0x3)) || :
	((modrm_reg = (modrm >> 3) & 0x7 | rex_r << 3)) || :
	((modrm_rm = (modrm) & 0x7 | rex_b << 3)) || :
	modrm_address=0

	if ((modrm_mod == 3)); then
		return 0
	fi

	if (((modrm & 0x7) == 4)); then
		# SIB byte
		((sib = memory[rip + advance])) || :
		((advance++)) || :
		((index = (sib >> 3) & 0x7 | rex_x << 3)) || :
		((base = sib & 0x7 | rex_b << 3)) || :
		if (((sib & 0x7) == 5 && modrm_mod == 0)); then
			# No base register, disp32 only.
			disp32
			((modrm_address = displacement)) || :
		else
			((modrm_address = registers[base])) || :
		fi
		# index 4 (rsp) means no index. r12 (with REX.X) is a valid index.
		if ((index != RSP)); then
			((modrm_address += registers[index] << (sib >> 6 & 0x3))) || :
		fi
	elif (((modrm & 0x7) == 5 && modrm_mod == 0)); then
		# RIP addressing, relative to the address of the next instruction.
		disp32
		((modrm_address = rip + advance + imm_size + displacement)) || :
		return 0
	else
		((modrm_address = registers[modrm_rm])) || :
	fi

	case $((modrm_mod)) in
	1)
		disp8
		((modrm_address += displacement)) || :
		;;
	2)
		disp32
		((modrm_address += displacement)) || :
		;;
	esac
}

# Sets `val` to the zero-extended value of register `reg` of `width` bytes.
# Byte registers 4-7 are AH, CH, DH, BH unless a REX prefix is present.
function read_reg() {
	declare -ri width="$1" reg="$2"
	case $((width)) in
	1)
		if ((reg >= 4 && reg < 8 && !rex)); then
			((val = (registers[reg - 4] >> 8) & 0xff)) || :
		else
			((val = registers[reg] & 0xff)) || :
		fi
		;;
	2) ((val = registers[reg] & 0xffff)) || : ;;
	4) ((val = registers[reg] & 0xffffffff)) || : ;;
	8) ((val = registers[reg])) || : ;;
	*) die "Unsupported data width in read_reg: ${width}" ;;
	esac
}

# Writes register `reg`. 32-bit writes zero the upper half of the register,
# 8 and 16-bit writes preserve the other bits.
function write_reg() {
	declare -ri width="$1" reg="$2" value="$3"
	case $((width)) in
	1)
		if ((reg >= 4 && reg < 8 && !rex)); then
			((registers[reg - 4] = registers[reg - 4] & ~0xff00 | (value & 0xff) << 8)) || :
		else
			((registers[reg] = registers[reg] & ~0xff | (value & 0xff))) || :
		fi
		;;
	2) ((registers[reg] = registers[reg] & ~0xffff | (value & 0xffff))) || : ;;
	4) ((registers[reg] = value & 0xffffffff)) || : ;;
	8) ((registers[reg] = value)) || : ;;
	*) die "Unsupported data width in write_reg: ${width}" ;;
	esac
}

# Sets `val` to the little endian value of `width` bytes at `address`.
function read_mem() {
	declare -ri width="$1" a="$2"
	case $((width)) in
	1) ((val = memory[a])) || : ;;
	2) ((val = memory[a] | memory[a + 1] << 8)) || : ;;
	4) ((val = memory[a] | memory[a + 1] << 8 | memory[a + 2] << 16 | memory[a + 3] << 24)) || : ;;
	8)
		((val = memory[a] | memory[a + 1] << 8 | memory[a + 2] << 16 |
			memory[a + 3] << 24 | memory[a + 4] << 32 | memory[a + 5] << 40 |
			memory[a + 6] << 48 | memory[a + 7] << 56)) || :
		;;
	*) die "Unsupported data width in read_mem: ${width}" ;;
	esac
}

function write_mem() {
	declare -ri width="$1" a="$2" value="$3"
	declare -i i
	for ((i = 0; i < width; i++)); do
		((memory[a + i] = (value >> (8 * i)) & 0xff)) || :
	done
}

# Read/write the r/m operand decoded by operands_modrm.
function read_rm() {
	if ((modrm_mod == 3)); then
		read_reg "$1" $((modrm_rm))
	else
		read_mem "$1" $((modrm_address))
	fi
}

function write_rm() {
	if ((modrm_mod == 3)); then
		write_reg "$1" $((modrm_rm)) "$2"
	else
		write_mem "$1" $((modrm_address)) "$2"
	fi
}

function push64() {
	((registers[RSP] -= 8)) || :
	write_mem 8 $((registers[RSP])) "$1"
}

# Sets `val`
function pop64() {
	read_mem 8 $((registers[RSP]))
	((registers[RSP] += 8)) || :
}

### Flags ###

# Sets ZF, SF and PF from `result` of `width` bytes.
function set_result_flags() {
	declare -ri width="$1" result="$2"
	((flag_zf = result == 0)) || :
	((flag_sf = result >> (width * 8 - 1) & 1)) || :
	((flag_pf = parity_table[result & 0xff])) || :
}

# Returns RFLAGS as an integer.
function get_rflags() {
	echo $((flag_cf | flag_pf << 2 | flag_af << 4 | flag_zf << 6 | flag_sf << 7 |
		flag_df << 10 | flag_of << 11 | 0x2))
}

# Sets `cond` to 1 when condition code `cc` (low nibble of jcc/setcc/cmovcc
# opcodes) holds, 0 otherwise.
function eval_cond() {
	declare -ri cc="$1"
	case $(((cc >> 1) & 7)) in
	0) ((cond = flag_of)) || : ;;                        # o
	1) ((cond = flag_cf)) || : ;;                        # b/c/nae
	2) ((cond = flag_zf)) || : ;;                        # e/z
	3) ((cond = flag_cf | flag_zf)) || : ;;              # be/na
	4) ((cond = flag_sf)) || : ;;                        # s
	5) ((cond = flag_pf)) || : ;;                        # p/pe
	6) ((cond = flag_sf != flag_of)) || : ;;             # l/nge
	7) ((cond = flag_zf | (flag_sf != flag_of))) || : ;; # le/ng
	esac
	((cond ^= cc & 1)) || :
}

# Arithmetic/logic operation number `op` as encoded in opcodes 00-3F and
# group 1 (0=add 1=or 2=adc 3=sbb 4=and 5=sub 6=xor 7=cmp) on zero-extended
# operands `a` and `b` of `width` bytes. Sets `val` and the flags.
function alu() {
	declare -ri op="$1" width="$2" a="$3" b="$4"
	declare -i r mask sbit carry=0
	((mask = width == 8 ? -1 : (1 << (width * 8)) - 1)) || :
	((sbit = width * 8 - 1)) || :
	case $((op)) in
	0 | 2)
		if ((op == 2)); then ((carry = flag_cf)) || :; fi
		((r = (a + b + carry) & mask)) || :
		if ((carry)); then
			((flag_cf = (r ^ INT64_MIN) <= (a ^ INT64_MIN))) || :
		else
			((flag_cf = (r ^ INT64_MIN) < (a ^ INT64_MIN))) || :
		fi
		((flag_of = ((a ^ r) & (b ^ r)) >> sbit & 1)) || :
		;;
	3 | 5 | 7)
		if ((op == 3)); then ((carry = flag_cf)) || :; fi
		((r = (a - b - carry) & mask)) || :
		if ((carry)); then
			((flag_cf = (a ^ INT64_MIN) <= (b ^ INT64_MIN))) || :
		else
			((flag_cf = (a ^ INT64_MIN) < (b ^ INT64_MIN))) || :
		fi
		((flag_of = ((a ^ b) & (a ^ r)) >> sbit & 1)) || :
		;;
	1) ((r = a | b, flag_cf = 0, flag_of = 0)) || : ;;
	4) ((r = a & b, flag_cf = 0, flag_of = 0)) || : ;;
	6) ((r = (a ^ b) & mask, flag_cf = 0, flag_of = 0)) || : ;;
	esac
	((flag_af = ((a ^ b ^ r) >> 4) & 1)) || :
	set_result_flags $((width)) $((r))
	((val = r)) || :
}

# Shift/rotate operation number `op` as encoded in group 2 (0=rol 1=ror
# 2=rcl 3=rcr 4=shl 5=shr 6=sal 7=sar) of `a` by `count`. Sets `val` and flags.
function shift_op() {
	declare -ri op="$1" width="$2" a="$3"
	declare -i count="$4"
	declare -i r=0 mask bits n s i msb
	((bits = width * 8)) || :
	((mask = width == 8 ? -1 : (1 << bits) - 1)) || :
	((count &= width == 8 ? 0x3f : 0x1f)) || :
	if ((count == 0)); then
		((val = a)) || :
		return 0
	fi
	case $((op)) in
	0) # rol
		((n = count % bits)) || :
		if ((n == 0)); then
			((r = a)) || :
		else
			((r = (a << n | (a >> (bits - n)) & ~(-1 << n)) & mask)) || :
		fi
		((flag_cf = r & 1)) || :
		((flag_of = (r >> (bits - 1) & 1) ^ flag_cf)) || :
		;;
	1) # ror
		((n = count % bits)) || :
		if ((n == 0)); then
			((r = a)) || :
		else
			((r = ((a >> n) & ~(-1 << (bits - n)) | a << (bits - n)) & mask)) || :
		fi
		((flag_cf = r >> (bits - 1) & 1)) || :
		((flag_of = flag_cf ^ (r >> (bits - 2) & 1))) || :
		;;
	2 | 3) # rcl, rcr: one bit at a time, through the carry flag.
		if ((width < 4)); then ((count %= bits + 1)) || :; fi
		((r = a)) || :
		for ((i = 0; i < count; i++)); do
			if ((op == 2)); then
				((msb = r >> (bits - 1) & 1)) || :
				((r = (r << 1 | flag_cf) & mask)) || :
				((flag_cf = msb)) || :
			else
				((msb = r & 1)) || :
				((r = ((r >> 1) & ~(-1 << (bits - 1)) | flag_cf << (bits - 1)) & mask)) || :
				((flag_cf = msb)) || :
			fi
		done
		((flag_of = (r >> (bits - 1) & 1) ^ (op == 2 ? flag_cf : (r >> (bits - 2) & 1)))) || :
		;;
	4 | 6) # shl/sal
		if ((count > bits)); then
			((r = 0, flag_cf = 0)) || :
		else
			((r = (count == 64 ? 0 : a << count) & mask)) || :
			((flag_cf = (a >> (bits - count)) & 1)) || :
		fi
		((flag_of = (r >> (bits - 1) & 1) ^ flag_cf)) || :
		set_result_flags $((width)) $((r))
		;;
	5) # shr
		((r = (a >> count) & ~(-1 << (64 - count)) & mask)) || :
		((flag_cf = (a >> (count - 1)) & 1)) || :
		((flag_of = a >> (bits - 1) & 1)) || :
		set_result_flags $((width)) $((r))
		;;
	7) # sar
		sign_extend $((width)) $((a))
		((s = val)) || :
		((r = (s >> count) & mask)) || :
		((flag_cf = (s >> (count - 1)) & 1)) || :
		((flag_of = 0)) || :
		set_result_flags $((width)) $((r))
		;;
	esac
	((val = r)) || :
}

# shld (left=1) / shrd (left=0) of `dest` by `count`, shifting in bits from
# `src`. Sets `val` and flags.
function double_shift() {
	declare -ri left="$1" width="$2" dest="$3" src="$4"
	declare -i count="$5" bits mask r
	((bits = width * 8)) || :
	((mask = width == 8 ? -1 : (1 << bits) - 1)) || :
	((count &= width == 8 ? 0x3f : 0x1f)) || :
	if ((count == 0)); then
		((val = dest)) || :
		return 0
	fi
	if ((count > bits)); then
		# Undefined result (16-bit operands only); keep it simple.
		((count = bits)) || :
	fi
	if ((left)); then
		((r = ((count == 64 ? 0 : dest << count) | (src >> (bits - count)) & ~(-1 << count)) & mask)) || :
		((flag_cf = (dest >> (bits - count)) & 1)) || :
	else
		((r = ((dest >> count) & ~(-1 << (64 - count)) | (count == 64 ? 0 : src << (bits - count))) & mask)) || :
		((flag_cf = (dest >> (count - 1)) & 1)) || :
	fi
	((flag_of = ((r ^ dest) >> (bits - 1)) & 1)) || :
	set_result_flags $((width)) $((r))
	((val = r)) || :
}

# Full unsigned 64x64 -> 128 bit multiplication. Sets `prod_lo` and `prod_hi`.
function mul64u() {
	declare -ri a="$1" b="$2"
	declare -ri m32=0xffffffff
	declare -i al ah bl bh ll lh hl hh mid
	((al = a & m32, ah = (a >> 32) & m32, bl = b & m32, bh = (b >> 32) & m32)) || :
	((ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh)) || :
	((mid = ((ll >> 32) & m32) + (lh & m32) + (hl & m32))) || :
	((prod_lo = (ll & m32) | mid << 32)) || :
	((prod_hi = hh + ((lh >> 32) & m32) + ((hl >> 32) & m32) + ((mid >> 32) & m32))) || :
}

# Signed multiplication of `a` and `b` of `width` bytes. Sets `prod_lo` (the
# truncated result, zero-extended), `prod_hi` (the upper half) and CF/OF when
# the result does not fit in `width` bytes.
function imul_op() {
	declare -ri width="$1"
	declare -i a b r mask
	sign_extend $((width)) "$2"
	((a = val)) || :
	sign_extend $((width)) "$3"
	((b = val)) || :
	if ((width == 8)); then
		mul64u $((a)) $((b))
		((prod_hi -= (a < 0 ? b : 0) + (b < 0 ? a : 0))) || :
		((flag_cf = prod_hi != (prod_lo >> 63))) || :
	else
		((mask = (1 << (width * 8)) - 1)) || :
		((r = a * b)) || :
		((prod_lo = r & mask, prod_hi = (r >> (width * 8)) & mask)) || :
		sign_extend $((width)) $((prod_lo))
		((flag_cf = val != r)) || :
	fi
	((flag_of = flag_cf)) || :
	set_result_flags $((width)) $((prod_lo))
}

# Unsigned division of the 128 bit value hi:lo by `d`, requires hi < d
# (unsigned). Sets `quotient` and `remainder`.
function udiv128() {
	declare -i rem="$1"
	declare -ri lo="$2" d="$3"
	declare -i q=0 i top
	for ((i = 63; i >= 0; i--)); do
		((top = rem < 0)) || :
		((rem = rem << 1 | ((lo >> i) & 1))) || :
		((q <<= 1)) || :
		if ((top || (rem ^ INT64_MIN) >= (d ^ INT64_MIN))); then
			((rem -= d, q |= 1)) || :
		fi
	done
	((quotient = q, remainder = rem)) || :
}

function divide_error() {
	die "Divide error (#DE) at 0x%x" $((rip))
}

# mul/imul/div/idiv with implicit rAX/rDX operands (group 3 /4 - /7).
function inst_muldiv() {
	declare -ri op="$1" width="$2" src="$3"
	declare -i a n d q r hi lo neg quotient remainder prod_lo prod_hi
	case $((op)) in
	4) # mul
		read_reg $((width)) $((RAX))
		((a = val)) || :
		case $((width)) in
		1)
			((r = a * src)) || :
			write_reg 2 $((RAX)) $((r))
			((flag_cf = r >> 8 != 0)) || :
			((prod_lo = r & 0xff)) || :
			;;
		2 | 4)
			((r = a * src)) || :
			((prod_lo = r & ((1 << (width * 8)) - 1))) || :
			((prod_hi = (r >> (width * 8)) & ((1 << (width * 8)) - 1))) || :
			write_reg $((width)) $((RAX)) $((prod_lo))
			write_reg $((width)) $((RDX)) $((prod_hi))
			((flag_cf = prod_hi != 0)) || :
			;;
		8)
			mul64u $((a)) $((src))
			write_reg 8 $((RAX)) $((prod_lo))
			write_reg 8 $((RDX)) $((prod_hi))
			((flag_cf = prod_hi != 0)) || :
			;;
		esac
		((flag_of = flag_cf)) || :
		set_result_flags $((width)) $((prod_lo))
		;;
	5) # imul
		read_reg $((width)) $((RAX))
		imul_op $((width)) $((val)) $((src))
		if ((width == 1)); then
			write_reg 2 $((RAX)) $((prod_hi << 8 | prod_lo))
		else
			write_reg $((width)) $((RAX)) $((prod_lo))
			write_reg $((width)) $((RDX)) $((prod_hi))
		fi
		;;
	6) # div
		((src == 0)) && divide_error
		case $((width)) in
		1)
			read_reg 2 $((RAX))
			((q = val / src, r = val % src)) || :
			((q > 0xff)) && divide_error
			write_reg 2 $((RAX)) $((r << 8 | q))
			;;
		2 | 4)
			read_reg $((width)) $((RDX))
			((n = val << (width * 8))) || :
			read_reg $((width)) $((RAX))
			((n |= val)) || :
			if ((n >= 0)); then
				((q = n / src, r = n % src)) || :
			else
				udiv128 0 $((n)) $((src))
				((q = quotient, r = remainder)) || :
			fi
			((q >> (width * 8))) && divide_error
			write_reg $((width)) $((RAX)) $((q))
			write_reg $((width)) $((RDX)) $((r))
			;;
		8)
			((hi = registers[RDX], lo = registers[RAX])) || :
			ule $((src)) $((hi)) && divide_error
			if ((hi == 0 && lo >= 0 && src > 0)); then
				((q = lo / src, r = lo % src)) || :
			else
				udiv128 $((hi)) $((lo)) $((src))
				((q = quotient, r = remainder)) || :
			fi
			write_reg 8 $((RAX)) $((q))
			write_reg 8 $((RDX)) $((r))
			;;
		esac
		;;
	7) # idiv
		sign_extend $((width)) $((src))
		((d = val)) || :
		((d == 0)) && divide_error
		case $((width)) in
		1 | 2 | 4)
			if ((width == 1)); then
				read_reg 2 $((RAX))
				sign_extend 2 $((val))
				((n = val)) || :
			else
				read_reg $((width)) $((RDX))
				((n = val << (width * 8))) || :
				read_reg $((width)) $((RAX))
				sign_extend $((width * 2)) $((n | val))
				((n = val)) || :
			fi
			((q = n / d, r = n % d)) || :
			sign_extend $((width)) $((q))
			((val != q || (n == INT64_MIN && d == -1))) && divide_error
			if ((width == 1)); then
				write_reg 2 $((RAX)) $(((r & 0xff) << 8 | (q & 0xff)))
			else
				write_reg $((width)) $((RAX)) $((q))
				write_reg $((width)) $((RDX)) $((r))
			fi
			;;
		8)
			((hi = registers[RDX], lo = registers[RAX])) || :
			if ((hi == lo >> 63)); then
				((lo == INT64_MIN && d == -1)) && divide_error
				((q = lo / d, r = lo % d)) || :
			else
				# 128 bit signed dividend: divide magnitudes.
				((neg = hi < 0)) || :
				if ((neg)); then
					((hi = ~hi + (lo == 0), lo = -lo)) || :
				fi
				((n = d < 0 ? -d : d)) || :
				ule $((n)) $((hi)) && divide_error
				udiv128 $((hi)) $((lo)) $((n))
				((q = quotient, r = remainder)) || :
				if ((neg ^ (d < 0))); then
					ult $((INT64_MIN)) $((q)) && divide_error
					((q = -q)) || :
				else
					((q < 0)) && divide_error
				fi
				if ((neg)); then ((r = -r)) || :; fi
			fi
			write_reg 8 $((RAX)) $((q))
			write_reg 8 $((RDX)) $((r))
			;;
		esac
		;;
	esac
	return 0
}

# Instructions with a modrm operand and a register operand (00-3B families,
# 84/85 test). The operation is encoded in the opcode.
function inst_binary_op() {
	declare -ri binary_instruction="$1"
	declare -ri modrm="$2"
	declare -ri direction=$(((binary_instruction >> 1) & 0x1))
	declare -ri width_is_byte=$((~binary_instruction & 0x1))
	declare -i op=$(((binary_instruction >> 3) & 0x7))
	declare -i width a b
	((width = width_is_byte ? WIDTH8 : rex_w ? WIDTH64 : operand_size_prefix ? WIDTH16 : WIDTH32)) || :

	declare -i modrm_mod modrm_reg modrm_rm modrm_address
	operands_modrm $((modrm))

	read_rm $((width))
	((a = val)) || :
	read_reg $((width)) $((modrm_reg))
	((b = val)) || :
	if (((binary_instruction & 0xfe) == 0x84)); then
		alu 4 $((width)) $((a)) $((b)) # test
		return 0
	fi
	if ((direction)); then
		alu $((op)) $((width)) $((b)) $((a))
		((op == 7)) || write_reg $((width)) $((modrm_reg)) $((val))
	else
		alu $((op)) $((width)) $((a)) $((b))
		((op == 7)) || write_rm $((width)) $((val))
	fi
	return 0
}

# 88-8B
function inst_mov() {
	declare -ri mov="$1"
	declare -ri modrm="$2"
	declare -ri direction=$(((mov >> 1) & 0x1))
	declare -ri width_is_byte=$((~mov & 0x1))
	declare -i width
	((width = width_is_byte ? WIDTH8 : rex_w ? WIDTH64 : operand_size_prefix ? WIDTH16 : WIDTH32)) || :

	declare -i modrm_mod modrm_reg modrm_rm modrm_address
	operands_modrm $((modrm))

	if ((direction)); then
		read_rm $((width))
		write_reg $((width)) $((modrm_reg)) $((val))
	else
		read_reg $((width)) $((modrm_reg))
		write_rm $((width)) $((val))
	fi
}

function inst_lea() {
	declare -i lea="$1"
	declare -i modrm="$2"
	declare -i modrm_mod modrm_reg modrm_rm modrm_address
	operands_modrm $((modrm))
	write_reg $((rex_w ? WIDTH64 : operand_size_prefix ? WIDTH16 : WIDTH32)) $((modrm_reg)) $((modrm_address))
}

# B0-BF. B8-BF with REX.W is movabs with a 64-bit immediate.
function inst_mov_imm() {
	declare -ri mov="$1"
	declare -ri reg=$((mov & 0x7 | rex_b << 3))
	declare -i width displacement
	((width = mov < 0xb8 ? WIDTH8 : rex_w ? WIDTH64 : operand_size_prefix ? WIDTH16 : WIDTH32)) || :
	disp_width $((width))
	write_reg $((width)) $((reg)) $((displacement))
}

function inst_push() {
	declare -i reg="$1"
	push64 $((registers[reg]))
}

# Executes the instruction at `rip` and moves `rip` to the next instruction.
function step() {
	declare -i op op2 modrm width imm_bytes a b displacement rep_prefix=0
	declare -i modrm_mod modrm_reg modrm_rm modrm_address
	rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 operand_size_prefix=0
	advance=0

	# Prefixes
	while true; do
		((op = memory[rip + advance])) || :
		((advance++)) || :
		if (((op & 0xf0) == 0x40)); then
			((rex = op, rex_w = op >> 3 & 1, rex_r = op >> 2 & 1, rex_x = op >> 1 & 1, rex_b = op & 1)) || :
			continue
		fi
		case $((op)) in
		$((0x66))) operand_size_prefix=1 ;;
		$((0xf2)) | $((0xf3))) rep_prefix=$((op)) ;;
		# cs, ds, es, ss segment overrides are no-ops in 64-bit mode. lock is
		# irrelevant to a single threaded emulator.
		$((0x2e)) | $((0x3e)) | $((0x26)) | $((0x36)) | $((0xf0))) ;;
		*) break ;;
		esac
		# A legacy prefix after REX cancels REX.
		rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0
	done

	if [[ ${enable_debug_messages} = true ]]; then
		debug "rip=0x%x opcode=0x%02x" $((rip)) $((op))
	fi

	((width = rex_w ? WIDTH64 : operand_size_prefix ? WIDTH16 : WIDTH32)) || :

	# add/or/adc/sbb/and/sub/xor/cmp: 00-05, 08-0D, ... 38-3D
	if ((op < 0x40 && (op & 0x7) < 6)); then
		if (((op & 0x7) < 4)); then
			((modrm = memory[rip + advance], advance++)) || :
			inst_binary_op $((op)) $((modrm))
		else
			# AL/eAX, imm
			(((op & 1) == 0)) && width=1
			disp_width $((width == 8 ? 4 : width))
			read_reg $((width)) $((RAX))
			alu $((op >> 3)) $((width)) $((val)) $((displacement & (width == 8 ? -1 : (1 << width * 8) - 1)))
			(((op >> 3) == 7)) || write_reg $((width)) $((RAX)) $((val))
		fi
		((rip += advance)) || :
		return 0
	fi

	case $((op)) in
	$((0x0f)))
		((op2 = memory[rip + advance], advance++)) || :
		case $((op2 & 0xf0)) in
		$((0x40))) # cmovcc
			((modrm = memory[rip + advance], advance++)) || :
			operands_modrm $((modrm))
			read_rm $((width))
			eval_cond $((op2))
			if ((cond)); then
				write_reg $((width)) $((modrm_reg)) $((val))
			elif ((width == 4)); then
				# Upper bits are cleared even if the condition is false.
				read_reg 4 $((modrm_reg))
				write_reg 4 $((modrm_reg)) $((val))
			fi
			;;
		$((0x80))) # jcc rel32
			disp32
			eval_cond $((op2))
			if ((cond)); then ((advance += displacement)) || :; fi
			;;
		$((0x90))) # setcc
			((modrm = memory[rip + advance], advance++)) || :
			operands_modrm $((modrm))
			eval_cond $((op2))
			write_rm 1 $((cond))
			;;
		*)
			case $((op2)) in
			$((0x05)))
				inst_syscall
				;;
			$((0x18)) | $((0x19)) | $((0x1a)) | $((0x1b)) | $((0x1c)) | $((0x1d)) | $((0x1e)) | $((0x1f)))
				# Hint nops: nopw/nopl, prefetch, endbr64 (f3 0f 1e fa)...
				((modrm = memory[rip + advance], advance++)) || :
				operands_modrm $((modrm))
				;;
			$((0xaf))) # imul r, r/m
				((modrm = memory[rip + advance], advance++)) || :
				operands_modrm $((modrm))
				read_rm $((width))
				((a = val)) || :
				read_reg $((width)) $((modrm_reg))
				imul_op $((width)) $((val)) $((a))
				write_reg $((width)) $((modrm_reg)) $((prod_lo))
				;;
			$((0xa4)) | $((0xa5)) | $((0xac)) | $((0xad))) # shld, shrd
				((modrm = memory[rip + advance], advance++)) || :
				operands_modrm $((modrm)) $((op2 & 1 ? 0 : 1))
				read_rm $((width))
				((a = val)) || :
				if ((op2 & 1)); then
					((b = registers[RCX])) || :
				else
					disp8
					((b = displacement)) || :
				fi
				read_reg $((width)) $((modrm_reg))
				double_shift $((op2 < 0xac)) $((width)) $((a)) $((val)) $((b))
				write_rm $((width)) $((val))
				;;
			$((0xbc)) | $((0xbd))) # bsf, bsr
				((modrm = memory[rip + advance], advance++)) || :
				operands_modrm $((modrm))
				read_rm $((width))
				if ((val == 0)); then
					flag_zf=1
				else
					flag_zf=0
					if ((op2 == 0xbc)); then
						for ((b = 0; !((val >> b) & 1); b++)); do :; done
					else
						for ((b = width * 8 - 1; !((val >> b) & 1); b--)); do :; done
					fi
					write_reg $((width)) $((modrm_reg)) $((b))
				fi
				;;
			$((0xb6)) | $((0xb7)) | $((0xbe)) | $((0xbf))) # movzx, movsx
				((modrm = memory[rip + advance], advance++)) || :
				operands_modrm $((modrm))
				read_rm $(((op2 & 1) + 1))
				if ((op2 & 0x8)); then
					sign_extend $(((op2 & 1) + 1)) $((val))
				fi
				write_reg $((width)) $((modrm_reg)) $((val))
				;;
			*)
				unknown_insruction "$(printf '0f %02x' $((op2)))" "unsupported 2 byte instruction"
				;;
			esac
			;;
		esac
		;;
	$((0x50)) | $((0x51)) | $((0x52)) | $((0x53)) | $((0x54)) | $((0x55)) | $((0x56)) | $((0x57)))
		inst_push $((op & 0x7 | rex_b << 3))
		;;
	$((0x58)) | $((0x59)) | $((0x5a)) | $((0x5b)) | $((0x5c)) | $((0x5d)) | $((0x5e)) | $((0x5f)))
		pop64
		write_reg 8 $((op & 0x7 | rex_b << 3)) $((val))
		;;
	$((0x63))) # movsxd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm $((modrm))
		if ((rex_w)); then
			read_rm 4
			sign_extend 4 $((val))
		else
			read_rm $((width))
		fi
		write_reg $((width)) $((modrm_reg)) $((val))
		;;
	$((0x68)) | $((0x6a))) # push imm32/imm8
		disp_width $((op == 0x68 ? 4 : 1))
		push64 $((displacement))
		;;
	$((0x69)) | $((0x6b))) # imul r, r/m, imm
		((imm_bytes = op == 0x6b ? 1 : $((width == 8 ? 4 : width)))) || :
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm $((modrm)) $((imm_bytes))
		read_rm $((width))
		((a = val)) || :
		disp_width $((imm_bytes))
		imul_op $((width)) $((a)) $((displacement))
		write_reg $((width)) $((modrm_reg)) $((prod_lo))
		;;
	$((0x70)) | $((0x71)) | $((0x72)) | $((0x73)) | $((0x74)) | $((0x75)) | $((0x76)) | $((0x77)) | \
		$((0x78)) | $((0x79)) | $((0x7a)) | $((0x7b)) | $((0x7c)) | $((0x7d)) | $((0x7e)) | $((0x7f)))
		disp8
		eval_cond $((op))
		if ((cond)); then ((advance += displacement)) || :; fi
		;;
	$((0x80)) | $((0x81)) | $((0x83))) # group 1: alu r/m, imm
		((op == 0x80)) && width=1
		((imm_bytes = op == 0x81 ? $((width == 8 ? 4 : width)) : 1)) || :
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm $((modrm)) $((imm_bytes))
		read_rm $((width))
		((a = val)) || :
		disp_width $((imm_bytes))
		alu $((modrm >> 3 & 7)) $((width)) $((a)) $((displacement & (width == 8 ? -1 : (1 << width * 8) - 1)))
		(((modrm >> 3 & 7) == 7)) || write_rm $((width)) $((val))
		;;
	$((0x84)) | $((0x85))) # test r/m, r
		((modrm = memory[rip + advance], advance++)) || :
		inst_binary_op $((op)) $((modrm))
		;;
	$((0x86)) | $((0x87))) # xchg r/m, r
		((op == 0x86)) && width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm $((modrm))
		read_rm $((width))
		((a = val)) || :
		read_reg $((width)) $((modrm_reg))
		write_rm $((width)) $((val))
		write_reg $((width)) $((modrm_reg)) $((a))
		;;
	$((0x88)) | $((0x89)) | $((0x8a)) | $((0x8b)))
		((modrm = memory[rip + advance], advance++)) || :
		inst_mov $((op)) $((modrm))
		;;
	$((0x8d)))
		((modrm = memory[rip + advance], advance++)) || :
		inst_lea $((op)) $((modrm))
		;;
	$((0x8f))) # pop r/m64
		((modrm = memory[rip + advance], advance++)) || :
		pop64
		((a = val)) || :
		operands_modrm $((modrm))
		write_rm 8 $((a))
		;;
	$((0x90)) | $((0x91)) | $((0x92)) | $((0x93)) | $((0x94)) | $((0x95)) | $((0x96)) | $((0x97)))
		# xchg rAX, r. 0x90 without REX.B is nop (or pause with f3).
		if (((op & 0x7 | rex_b << 3) != RAX)); then
			read_reg $((width)) $((RAX))
			((a = val)) || :
			read_reg $((width)) $((op & 0x7 | rex_b << 3))
			write_reg $((width)) $((RAX)) $((val))
			write_reg $((width)) $((op & 0x7 | rex_b << 3)) $((a))
		fi
		;;
	$((0x98))) # cbw, cwde, cdqe
		read_reg $((width / 2)) $((RAX))
		sign_extend $((width / 2)) $((val))
		write_reg $((width)) $((RAX)) $((val))
		;;
	$((0x99))) # cwd, cdq, cqo
		read_reg $((width)) $((RAX))
		write_reg $((width)) $((RDX)) $(((val >> (width * 8 - 1) & 1) ? -1 : 0))
		;;
	$((0xa4)) | $((0xa5)) | $((0xaa)) | $((0xab))) # movs, stos
		(((op & 1) == 0)) && width=1
		while ((!rep_prefix || registers[RCX] != 0)); do
			if ((op >= 0xaa)); then
				read_reg $((width)) $((RAX))
			else
				read_mem $((width)) $((registers[RSI]))
				((registers[RSI] += flag_df ? -width : width)) || :
			fi
			write_mem $((width)) $((registers[RDI])) $((val))
			((registers[RDI] += flag_df ? -width : width)) || :
			((rep_prefix)) || break
			((registers[RCX]--)) || :
		done
		;;
	$((0xa8)) | $((0xa9))) # test al/eAX, imm
		((op == 0xa8)) && width=1
		disp_width $((width == 8 ? 4 : width))
		read_reg $((width)) $((RAX))
		alu 4 $((width)) $((val)) $((displacement & (width == 8 ? -1 : (1 << width * 8) - 1)))
		;;
	$((0xb0)) | $((0xb1)) | $((0xb2)) | $((0xb3)) | $((0xb4)) | $((0xb5)) | $((0xb6)) | $((0xb7)) | \
		$((0xb8)) | $((0xb9)) | $((0xba)) | $((0xbb)) | $((0xbc)) | $((0xbd)) | $((0xbe)) | $((0xbf)))
		inst_mov_imm $((op))
		;;
	$((0xc0)) | $((0xc1)) | $((0xd0)) | $((0xd1)) | $((0xd2)) | $((0xd3))) # group 2: shifts
		(((op & 1) == 0)) && width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm $((modrm)) $((op < 0xd0 ? 1 : 0))
		read_rm $((width))
		((a = val)) || :
		if ((op < 0xd0)); then
			disp8
			((b = displacement & 0xff)) || :
		elif ((op < 0xd2)); then
			b=1
		else
			((b = registers[RCX] & 0xff)) || :
		fi
		shift_op $((modrm >> 3 & 7)) $((width)) $((a)) $((b))
		write_rm $((width)) $((val))
		;;
	$((0xc2)) | $((0xc3))) # ret, ret imm16
		if ((op == 0xc2)); then
			disp16
			((b = displacement & 0xffff)) || :
		else
			b=0
		fi
		pop64
		((registers[RSP] += b)) || :
		((advance = val - rip)) || :
		;;
	$((0xc6)) | $((0xc7))) # mov r/m, imm
		((op == 0xc6)) && width=1
		((imm_bytes = op == 0xc6 ? 1 : $((width == 8 ? 4 : width)))) || :
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm $((modrm)) $((imm_bytes))
		disp_width $((imm_bytes))
		write_rm $((width)) $((displacement))
		;;
	$((0xc9))) # leave
		((registers[RSP] = registers[RBP])) || :
		pop64
		((registers[RBP] = val)) || :
		;;
	$((0xe8))) # call rel32
		disp32
		push64 $((rip + advance))
		((advance += displacement)) || :
		;;
	$((0xe9))) # jmp rel32
		disp32
		((advance += displacement)) || :
		;;
	$((0xeb))) # jmp rel8
		disp8
		((advance += displacement)) || :
		;;
	$((0xf5))) ((flag_cf = !flag_cf)) || : ;; # cmc
	$((0xf8))) flag_cf=0 ;;                     # clc
	$((0xf9))) flag_cf=1 ;;                     # stc
	$((0xfc))) flag_df=0 ;;                     # cld
	$((0xfd))) flag_df=1 ;;                     # std
	$((0xf6)) | $((0xf7))) # group 3
		((op == 0xf6)) && width=1
		((modrm = memory[rip + advance], advance++)) || :
		((imm_bytes = (modrm >> 3 & 7) < 2 ? $((width == 8 ? 4 : width)) : 0)) || :
		operands_modrm $((modrm)) $((imm_bytes))
		read_rm $((width))
		((a = val)) || :
		case $((modrm >> 3 & 7)) in
		0 | 1) # test
			disp_width $((imm_bytes))
			alu 4 $((width)) $((a)) $((displacement & (width == 8 ? -1 : (1 << width * 8) - 1)))
			;;
		2) # not
			write_rm $((width)) $((~a))
			;;
		3) # neg
			alu 5 $((width)) 0 $((a))
			write_rm $((width)) $((val))
			;;
		*)
			inst_muldiv $((modrm >> 3 & 7)) $((width)) $((a))
			;;
		esac
		;;
	$((0xfe)) | $((0xff))) # group 4/5
		((op == 0xfe)) && width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm $((modrm))
		case $((modrm >> 3 & 7)) in
		0 | 1) # inc, dec: CF is preserved.
			read_rm $((width))
			((b = flag_cf)) || :
			alu $(((modrm >> 3 & 7) ? 5 : 0)) $((width)) $((val)) 1
			((flag_cf = b)) || :
			write_rm $((width)) $((val))
			;;
		2) # call r/m64
			((op == 0xff)) || unknown_insruction "fe /2" "invalid"
			read_rm 8
			((a = val)) || :
			push64 $((rip + advance))
			((advance = a - rip)) || :
			;;
		4) # jmp r/m64
			((op == 0xff)) || unknown_insruction "fe /4" "invalid"
			read_rm 8
			((advance = val - rip)) || :
			;;
		6) # push r/m64
			((op == 0xff)) || unknown_insruction "fe /6" "invalid"
			read_rm 8
			push64 $((val))
			;;
		*)
			unknown_insruction "$(printf '%02x /%d' $((op)) $((modrm >> 3 & 7)))" "unsupported group 5 instruction"
			;;
		esac
		;;
	*)
		unknown_insruction "$(printf '%02x' $((op)))" "unsupported instruction"
		;;
	esac

	((rip += advance)) || :
}

function set_register() {
	declare -ri width="$1" reg="$2" value="$3"
	debug "Setting register %s with value %x (width: %d)" \
		$(register_name $((reg))) $((value)) $((width))
	case $((width)) in
	1)
		((registers[reg]=registers[reg] & (~0 << 8) | (value & 0xff) )) || :
		;;
	2)
		((registers[reg]=registers[reg] & (~0 << 16) | (value & 0xffff) )) || :
		;;
	4)
		((registers[reg]=registers[reg] & (~0 << 32) | (value & 0xffffffff) )) || :
		;;
	8)
		((registers[reg]=value)) || :
		;;
	*)
		die "Unsupported data width in set_register: ${width}"
		;;
	esac
}

function set_memory() {
	declare -ri width="$1" address="$2" value="$3"
	declare -ria value_bytes=(
		$((value & 0xff))
		$(((value >> 8) & 0xff))
		$(((value >> 16) & 0xff))
		$(((value >> 24) & 0xff))
		$(((value >> 32) & 0xff))
		$(((value >> 40) & 0xff))
		$(((value >> 48) & 0xff))
		$(((value >> 56) & 0xff))
	)
	declare -i i
	for ((i = 0; i < width; i++)); do
		((memory[address + i]=value_bytes[i])) || :
	done
}

function get_register() {
	declare -ri width="$1" reg="$2"
	case $((width)) in
	1)
		echo $((registers[reg] & 0xff))
		;;
	2)
		echo $((registers[reg] & 0xffff))
		;;
	4)
		echo $((registers[reg] & 0xffffffff))
		;;
	8)
		echo $((registers[reg]))
		;;
	*)
		die "Unsupported data width in get_register: ${width}"
		;;
	esac
}

function get_memory() {
	declare -ri width="$1" address="$2"
	declare -i value=0
	declare -i i
	for ((i = 0; i < width; i++)); do
		((value += memory[address + i] << (8 * i))) || :
	done
	echo $((value))
}

function get_width() {
	# TODO: figure out the semantics of more than one prefix set
	if ((rex_w)); then
		echo $((WIDTH64))
	elif ((operand_size_prefix)); then
		echo $((WIDTH16))
	else
		echo $((WIDTH32))
	fi
}

function inst_syscall() {
	case "${GLOBAL_os_abi}" in
	macos)
		syscall_macos
		;;
	linux)
		syscall_linux
		;;
	*)
		die "Unknown GLOBAL_os_abi: '%s' (expected macos or linux)" "${GLOBAL_os_abi}"
		;;
	esac
}

# This function is basically an OSX kernel emulator written in bash.
function syscall_macos() {
	debug "Syscall: %0x\n" $((registers[RAX]))
	case $((registers[RAX])) in
	$((0x02000001)))
		inst_syscall_exit
		;;
	$((0x02000004)))
		inst_syscall_write
		;;
	*)
		die "Unimplemented syscall"
		;;
	esac
}

function inst_syscall_write() {
	declare -ri out_fd=$((registers[RDI]))
	declare -ri buf=$((registers[RSI]))
	declare -ri len=$((registers[RDX]))
	declare -i i
	declare string=

	for ((i = 0; i < len; i++)); do
		string="${string}$(printf '\\x%x' $(get_memory 1 $((buf + i))))"
	done
	debug "SYSCALL WRITE: %x %x %x %s" $((out_fd)) $((buf)) $((len)) "${string}"
	printf "${string}" >&${out_fd}
}

function inst_syscall_exit() {
	declare -ri exit_code=$((registers[RDX]))
	debug "SYSCALL EXIT: exitting with code: %x" $((exit_code))
	exit $((exit_code))
}

### Linux kernel emulation ###

declare -ri LINUX_EPERM=1
declare -ri LINUX_ENOENT=2
declare -ri LINUX_ENXIO=6
declare -ri LINUX_EBADF=9
declare -ri LINUX_ENOMEM=12
declare -ri LINUX_EACCES=13
declare -ri LINUX_EFAULT=14
declare -ri LINUX_ENODEV=19
declare -ri LINUX_EISDIR=21
declare -ri LINUX_EINVAL=22
declare -ri LINUX_ENOTTY=25
declare -ri LINUX_ESPIPE=29
declare -ri LINUX_EROFS=30
declare -ri LINUX_ERANGE=34
declare -ri LINUX_ENOSYS=38

declare -ri LINUX_PAGE_SIZE=4096
declare -ri LINUX_DEFAULT_BRK_START=$((0x10000000))
declare -ri LINUX_MAP_FIXED=$((0x10))
declare -ri LINUX_MAP_ANONYMOUS=$((0x20))
declare -ri LINUX_AT_FDCWD=-100
declare -ri LINUX_AT_SYMLINK_NOFOLLOW=$((0x100))
declare -ri LINUX_AT_EMPTY_PATH=$((0x1000))
declare -ri LINUX_ARCH_SET_GS=$((0x1001))
declare -ri LINUX_ARCH_SET_FS=$((0x1002))
declare -ri LINUX_ARCH_GET_FS=$((0x1003))
declare -ri LINUX_ARCH_GET_GS=$((0x1004))
# Value stored in r11 by `syscall`. spleen does not emulate RFLAGS yet, so we
# report IF set plus the always-one reserved bit 1.
declare -ri LINUX_SYSCALL_RFLAGS=$((0x202))

# Sign-extends a 32-bit int syscall argument (e.g. AT_FDCWD passed via %edi).
function linux_s32() {
	echo $(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
}

# Reads a NUL-terminated string from emulated `memory[addr..]` into `guest_str`.
function read_guest_cstring() {
	declare -ri addr="$1"
	declare -i i=0 b
	declare escaped="" ch
	guest_str=""
	[[ -n "${memory[@]+x}" ]] || memory=()
	while ((i < 4096)); do
		((b = memory[addr + i] & 0xff)) || :
		((b == 0)) && break
		printf -v ch '\\x%02x' $((b))
		escaped+="${ch}"
		((i++)) || :
	done
	if [[ -n "${escaped}" ]]; then
		printf -v guest_str '%b' "${escaped}"
	fi
}

# Resolves guest path at `path_addr` relative to `dirfd` into `resolved_path`.
# On error sets `ret` to negative errno and returns 1.
function linux_resolve_path() {
	declare -ri dirfd="$1" path_addr="$2"
	declare guest_str=""
	read_guest_cstring $((path_addr))
	if [[ -z "${guest_str}" ]]; then
		resolved_path=""
		ret=-LINUX_ENOENT
		return 1
	fi
	if [[ "${guest_str}" == /* ]]; then
		resolved_path="${guest_str}"
		return 0
	fi
	if ((dirfd == LINUX_AT_FDCWD)); then
		resolved_path="${PWD}/${guest_str}"
		return 0
	fi
	if ((dirfd >= 3)) && [[ -n "${LINUX_fd_path[dirfd]+x}" && "${LINUX_fd_path[dirfd]}" != stdio:* ]]; then
		if [[ -d "${LINUX_fd_path[dirfd]}" ]]; then
			resolved_path="${LINUX_fd_path[dirfd]}/${guest_str}"
		else
			resolved_path="$(dirname "${LINUX_fd_path[dirfd]}")/${guest_str}"
		fi
		return 0
	fi
	ret=-LINUX_EBADF
	return 1
}

# Writes `len` bytes of emulated memory starting at `address` to stdout, byte
# for byte. NUL bytes, newlines, '%' and '\' are all emitted verbatim.
function print_memory_bytes() {
	declare -ri address="$1" len="$2"
	declare -i i
	declare escaped="" byte
	[[ -n "${memory[@]+x}" ]] || memory=()
	for ((i = 0; i < len; i++)); do
		printf -v byte '\\x%02x' $((${memory[address + i]:-0} & 0xff))
		escaped="${escaped}${byte}"
	done
	printf '%b' "${escaped}"
}

# Copies `string` to emulated memory at `address`, followed by NUL bytes up to
# `size` bytes in total. The string is truncated to size - 1 bytes.
function set_memory_string() {
	declare -ri address="$1"
	declare -r string="$2"
	declare -ri size="$3"
	declare LC_ALL=C
	declare -i i code
	for ((i = 0; i < size; i++)); do
		if ((i < ${#string} && i < size - 1)); then
			printf -v code '%d' "'${string:i:1}"
			memory[address + i]=$((code & 0xff))
		else
			memory[address + i]=0
		fi
	done
}

# Zeroes emulated memory in [address, address + len). Chooses whichever of
# range iteration or sparse-key iteration touches fewer entries.
function zero_memory_range() {
	declare -ri address="$1" len="$2"
	[[ -n "${memory[@]+x}" ]] || { memory=(); return; }
	if ((len <= 0)); then
		return
	fi
	declare -i i
	if ((len <= ${#memory[@]})); then
		for ((i = address; i < address + len; i++)); do
			unset 'memory[i]'
		done
	else
		for i in "${!memory[@]}"; do
			if ((i >= address && i < address + len)); then
				unset 'memory[i]'
			fi
		done
	fi
}

# Sets `now_sec` and `now_nsec` to the current wall clock time.
function linux_time_now() {
	if [[ -n "${EPOCHREALTIME:-}" ]]; then
		declare -r usec="${EPOCHREALTIME#*[.,]}"
		now_sec=$((${EPOCHREALTIME%[.,]*}))
		now_nsec=$((10#${usec} * 1000))
	else
		now_sec=$(date +%s)
		now_nsec=0
	fi
}

# read(fd, buf, count): fd 0 reads stdin; fd >= 3 reads an open host file.
function linux_sys_read() {
	declare -ri fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri buf="$2" count="$3"
	if ((count < 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	if ((fd == 0)) || [[ "${LINUX_fd_path[fd]:-}" == "stdio:0" ]]; then
		declare LC_ALL=C
		declare -i n=0 code
		declare c
		while ((n < count)); do
			# With -d '' a NUL byte acts as the delimiter, and reads as "".
			IFS= read -r -n 1 -d '' c || break
			printf -v code '%d' "'${c}"
			memory[buf + n]=$((code & 0xff))
			((n++)) || :
			if ((code == 10)); then
				break
			fi
		done
		ret=$((n))
		return
	fi
	if ((fd < 3)) || [[ -z "${LINUX_fd_path[fd]+x}" || "${LINUX_fd_path[fd]}" == stdio:* ]]; then
		ret=-LINUX_EBADF
		return
	fi
	declare -r fpath="${LINUX_fd_path[fd]}"
	if [[ -d "${fpath}" ]]; then
		ret=-LINUX_EISDIR
		return
	fi
	declare -ri pos=${LINUX_fd_pos[fd]} fsize=${LINUX_fd_size[fd]}
	if ((count == 0 || pos >= fsize)); then
		ret=0
		return
	fi
	declare -i avail=$((fsize - pos))
	((avail > count)) && avail=$((count))
	load_file_slice_to_memory "${fpath}" $((buf)) $((pos)) $((avail))
	((LINUX_fd_pos[fd] = pos + avail)) || :
	ret=$((avail))
}

# pread64(fd, buf, count, offset): reads at `offset` without changing fd_pos.
function linux_sys_pread64() {
	declare -ri fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri buf="$2" count="$3" offset="$4"
	if ((count < 0 || offset < 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	if ((fd >= 0 && fd <= 2)); then
		ret=-LINUX_ESPIPE
		return
	fi
	if ((fd < 3)) || [[ -z "${LINUX_fd_path[fd]+x}" || "${LINUX_fd_path[fd]}" == stdio:* ]]; then
		ret=-LINUX_EBADF
		return
	fi
	declare -r fpath="${LINUX_fd_path[fd]}"
	if [[ -d "${fpath}" ]]; then
		ret=-LINUX_EISDIR
		return
	fi
	declare -ri fsize=${LINUX_fd_size[fd]}
	if ((count == 0 || offset >= fsize)); then
		ret=0
		return
	fi
	declare -i avail=$((fsize - offset))
	((avail > count)) && avail=$((count))
	load_file_slice_to_memory "${fpath}" $((buf)) $((offset)) $((avail))
	ret=$((avail))
}

# write(fd, buf, count) for fd 1 (stdout) and 2 (stderr).
function linux_sys_write() {
	declare -i fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri buf="$2" count="$3"
	if ((fd >= 3)) && [[ "${LINUX_fd_path[fd]:-}" == stdio:* ]]; then
		fd=$((${LINUX_fd_path[fd]#stdio:}))
	fi
	case $((fd)) in
	1 | 2)
		print_memory_bytes $((buf)) $((count)) >&$((fd))
		ret=$((count))
		;;
	*)
		ret=-LINUX_EBADF
		;;
	esac
}

# writev(fd, iov, iovcnt). struct iovec { void *iov_base; size_t iov_len; }
function linux_sys_writev() {
	declare -i fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri iov="$2" iovcnt=$(((($3 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	if ((fd >= 3)) && [[ "${LINUX_fd_path[fd]:-}" == stdio:* ]]; then
		fd=$((${LINUX_fd_path[fd]#stdio:}))
	fi
	if ((fd != 1 && fd != 2)); then
		ret=-LINUX_EBADF
		return
	fi
	declare -i i base len total=0 mem_val
	[[ -n "${memory[@]+x}" ]] || memory=()
	for ((i = 0; i < iovcnt; i++)); do
		elf_mem_read64 $((iov + 16 * i))
		base=$((mem_val))
		elf_mem_read64 $((iov + 16 * i + 8))
		len=$((mem_val))
		print_memory_bytes $((base)) $((len)) >&$((fd))
		((total += len)) || :
	done
	ret=$((total))
}

# openat(dirfd, path, flags, mode): read-only access to host files/directories.
function linux_sys_openat() {
	declare -ri dirfd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri path_addr="$2"
	declare -ri flags=$(((($3 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare resolved_path=""
	linux_resolve_path $((dirfd)) $((path_addr)) || return
	debug "openat(%d, '%s', 0x%x)" $((dirfd)) "${resolved_path}" $((flags))

	if [[ -e "${resolved_path}" && ! -f "${resolved_path}" && ! -d "${resolved_path}" ]]; then
		ret=-LINUX_ENXIO
		return
	fi
	# O_WRONLY (1), O_RDWR (2), O_CREAT (0x40), O_TRUNC (0x200) are refused.
	if (((flags & 0x3) != 0 || (flags & 0x240) != 0)); then
		ret=-LINUX_EACCES
		return
	fi
	if [[ ! -e "${resolved_path}" ]]; then
		ret=-LINUX_ENOENT
		return
	fi
	if [[ ! -r "${resolved_path}" ]]; then
		ret=-LINUX_EACCES
		return
	fi

	declare -i fd
	for ((fd = 3; ; fd++)); do
		if [[ -z "${LINUX_fd_path[fd]+x}" ]]; then
			break
		fi
	done
	LINUX_fd_path[fd]="${resolved_path}"
	LINUX_fd_pos[fd]=0
	if [[ -f "${resolved_path}" ]]; then
		LINUX_fd_size[fd]=$(wc -c <"${resolved_path}")
	else
		LINUX_fd_size[fd]=4096
	fi
	LINUX_fd_flags[fd]=$((flags))
	ret=$((fd))
}

function linux_sys_close() {
	declare -ri fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	if ((fd >= 0 && fd <= 2)); then
		ret=0
	elif ((fd >= 3)) && [[ -n "${LINUX_fd_path[fd]+x}" ]]; then
		unset 'LINUX_fd_path[fd]' 'LINUX_fd_pos[fd]' 'LINUX_fd_size[fd]' 'LINUX_fd_flags[fd]'
		ret=0
	else
		ret=-LINUX_EBADF
	fi
}

# Populates a 144-byte x86_64 Linux `struct stat` at `statbuf` from `target_path`.
function linux_fill_stat_path() {
	declare -r target_path="$1" deref="$2"
	declare -ri statbuf="$3"
	declare -i i
	[[ -n "${memory[@]+x}" ]] || memory=()
	if [[ "${deref}" == "-L" ]]; then
		[[ -e "${target_path}" ]] || { ret=-LINUX_ENOENT; return; }
	else
		[[ -e "${target_path}" || -L "${target_path}" ]] || { ret=-LINUX_ENOENT; return; }
	fi

	declare st_dev=1 st_ino=1 st_nlink=1 st_mode=0x81a4 st_uid=${UID}
	declare st_gid=${GROUPS[0]:-0} st_size=0 st_mtime=0
	if [[ "${deref}" == "-L" ]]; then
		read -r st_dev st_ino st_nlink st_mode st_uid st_gid st_size st_mtime \
			< <(stat -L -c '%d %i %h 0x%f %u %g %s %Y' "${target_path}" 2>/dev/null) || :
	else
		read -r st_dev st_ino st_nlink st_mode st_uid st_gid st_size st_mtime \
			< <(stat -c '%d %i %h 0x%f %u %g %s %Y' "${target_path}" 2>/dev/null) || :
	fi

	for ((i = 0; i < 144; i++)); do
		memory[statbuf + i]=0
	done
	elf_mem_write64 $((statbuf + 0)) $((st_dev))
	elf_mem_write64 $((statbuf + 8)) $((st_ino))
	elf_mem_write64 $((statbuf + 16)) $((st_nlink))
	elf_mem_write32 $((statbuf + 24)) $((st_mode))
	elf_mem_write32 $((statbuf + 28)) $((st_uid))
	elf_mem_write32 $((statbuf + 32)) $((st_gid))
	elf_mem_write64 $((statbuf + 48)) $((st_size))
	elf_mem_write64 $((statbuf + 56)) 4096
	elf_mem_write64 $((statbuf + 64)) $(((st_size + 511) / 512))
	elf_mem_write64 $((statbuf + 72)) $((st_mtime))
	elf_mem_write64 $((statbuf + 88)) $((st_mtime))
	elf_mem_write64 $((statbuf + 104)) $((st_mtime))
	ret=0
}

function linux_sys_fstat() {
	declare -i fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri statbuf="$2"
	declare -i i
	[[ -n "${memory[@]+x}" ]] || memory=()
	if ((fd >= 3)) && [[ "${LINUX_fd_path[fd]:-}" == stdio:* ]]; then
		fd=$((${LINUX_fd_path[fd]#stdio:}))
	fi
	if ((fd >= 0 && fd <= 2)); then
		for ((i = 0; i < 144; i++)); do
			memory[statbuf + i]=0
		done
		elf_mem_write64 $((statbuf + 0)) 1
		elf_mem_write64 $((statbuf + 8)) $((fd + 1))
		elf_mem_write64 $((statbuf + 16)) 1
		# S_IFCHR | 0620 (0020620 = 0x2190)
		elf_mem_write32 $((statbuf + 24)) $((0x2190))
		elf_mem_write32 $((statbuf + 28)) ${UID}
		elf_mem_write32 $((statbuf + 32)) ${GROUPS[0]:-0}
		elf_mem_write64 $((statbuf + 56)) 4096
		ret=0
		return
	fi
	if ((fd < 3)) || [[ -z "${LINUX_fd_path[fd]+x}" ]]; then
		ret=-LINUX_EBADF
		return
	fi
	linux_fill_stat_path "${LINUX_fd_path[fd]}" "-L" $((statbuf))
}

function linux_sys_newfstatat() {
	declare -ri dirfd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri path_addr="$2" statbuf="$3"
	declare -ri flags=$(((($4 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare guest_str=""
	read_guest_cstring $((path_addr))
	if [[ -z "${guest_str}" ]]; then
		if ((flags & LINUX_AT_EMPTY_PATH)); then
			linux_sys_fstat $((dirfd)) $((statbuf))
		else
			ret=-LINUX_ENOENT
		fi
		return
	fi
	declare resolved_path=""
	linux_resolve_path $((dirfd)) $((path_addr)) || return
	if ((flags & LINUX_AT_SYMLINK_NOFOLLOW)); then
		linux_fill_stat_path "${resolved_path}" "" $((statbuf))
	else
		linux_fill_stat_path "${resolved_path}" "-L" $((statbuf))
	fi
}

function linux_sys_lseek() {
	declare -ri fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri offset="$2"
	declare -ri whence=$(((($3 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	if ((fd >= 0 && fd <= 2)) || [[ "${LINUX_fd_path[fd]:-}" == stdio:* ]]; then
		ret=-LINUX_ESPIPE
		return
	fi
	if ((fd < 3)) || [[ -z "${LINUX_fd_path[fd]+x}" ]]; then
		ret=-LINUX_EBADF
		return
	fi
	declare -i new_pos=0
	case $((whence)) in
	0) new_pos=$((offset)) ;;
	1) new_pos=$((LINUX_fd_pos[fd] + offset)) ;;
	2) new_pos=$((LINUX_fd_size[fd] + offset)) ;;
	*)
		ret=-LINUX_EINVAL
		return
		;;
	esac
	if ((new_pos < 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	LINUX_fd_pos[fd]=$((new_pos))
	ret=$((new_pos))
}

function linux_sys_faccessat() {
	declare -ri dirfd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri path_addr="$2"
	declare -ri mode=$(((($3 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare resolved_path=""
	linux_resolve_path $((dirfd)) $((path_addr)) || return
	if [[ ! -e "${resolved_path}" ]]; then
		ret=-LINUX_ENOENT
		return
	fi
	if ((mode & 2)); then
		ret=-LINUX_EACCES
		return
	fi
	if ((mode & 4)) && [[ ! -r "${resolved_path}" ]]; then
		ret=-LINUX_EACCES
		return
	fi
	if ((mode & 1)) && [[ ! -x "${resolved_path}" ]]; then
		ret=-LINUX_EACCES
		return
	fi
	ret=0
}

function linux_sys_fcntl() {
	declare -ri fd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri cmd=$(((($2 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri arg="$3"
	if ((fd < 0)) || { ((fd >= 3)) && [[ -z "${LINUX_fd_path[fd]+x}" ]]; }; then
		ret=-LINUX_EBADF
		return
	fi
	case $((cmd)) in
	0 | 1030) # F_DUPFD, F_DUPFD_CLOEXEC
		declare -i minfd=$(((($arg & 0xffffffff) ^ 0x80000000) - 0x80000000))
		if ((minfd < 0)); then
			ret=-LINUX_EINVAL
			return
		fi
		((minfd < 3)) && minfd=3
		declare -i newfd
		for ((newfd = minfd; ; newfd++)); do
			if [[ -z "${LINUX_fd_path[newfd]+x}" ]]; then
				break
			fi
		done
		if ((fd >= 0 && fd <= 2)); then
			LINUX_fd_path[newfd]="stdio:${fd}"
			LINUX_fd_pos[newfd]=0
			LINUX_fd_size[newfd]=0
			LINUX_fd_flags[newfd]=0
		else
			LINUX_fd_path[newfd]="${LINUX_fd_path[fd]}"
			LINUX_fd_pos[newfd]=$((LINUX_fd_pos[fd]))
			LINUX_fd_size[newfd]=$((LINUX_fd_size[fd]))
			LINUX_fd_flags[newfd]=$((LINUX_fd_flags[fd]))
		fi
		ret=$((newfd))
		;;
	1 | 2 | 4) # F_GETFD, F_SETFD, F_SETFL
		ret=0
		;;
	3) # F_GETFL
		ret=$((fd >= 3 ? (LINUX_fd_flags[fd] & ~0x80000) : 0))
		;;
	*)
		ret=-LINUX_EINVAL
		;;
	esac
}

function linux_sys_getcwd() {
	declare -ri buf="$1" size="$2"
	declare -r cwd="${PWD}"
	declare -ri need=$((${#cwd} + 1))
	if ((size < need)); then
		ret=-LINUX_ERANGE
		return
	fi
	[[ -n "${memory[@]+x}" ]] || memory=()
	put_string $((buf)) "${cwd}"
	ret=$((need))
}

function linux_sys_readlinkat() {
	declare -ri dirfd=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri path_addr="$2" buf="$3" bufsiz="$4"
	if ((bufsiz <= 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	declare resolved_path=""
	linux_resolve_path $((dirfd)) $((path_addr)) || return
	if [[ ! -e "${resolved_path}" && ! -L "${resolved_path}" ]]; then
		ret=-LINUX_ENOENT
		return
	fi
	if [[ ! -L "${resolved_path}" ]]; then
		ret=-LINUX_EINVAL
		return
	fi
	declare target
	target=$(readlink "${resolved_path}")
	declare LC_ALL=C
	declare -i n=${#target} i c
	((n > bufsiz)) && n=$((bufsiz))
	[[ -n "${memory[@]+x}" ]] || memory=()
	for ((i = 0; i < n; i++)); do
		printf -v c '%d' "'${target:i:1}"
		memory[buf + i]=$((c & 0xff))
	done
	ret=$((n))
}

function linux_sys_prlimit64() {
	declare -ri pid=$(((($1 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri resource=$(((($2 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri old_limit="$4"
	if ((pid != 0 && pid != $$)); then
		ret=-LINUX_EPERM
		return
	fi
	if ((old_limit != 0)); then
		[[ -n "${memory[@]+x}" ]] || memory=()
		declare -i cur=-1
		case $((resource)) in
		3) cur=$((8 * 1024 * 1024)) ;; # RLIMIT_STACK
		7) cur=1024 ;;                 # RLIMIT_NOFILE
		esac
		elf_mem_write64 $((old_limit)) $((cur))
		elf_mem_write64 $((old_limit + 8)) -1
	fi
	ret=0
}

function linux_sys_getresuid() {
	declare -ri ruid="$1" euid="$2" suid="$3"
	[[ -n "${memory[@]+x}" ]] || memory=()
	((ruid != 0)) && elf_mem_write32 $((ruid)) ${UID}
	((euid != 0)) && elf_mem_write32 $((euid)) ${EUID}
	((suid != 0)) && elf_mem_write32 $((suid)) ${EUID}
	ret=0
}

function linux_sys_getresgid() {
	declare -ri rgid="$1" egid="$2" sgid="$3"
	declare -ri gid=${GROUPS[0]:-0}
	[[ -n "${memory[@]+x}" ]] || memory=()
	((rgid != 0)) && elf_mem_write32 $((rgid)) $((gid))
	((egid != 0)) && elf_mem_write32 $((egid)) $((gid))
	((sgid != 0)) && elf_mem_write32 $((sgid)) $((gid))
	ret=0
}

function linux_sys_getrandom() {
	declare -ri buf="$1" buflen="$2"
	if ((buflen < 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	[[ -n "${memory[@]+x}" ]] || memory=()
	declare -i i
	for ((i = 0; i < buflen; i++)); do
		((memory[buf + i] = RANDOM & 0xff)) || :
	done
	ret=$((buflen))
}

# brk(addr): returns the new program break, or the current one if `addr` is 0
# or below the initial break. Memory is sparse, so growing needs no work;
# shrinking zeroes the released bytes so that growing again reads zeros.
function linux_sys_brk() {
	declare -ri addr="$1"
	[[ -n "${memory[@]+x}" ]] || memory=()
	if ((GLOBAL_linux_brk_start == 0)); then
		GLOBAL_linux_brk_start=$((LINUX_DEFAULT_BRK_START))
	fi
	if ((GLOBAL_linux_brk == 0)); then
		GLOBAL_linux_brk=$((GLOBAL_linux_brk_start))
	fi
	if ((addr >= GLOBAL_linux_brk_start)); then
		if ((addr < GLOBAL_linux_brk)); then
			zero_memory_range $((addr)) $((GLOBAL_linux_brk - addr))
		fi
		GLOBAL_linux_brk=$((addr))
	fi
	ret=$((GLOBAL_linux_brk))
}

# mmap(addr, length, prot, flags, fd, offset): supports both anonymous and
# read-only file-backed mappings. Without MAP_FIXED, memory comes from a bump
# allocator and is never reused.
function linux_sys_mmap() {
	declare -ri addr="$1" length="$2"
	declare -ri prot=$(((($3 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri flags=$(((($4 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri fd=$(((($5 & 0xffffffff) ^ 0x80000000) - 0x80000000))
	declare -ri offset="$6"
	[[ -n "${memory[@]+x}" ]] || memory=()
	if ((length <= 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	declare -ri size=$(((length + LINUX_PAGE_SIZE - 1) & ~(LINUX_PAGE_SIZE - 1)))

	if ((flags & LINUX_MAP_ANONYMOUS)); then
		if ((flags & LINUX_MAP_FIXED)); then
			if ((addr & (LINUX_PAGE_SIZE - 1))); then
				ret=-LINUX_EINVAL
				return
			fi
			LINUX_ro_mmap_path=""
			zero_memory_range $((addr)) $((size))
			ret=$((addr))
			return
		fi
		if ((GLOBAL_linux_mmap_next + size > ELF_INTERP_BASE)); then
			ret=-LINUX_ENOMEM
			return
		fi
		ret=$((GLOBAL_linux_mmap_next))
		((GLOBAL_linux_mmap_next += size)) || :
		return
	fi

	# File-backed mapping.
	if ((offset < 0 || (offset & (LINUX_PAGE_SIZE - 1)) != 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	if ((fd >= 0 && fd <= 2)) || [[ "${LINUX_fd_path[fd]:-}" == stdio:* ]]; then
		ret=-LINUX_ENODEV
		return
	fi
	if ((fd < 3)) || [[ -z "${LINUX_fd_path[fd]+x}" ]]; then
		ret=-LINUX_EBADF
		return
	fi
	declare -r fpath="${LINUX_fd_path[fd]}"
	if [[ ! -f "${fpath}" ]]; then
		ret=-LINUX_ENODEV
		return
	fi
	declare -ri fsize=${LINUX_fd_size[fd]}
	declare -i map_addr=0

	if ((flags & LINUX_MAP_FIXED)); then
		if ((addr & (LINUX_PAGE_SIZE - 1))); then
			ret=-LINUX_EINVAL
			return
		fi
		# Fast path: ld.so reserves the full library range with PROT_READ and
		# immediately remaps segments with MAP_FIXED at identical file offsets.
		if [[ -n "${LINUX_ro_mmap_path}" && "${fpath}" == "${LINUX_ro_mmap_path}" ]] &&
			((addr >= LINUX_ro_mmap_base &&
				addr + size <= LINUX_ro_mmap_base + LINUX_ro_mmap_size &&
				addr + length <= LINUX_ro_mmap_base + LINUX_ro_mmap_reqlen &&
				addr - LINUX_ro_mmap_base == offset - LINUX_ro_mmap_off)); then
			if ((prot & 0x2)); then
				LINUX_ro_mmap_path=""
			fi
			ret=$((addr))
			return
		fi
		LINUX_ro_mmap_path=""
		zero_memory_range $((addr)) $((size))
		map_addr=$((addr))
	else
		if ((GLOBAL_linux_mmap_next + size > ELF_INTERP_BASE)); then
			ret=-LINUX_ENOMEM
			return
		fi
		map_addr=$((GLOBAL_linux_mmap_next))
		((GLOBAL_linux_mmap_next += size)) || :
		if (((prot & 0x2) == 0)); then
			LINUX_ro_mmap_path="${fpath}"
			LINUX_ro_mmap_base=$((map_addr))
			LINUX_ro_mmap_size=$((size))
			LINUX_ro_mmap_reqlen=$((length))
			LINUX_ro_mmap_off=$((offset))
		else
			LINUX_ro_mmap_path=""
		fi
	fi

	if ((offset < fsize)); then
		declare -i avail=$((fsize - offset))
		((avail > length)) && avail=$((length))
		load_file_slice_to_memory "${fpath}" $((map_addr)) $((offset)) $((avail))
	fi
	ret=$((map_addr))
}

# uname(buf): struct utsname has 6 fields of 65 bytes each.
function linux_sys_uname() {
	declare -ri buf="$1"
	declare -ri field=65
	set_memory_string $((buf + 0 * field)) "Linux" $((field))
	set_memory_string $((buf + 1 * field)) "spleen" $((field))
	set_memory_string $((buf + 2 * field)) "6.1.0-spleen" $((field))
	set_memory_string $((buf + 3 * field)) "#1 SMP bash" $((field))
	set_memory_string $((buf + 4 * field)) "x86_64" $((field))
	set_memory_string $((buf + 5 * field)) "(none)" $((field))
	ret=0
}

function linux_sys_arch_prctl() {
	declare -ri code="$1" addr="$2"
	ret=0
	case $((code)) in
	$((LINUX_ARCH_SET_FS)))
		GLOBAL_fs_base=$((addr))
		;;
	$((LINUX_ARCH_SET_GS)))
		GLOBAL_gs_base=$((addr))
		;;
	$((LINUX_ARCH_GET_FS)))
		set_memory 8 $((addr)) $((GLOBAL_fs_base))
		;;
	$((LINUX_ARCH_GET_GS)))
		set_memory 8 $((addr)) $((GLOBAL_gs_base))
		;;
	*)
		ret=-LINUX_EINVAL
		;;
	esac
}

# clock_gettime(clockid, tp): every clock reads the wall clock.
function linux_sys_clock_gettime() {
	declare -ri clockid="$1" tp="$2"
	declare -i now_sec now_nsec
	linux_time_now
	set_memory 8 $((tp)) $((now_sec))
	set_memory 8 $((tp + 8)) $((now_nsec))
	ret=0
}

# gettimeofday(tv, tz): tz is ignored.
function linux_sys_gettimeofday() {
	declare -ri tv="$1"
	declare -i now_sec now_nsec
	linux_time_now
	if ((tv)); then
		set_memory 8 $((tv)) $((now_sec))
		set_memory 8 $((tv + 8)) $((now_nsec / 1000))
	fi
	ret=0
}

# time(tloc)
function linux_sys_time() {
	declare -ri tloc="$1"
	declare -i now_sec now_nsec
	linux_time_now
	if ((tloc)); then
		set_memory 8 $((tloc)) $((now_sec))
	fi
	ret=$((now_sec))
}

# Linux x86_64 system calls. The number is in rax, arguments in rdi, rsi, rdx,
# r10, r8 and r9. The result goes to rax, a negative errno on failure. Like
# the real `syscall` instruction, rcx receives the return rip and r11 rflags.
#
# Unknown system calls return -ENOSYS (and print a DEBUG message) rather than
# aborting: libc start-up code routinely probes for optional system calls and
# copes with ENOSYS.
function syscall_linux() {
	declare -ri nr=${registers[RAX]:-0}
	declare -ri a0=${registers[RDI]:-0}
	declare -ri a1=${registers[RSI]:-0}
	declare -ri a2=${registers[RDX]:-0}
	declare -ri a3=${registers[R10]:-0}
	declare -ri a4=${registers[R8]:-0}
	declare -ri a5=${registers[R9]:-0}
	declare -i ret=0

	debug "Linux syscall %d (%x, %x, %x, %x, %x, %x)" \
		$((nr)) $((a0)) $((a1)) $((a2)) $((a3)) $((a4)) $((a5))

	case $((nr)) in
	0) # read
		linux_sys_read $((a0)) $((a1)) $((a2))
		;;
	1) # write
		linux_sys_write $((a0)) $((a1)) $((a2))
		;;
	2) # open
		linux_sys_openat $((LINUX_AT_FDCWD)) $((a0)) $((a1)) $((a2))
		;;
	3) # close
		linux_sys_close $((a0))
		;;
	4) # stat
		linux_sys_newfstatat $((LINUX_AT_FDCWD)) $((a0)) $((a1)) 0
		;;
	5) # fstat
		linux_sys_fstat $((a0)) $((a1))
		;;
	6) # lstat
		linux_sys_newfstatat $((LINUX_AT_FDCWD)) $((a0)) $((a1)) $((LINUX_AT_SYMLINK_NOFOLLOW))
		;;
	8) # lseek
		linux_sys_lseek $((a0)) $((a1)) $((a2))
		;;
	9) # mmap
		linux_sys_mmap $((a0)) $((a1)) $((a2)) $((a3)) $((a4)) $((a5))
		;;
	10) # mprotect: nothing to do, memory is not protected
		ret=0
		;;
	11) # munmap
		LINUX_ro_mmap_path=""
		ret=0
		;;
	12) # brk
		linux_sys_brk $((a0))
		;;
	13 | 14) # rt_sigaction, rt_sigprocmask: signals are never delivered
		ret=0
		;;
	16) # ioctl: no file descriptor is a terminal
		ret=-LINUX_ENOTTY
		;;
	17) # pread64
		linux_sys_pread64 $((a0)) $((a1)) $((a2)) $((a3))
		;;
	20) # writev
		linux_sys_writev $((a0)) $((a1)) $((a2))
		;;
	21) # access
		linux_sys_faccessat $((LINUX_AT_FDCWD)) $((a0)) $((a1))
		;;
	32) # dup
		linux_sys_fcntl $((a0)) 0 0
		;;
	39 | 186) # getpid, gettid
		ret=$$
		;;
	60 | 231) # exit, exit_group
		debug "SYSCALL EXIT: exiting with code: %d" $((a0 & 0xff))
		exit $((a0 & 0xff))
		;;
	63) # uname
		linux_sys_uname $((a0))
		;;
	72) # fcntl
		linux_sys_fcntl $((a0)) $((a1)) $((a2))
		;;
	79) # getcwd
		linux_sys_getcwd $((a0)) $((a1))
		;;
	89) # readlink
		linux_sys_readlinkat $((LINUX_AT_FDCWD)) $((a0)) $((a1)) $((a2))
		;;
	96) # gettimeofday
		linux_sys_gettimeofday $((a0))
		;;
	97) # getrlimit
		linux_sys_prlimit64 0 $((a0)) 0 $((a1))
		;;
	102) # getuid
		ret=${UID}
		;;
	104 | 108) # getgid, getegid
		ret=${GROUPS[0]:-0}
		;;
	107) # geteuid
		ret=${EUID}
		;;
	110) # getppid
		ret=${PPID:-1}
		;;
	111) # getpgrp
		ret=$$
		;;
	118) # getresuid
		linux_sys_getresuid $((a0)) $((a1)) $((a2))
		;;
	120) # getresgid
		linux_sys_getresgid $((a0)) $((a1)) $((a2))
		;;
	158) # arch_prctl
		linux_sys_arch_prctl $((a0)) $((a1))
		;;
	201) # time
		linux_sys_time $((a0))
		;;
	202 | 273) # futex, set_robust_list
		ret=0
		;;
	218) # set_tid_address: returns the thread id
		ret=$$
		;;
	228) # clock_gettime
		linux_sys_clock_gettime $((a0)) $((a1))
		;;
	257) # openat
		linux_sys_openat $((a0)) $((a1)) $((a2)) $((a3))
		;;
	262) # newfstatat
		linux_sys_newfstatat $((a0)) $((a1)) $((a2)) $((a3))
		;;
	267) # readlinkat
		linux_sys_readlinkat $((a0)) $((a1)) $((a2)) $((a3))
		;;
	269 | 439) # faccessat, faccessat2
		linux_sys_faccessat $((a0)) $((a1)) $((a2))
		;;
	302) # prlimit64
		linux_sys_prlimit64 $((a0)) $((a1)) $((a2)) $((a3))
		;;
	318) # getrandom
		linux_sys_getrandom $((a0)) $((a1)) $((a2))
		;;
	334) # rseq
		ret=-LINUX_ENOSYS
		;;
	*)
		debug "Unimplemented Linux syscall %d, returning -ENOSYS" $((nr))
		ret=-LINUX_ENOSYS
		;;
	esac

	registers[RAX]=$((ret))
	registers[RCX]=$((${rip:-0} + ${advance:-0}))
	registers[R11]=$((LINUX_SYSCALL_RFLAGS))
}

function run() {
	declare -i rip=$((GLOBAL_text_vmaddr + GLOBAL_entryoff))
	declare -i rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 operand_size_prefix=0

	while true; do
		step
	done
}

function init() {
	typeset -i i
	[[ -n "${memory[@]+x}" ]] || memory=()
	for ((i = 0; i < 16; i++)); do
		registers[$i]=0
	done
	registers[${RSP}]=$((0x10000))
}

# Prints "macho" or "elf" depending on the magic number of `binary_file`.
function binary_format() {
	[[ -r "${binary_file}" ]] || die "Can't read binary: ${binary_file}"
	declare -r magic=$(hexdump -n 4 -v -e '4/1 "%02x"' "${binary_file}")
	case "${magic}" in
	7f454c46)
		echo elf
		;;
	cffaedfe)
		echo macho
		;;
	*)
		die "Unknown binary format (magic: ${magic})"
		;;
	esac
}

function main() {
	declare -r binary_file="$1"
	declare format
	# Separate assignment so that set -e catches a failing binary_format.
	format=$(binary_format)
	# The macOS loader reads the binary through a pipe that replaces stdin.
	# Keep the original stdin on fd 3 and give it back to the emulated program.
	case "${format}" in
	macho)
		{
			dump_file | (
				init
				load_macho_file
				run 0<&3 3<&-
			)
		} 3<&0
		;;
	elf)
		(
			init
			load_elf_file "$@"
			run
		)
		;;
	esac
}
