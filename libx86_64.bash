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
# Load address used for ET_DYN (static-pie) binaries.
declare -ri ELF_DYN_BASE=$((0x555555554000))
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
# Next address handed out by anonymous mmap (bump allocator, never reused).
declare -i GLOBAL_linux_mmap_next=$((0x7f0000000000))
# FS/GS segment bases as set by arch_prctl. Nothing uses them for memory
# addressing (yet); they are only stored.
declare -i GLOBAL_fs_base=0
declare -i GLOBAL_gs_base=0

# Insanity
declare -ia memory=()

declare -ia registers=()

# 128-bit SSE/SSE2 registers XMM0-XMM15 (low and high 64-bit halves).
declare -ia xmm_lo=()
declare -ia xmm_hi=()

# Time-stamp counter and MXCSR state.
declare -i GLOBAL_tsc=0
declare -i GLOBAL_mxcsr=$((0x1f80))

# Instruction decoding state. Shadowed by run(), declared globally so that the
# instruction helpers can be used directly (e.g. by the tests).
declare -i rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 operand_size_prefix=0
declare -i addr_size_prefix=0 seg_override=0 seg_base=0 rep_prefix=0
declare -i rip=0 advance=0 val=0 cond=0 displacement=0
declare -i modrm=0 modrm_mod=0 modrm_reg=0 modrm_rm=0 modrm_address=0

# Pre-declared integer scratch variables for hot execution helpers to avoid
# per-instruction `declare -i` overhead in step().
declare -i step_op=0 step_op2=0 step_width=0 step_imm_bytes=0
declare -i step_a=0 step_b=0 step_c=0 step_d=0
declare -i _da=0 _om_m=0 _om_imm=0 _om_disp=0 _om_sib=0 _om_base=0 _om_index=0 _om_a=0
declare -i _rma=0 _wma=0 _wmv=0 _alu_r=0 _alu_mask=0 _alu_sbit=0 _alu_carry=0
declare -i _ibo_op=0 _ibo_modrm=0 _ibo_w=0 _ibo_a=0 _ibo_b=0
declare -i slo=0 shi=0 dlo=0 dhi=0 rlo=0 rhi=0
declare -i _xi=0 _xda=0 _xsb=0 _xv=0 _xres=0 _xmask=0 _xlo=0 _xhi=0

# RFLAGS, one variable per flag.
declare -i flag_cf=0 flag_pf=0 flag_af=0 flag_zf=0 flag_sf=0 flag_of=0 flag_df=0
declare -ri INT64_MIN=$((1 << 63))

# parity_table[byte] is 1 when byte has an even number of bits set (PF).
declare -ia parity_table=()
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

# Copies `filesz` bytes of the segment in memory and zero fills up to
# `memsz` (.bss).
function load_elf_segment() {
	declare -ri vaddr="$1" offset="$2" filesz="$3" memsz="$4"
	declare -i i
	((offset >= 0 && offset + filesz <= ${#file_bytes[@]})) ||
		die "ELF: segment at offset 0x%x (size 0x%x) is out of file bounds" \
			$((offset)) $((filesz))
	((filesz <= memsz)) ||
		die "ELF: segment at 0x%x has p_filesz > p_memsz" $((vaddr))
	debug "ELF: loading segment vaddr: %x offset: %x filesz: %x memsz: %x" \
		$((vaddr)) $((offset)) $((filesz)) $((memsz))
	for ((i = 0; i < filesz; i++)); do
		((memory[vaddr + i] = file_bytes[offset + i])) || :
	done
	for ((; i < memsz; i++)); do
		((memory[vaddr + i] = 0)) || :
	done
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
function setup_linux_stack() {
	declare -ri entry="$1" phdr="$2" phentsize="$3" phnum="$4"
	shift 4
	declare -a args=("$@")
	declare -ri argc=$#
	declare -i sp=$((registers[RSP]))
	declare -ia argv_ptrs=()
	declare -i i

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
		$((AT_BASE)) 0
		$((AT_ENTRY)) $((entry))
		$((AT_UID)) 0
		$((AT_EUID)) 0
		$((AT_GID)) 0
		$((AT_EGID)) 0
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

# Loads a static Linux ELF64 x86_64 executable from `binary_file`.
# Arguments are the guest argv (argv[0] included).
function load_elf_file() {
	declare -a file_bytes
	read_file_bytes
	declare -ri file_size=${#file_bytes[@]}

	#typedef struct {
	#	unsigned char e_ident[16]; /* 0: magic, class, data, version... */
	#	uint16_t e_type;           /* 16 */
	#	uint16_t e_machine;        /* 18 */
	#	uint32_t e_version;        /* 20 */
	#	uint64_t e_entry;          /* 24 */
	#	uint64_t e_phoff;          /* 32 */
	#	uint64_t e_shoff;          /* 40 */
	#	uint32_t e_flags;          /* 48 */
	#	uint16_t e_ehsize;         /* 52 */
	#	uint16_t e_phentsize;      /* 54 */
	#	uint16_t e_phnum;          /* 56 */
	#	...
	#} Elf64_Ehdr;
	((file_size >= 64)) || die "ELF: file too small"
	((file_bytes[0] == 0x7f && file_bytes[1] == 0x45 &&
		file_bytes[2] == 0x4c && file_bytes[3] == 0x46)) ||
		die "ELF: can't find magic number"
	((file_bytes[4] == ELFCLASS64)) ||
		die "ELF: only 64 bit (ELFCLASS64) binaries are supported"
	((file_bytes[5] == ELFDATA2LSB)) ||
		die "ELF: only little endian binaries are supported"

	declare -i e_type e_machine e_entry e_phoff e_phentsize e_phnum
	le_bytes e_type 16 2
	le_bytes e_machine 18 2
	le_bytes e_entry 24 8
	le_bytes e_phoff 32 8
	le_bytes e_phentsize 54 2
	le_bytes e_phnum 56 2

	((e_machine == EM_X86_64)) ||
		die "ELF: unsupported machine %d, only x86_64 (%d) is supported" \
			$((e_machine)) $((EM_X86_64))

	declare -i load_base=0
	case $((e_type)) in
	$((ET_EXEC))) ;;
	$((ET_DYN)))
		# static-pie: load at a fixed base.
		load_base=$((ELF_DYN_BASE))
		;;
	*)
		die "ELF: unsupported type %d, not an executable" $((e_type))
		;;
	esac

	((e_phnum > 0)) || die "ELF: no program headers"
	((e_phentsize >= 56)) || die "ELF: invalid e_phentsize %d" $((e_phentsize))
	((e_phoff + e_phnum * e_phentsize <= file_size)) ||
		die "ELF: program headers are out of file bounds"

	#typedef struct {
	#	uint32_t p_type;   /* 0 */
	#	uint32_t p_flags;  /* 4 */
	#	uint64_t p_offset; /* 8 */
	#	uint64_t p_vaddr;  /* 16 */
	#	uint64_t p_paddr;  /* 24 */
	#	uint64_t p_filesz; /* 32 */
	#	uint64_t p_memsz;  /* 40 */
	#	uint64_t p_align;  /* 48 */
	#} Elf64_Phdr;
	declare -i i ph p_type p_flags p_offset p_vaddr p_filesz p_memsz
	# Refuse dynamically linked binaries before loading anything.
	for ((i = 0; i < e_phnum; i++)); do
		((ph = e_phoff + i * e_phentsize)) || :
		le_bytes p_type $((ph)) 4
		((p_type != PT_INTERP)) ||
			die "ELF: dynamically linked binaries (PT_INTERP) are not supported, link with -static"
	done

	declare -i phdr_addr=0 text_vmaddr=-1 image_end=0
	for ((i = 0; i < e_phnum; i++)); do
		((ph = e_phoff + i * e_phentsize)) || :
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
			load_elf_segment $((load_base + p_vaddr)) $((p_offset)) $((p_filesz)) $((p_memsz))
			# The program break starts after the highest loaded segment.
			if ((load_base + p_vaddr + p_memsz > image_end)); then
				((image_end = load_base + p_vaddr + p_memsz)) || :
			fi
			# PF_X: the first executable segment plays the role of __TEXT.
			if ((p_flags & 0x1 && text_vmaddr < 0)); then
				((text_vmaddr = load_base + p_vaddr)) || :
			fi
			# Program headers mapped by this segment (for AT_PHDR).
			if ((phdr_addr == 0 && e_phoff >= p_offset &&
				e_phoff < p_offset + p_filesz)); then
				((phdr_addr = load_base + p_vaddr + e_phoff - p_offset)) || :
			fi
			;;
		$((PT_PHDR)))
			((phdr_addr = load_base + p_vaddr)) || :
			;;
		esac
	done

	((text_vmaddr >= 0)) || die "ELF: no executable PT_LOAD segment"

	GLOBAL_os_abi="linux"
	# Page aligned end of the loaded image.
	((GLOBAL_linux_brk_start = (image_end + 0xfff) & ~0xfff)) || :
	# run() starts at GLOBAL_text_vmaddr + GLOBAL_entryoff.
	((GLOBAL_text_vmaddr = text_vmaddr)) || :
	((GLOBAL_entryoff = load_base + e_entry - text_vmaddr)) || :
	debug "ELF: entry point: %x" $((load_base + e_entry))

	setup_linux_stack $((load_base + e_entry)) $((phdr_addr)) \
		$((e_phentsize)) $((e_phnum)) "$@"
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
	case $1 in
	4) ((val = (($2 & 0xffffffff) ^ 0x80000000) - 0x80000000)) || : ;;
	1) ((val = (($2 & 0xff) ^ 0x80) - 0x80)) || : ;;
	2) ((val = (($2 & 0xffff) ^ 0x8000) - 0x8000)) || : ;;
	*) ((val = $2)) || : ;;
	esac
}

# Modifies variables `displacement` and `advance`
function disp64() {
	((_da = rip + advance,
		displacement = memory[_da] | memory[_da + 1] << 8 | memory[_da + 2] << 16 |
			memory[_da + 3] << 24 | memory[_da + 4] << 32 | memory[_da + 5] << 40 |
			memory[_da + 6] << 48 | memory[_da + 7] << 56,
		advance += 8)) || :
}

# Modifies variables `displacement` and `advance`. Sign-extended.
function disp32() {
	((_da = rip + advance,
		displacement = ((memory[_da] | memory[_da + 1] << 8 | memory[_da + 2] << 16 | memory[_da + 3] << 24) ^ 0x80000000) - 0x80000000,
		advance += 4)) || :
}

# Modifies variables `displacement` and `advance`. Sign-extended.
function disp16() {
	((_da = rip + advance,
		displacement = ((memory[_da] | memory[_da + 1] << 8) ^ 0x8000) - 0x8000,
		advance += 2)) || :
}

# Modifies variables `displacement` and `advance`. Sign-extended.
function disp8() {
	((displacement = (memory[rip + advance] ^ 0x80) - 0x80, advance += 1)) || :
}

# Modifies variables `displacement` and `advance`
function disp_width() {
	case $1 in
	4)
		((_da = rip + advance,
			displacement = ((memory[_da] | memory[_da + 1] << 8 | memory[_da + 2] << 16 | memory[_da + 3] << 24) ^ 0x80000000) - 0x80000000,
			advance += 4)) || :
		;;
	1) ((displacement = (memory[rip + advance] ^ 0x80) - 0x80, advance += 1)) || : ;;
	8)
		((_da = rip + advance,
			displacement = memory[_da] | memory[_da + 1] << 8 | memory[_da + 2] << 16 |
				memory[_da + 3] << 24 | memory[_da + 4] << 32 | memory[_da + 5] << 40 |
				memory[_da + 6] << 48 | memory[_da + 7] << 56,
			advance += 8)) || :
		;;
	2)
		((_da = rip + advance,
			displacement = ((memory[_da] | memory[_da + 1] << 8) ^ 0x8000) - 0x8000,
			advance += 2)) || :
		;;
	*) die "Invalid width for immediate value or displacement." ;;
	esac
}

# Sets modrm_mod modrm_reg modrm_rm modrm_address.
# Reads SIB and displacement bytes at rip + advance and updates `advance`.
# `imm_size` is the number of immediate bytes that follow the modrm operand:
# RIP-relative addresses are relative to the end of the instruction.
function operands_modrm() {
	_om_m=$1
	_om_imm=${2:-0}
	((modrm_mod = (_om_m >> 6) & 3,
		modrm_reg = ((_om_m >> 3) & 7) | (rex_r << 3),
		modrm_rm = (_om_m & 7) | (rex_b << 3))) || :

	if ((modrm_mod == 3)); then
		modrm_address=0
		return 0
	fi

	if (((_om_m & 7) == 4)); then
		# SIB byte
		((_om_sib = memory[rip + advance], advance++,
			_om_index = ((_om_sib >> 3) & 7) | (rex_x << 3),
			_om_base = (_om_sib & 7) | (rex_b << 3))) || :
		if (((_om_sib & 7) == 5 && modrm_mod == 0)); then
			# No base register, disp32 only.
			((_om_a = rip + advance,
				modrm_address = ((memory[_om_a] | memory[_om_a + 1] << 8 | memory[_om_a + 2] << 16 | memory[_om_a + 3] << 24) ^ 0x80000000) - 0x80000000,
				advance += 4)) || :
		else
			((modrm_address = registers[_om_base])) || :
		fi
		# index 4 (rsp) means no index. r12 (with REX.X) is a valid index.
		if ((_om_index != 4)); then
			((modrm_address += registers[_om_index] << ((_om_sib >> 6) & 3))) || :
		fi
	elif (((_om_m & 7) == 5 && modrm_mod == 0)); then
		# RIP addressing, relative to the address of the next instruction.
		((_om_a = rip + advance,
			_om_disp = ((memory[_om_a] | memory[_om_a + 1] << 8 | memory[_om_a + 2] << 16 | memory[_om_a + 3] << 24) ^ 0x80000000) - 0x80000000,
			advance += 4,
			modrm_address = rip + advance + _om_imm + _om_disp)) || :
	else
		((modrm_address = registers[modrm_rm])) || :
	fi

	case ${modrm_mod} in
	1)
		((modrm_address += (memory[rip + advance] ^ 0x80) - 0x80, advance += 1)) || :
		;;
	2)
		((_om_a = rip + advance,
			modrm_address += ((memory[_om_a] | memory[_om_a + 1] << 8 | memory[_om_a + 2] << 16 | memory[_om_a + 3] << 24) ^ 0x80000000) - 0x80000000,
			advance += 4)) || :
		;;
	esac

	if ((addr_size_prefix)); then
		((modrm_address &= 0xffffffff)) || :
	fi
	if ((seg_base)); then
		((modrm_address += seg_base)) || :
	fi
}

# Sets `val` to the zero-extended value of register `reg` of `width` bytes.
# Byte registers 4-7 are AH, CH, DH, BH unless a REX prefix is present.
function read_reg() {
	case $1 in
	8) ((val = registers[$2])) || : ;;
	4) ((val = registers[$2] & 0xffffffff)) || : ;;
	1)
		if (($2 >= 4 && $2 < 8 && !rex)); then
			((val = (registers[$2 - 4] >> 8) & 0xff)) || :
		else
			((val = registers[$2] & 0xff)) || :
		fi
		;;
	2) ((val = registers[$2] & 0xffff)) || : ;;
	*) die "Unsupported data width in read_reg: $1" ;;
	esac
}

# Writes register `reg`. 32-bit writes zero the upper half of the register,
# 8 and 16-bit writes preserve the other bits.
function write_reg() {
	case $1 in
	8) ((registers[$2] = $3)) || : ;;
	4) ((registers[$2] = $3 & 0xffffffff)) || : ;;
	1)
		if (($2 >= 4 && $2 < 8 && !rex)); then
			((registers[$2 - 4] = (registers[$2 - 4] & ~0xff00) | (($3 & 0xff) << 8))) || :
		else
			((registers[$2] = (registers[$2] & ~0xff) | ($3 & 0xff))) || :
		fi
		;;
	2) ((registers[$2] = (registers[$2] & ~0xffff) | ($3 & 0xffff))) || : ;;
	*) die "Unsupported data width in write_reg: $1" ;;
	esac
}

# Sets `val` to the little endian value of `width` bytes at `address`.
function read_mem() {
	_rma=$2
	case $1 in
	8)
		((val = memory[_rma] | memory[_rma + 1] << 8 | memory[_rma + 2] << 16 |
			memory[_rma + 3] << 24 | memory[_rma + 4] << 32 | memory[_rma + 5] << 40 |
			memory[_rma + 6] << 48 | memory[_rma + 7] << 56)) || :
		;;
	4) ((val = memory[_rma] | memory[_rma + 1] << 8 | memory[_rma + 2] << 16 | memory[_rma + 3] << 24)) || : ;;
	1) ((val = memory[_rma])) || : ;;
	2) ((val = memory[_rma] | memory[_rma + 1] << 8)) || : ;;
	*) die "Unsupported data width in read_mem: $1" ;;
	esac
}

function write_mem() {
	_wma=$2
	_wmv=$3
	case $1 in
	8)
		((memory[_wma] = _wmv & 0xff, memory[_wma + 1] = (_wmv >> 8) & 0xff,
			memory[_wma + 2] = (_wmv >> 16) & 0xff, memory[_wma + 3] = (_wmv >> 24) & 0xff,
			memory[_wma + 4] = (_wmv >> 32) & 0xff, memory[_wma + 5] = (_wmv >> 40) & 0xff,
			memory[_wma + 6] = (_wmv >> 48) & 0xff, memory[_wma + 7] = (_wmv >> 56) & 0xff)) || :
		;;
	4)
		((memory[_wma] = _wmv & 0xff, memory[_wma + 1] = (_wmv >> 8) & 0xff,
			memory[_wma + 2] = (_wmv >> 16) & 0xff, memory[_wma + 3] = (_wmv >> 24) & 0xff)) || :
		;;
	1) ((memory[_wma] = _wmv & 0xff)) || : ;;
	2) ((memory[_wma] = _wmv & 0xff, memory[_wma + 1] = (_wmv >> 8) & 0xff)) || : ;;
	*) die "Unsupported data width in write_mem: $1" ;;
	esac
}

# Read/write the r/m operand decoded by operands_modrm.
function read_rm() {
	if ((modrm_mod == 3)); then
		case $1 in
		8) ((val = registers[modrm_rm])) || : ;;
		4) ((val = registers[modrm_rm] & 0xffffffff)) || : ;;
		*) read_reg "$1" "${modrm_rm}" ;;
		esac
	else
		_rma=${modrm_address}
		case $1 in
		8)
			((val = memory[_rma] | memory[_rma + 1] << 8 | memory[_rma + 2] << 16 |
				memory[_rma + 3] << 24 | memory[_rma + 4] << 32 | memory[_rma + 5] << 40 |
				memory[_rma + 6] << 48 | memory[_rma + 7] << 56)) || :
			;;
		4) ((val = memory[_rma] | memory[_rma + 1] << 8 | memory[_rma + 2] << 16 | memory[_rma + 3] << 24)) || : ;;
		1) ((val = memory[_rma])) || : ;;
		2) ((val = memory[_rma] | memory[_rma + 1] << 8)) || : ;;
		*) die "Unsupported data width in read_rm: $1" ;;
		esac
	fi
}

function write_rm() {
	if ((modrm_mod == 3)); then
		case $1 in
		8) ((registers[modrm_rm] = $2)) || : ;;
		4) ((registers[modrm_rm] = $2 & 0xffffffff)) || : ;;
		*) write_reg "$1" "${modrm_rm}" "$2" ;;
		esac
	else
		_wma=${modrm_address}
		_wmv=$2
		case $1 in
		8)
			((memory[_wma] = _wmv & 0xff, memory[_wma + 1] = (_wmv >> 8) & 0xff,
				memory[_wma + 2] = (_wmv >> 16) & 0xff, memory[_wma + 3] = (_wmv >> 24) & 0xff,
				memory[_wma + 4] = (_wmv >> 32) & 0xff, memory[_wma + 5] = (_wmv >> 40) & 0xff,
				memory[_wma + 6] = (_wmv >> 48) & 0xff, memory[_wma + 7] = (_wmv >> 56) & 0xff)) || :
			;;
		4)
			((memory[_wma] = _wmv & 0xff, memory[_wma + 1] = (_wmv >> 8) & 0xff,
				memory[_wma + 2] = (_wmv >> 16) & 0xff, memory[_wma + 3] = (_wmv >> 24) & 0xff)) || :
			;;
		1) ((memory[_wma] = _wmv & 0xff)) || : ;;
		2) ((memory[_wma] = _wmv & 0xff, memory[_wma + 1] = (_wmv >> 8) & 0xff)) || : ;;
		*) die "Unsupported data width in write_rm: $1" ;;
		esac
	fi
}

function push64() {
	((_wma = registers[RSP] - 8, registers[RSP] = _wma, _wmv = $1,
		memory[_wma] = _wmv & 0xff, memory[_wma + 1] = (_wmv >> 8) & 0xff,
		memory[_wma + 2] = (_wmv >> 16) & 0xff, memory[_wma + 3] = (_wmv >> 24) & 0xff,
		memory[_wma + 4] = (_wmv >> 32) & 0xff, memory[_wma + 5] = (_wmv >> 40) & 0xff,
		memory[_wma + 6] = (_wmv >> 48) & 0xff, memory[_wma + 7] = (_wmv >> 56) & 0xff)) || :
}

# Sets `val`
function pop64() {
	((_rma = registers[RSP], registers[RSP] = _rma + 8,
		val = memory[_rma] | memory[_rma + 1] << 8 | memory[_rma + 2] << 16 |
			memory[_rma + 3] << 24 | memory[_rma + 4] << 32 | memory[_rma + 5] << 40 |
			memory[_rma + 6] << 48 | memory[_rma + 7] << 56)) || :
}

### Flags ###

# Sets ZF, SF and PF from `result` of `width` bytes.
function set_result_flags() {
	((flag_zf = $2 == 0,
		flag_sf = ($2 >> ($1 * 8 - 1)) & 1,
		flag_pf = parity_table[$2 & 0xff])) || :
}

# Returns RFLAGS as an integer.
function get_rflags() {
	echo $((flag_cf | flag_pf << 2 | flag_af << 4 | flag_zf << 6 | flag_sf << 7 |
		flag_df << 10 | flag_of << 11 | 0x2))
}

# Sets `cond` to 1 when condition code `cc` (low nibble of jcc/setcc/cmovcc
# opcodes) holds, 0 otherwise.
function eval_cond() {
	case $((($1 >> 1) & 7)) in
	0) ((cond = flag_of ^ ($1 & 1))) || : ;;                        # o / no
	1) ((cond = flag_cf ^ ($1 & 1))) || : ;;                        # b / ae
	2) ((cond = flag_zf ^ ($1 & 1))) || : ;;                        # e / ne
	3) ((cond = (flag_cf | flag_zf) ^ ($1 & 1))) || : ;;            # be / a
	4) ((cond = flag_sf ^ ($1 & 1))) || : ;;                        # s / ns
	5) ((cond = flag_pf ^ ($1 & 1))) || : ;;                        # p / np
	6) ((cond = (flag_sf != flag_of) ^ ($1 & 1))) || : ;;           # l / ge
	7) ((cond = (flag_zf | (flag_sf != flag_of)) ^ ($1 & 1))) || : ;; # le / g
	esac
}

# Arithmetic/logic operation number `op` as encoded in opcodes 00-3F and
# group 1 (0=add 1=or 2=adc 3=sbb 4=and 5=sub 6=xor 7=cmp) on zero-extended
# operands `a` and `b` of `width` bytes. Sets `val` and the flags.
function alu() {
	((_alu_mask = $2 == 8 ? -1 : (1 << ($2 * 8)) - 1, _alu_sbit = $2 * 8 - 1)) || :
	case $1 in
	0)
		((_alu_r = ($3 + $4) & _alu_mask,
			flag_cf = (_alu_r ^ INT64_MIN) < ($3 ^ INT64_MIN),
			flag_of = ((($3 ^ _alu_r) & ($4 ^ _alu_r)) >> _alu_sbit) & 1)) || :
		;;
	5 | 7)
		((_alu_r = ($3 - $4) & _alu_mask,
			flag_cf = ($3 ^ INT64_MIN) < ($4 ^ INT64_MIN),
			flag_of = ((($3 ^ $4) & ($3 ^ _alu_r)) >> _alu_sbit) & 1)) || :
		;;
	4) ((_alu_r = $3 & $4, flag_cf = 0, flag_of = 0)) || : ;;
	6) ((_alu_r = ($3 ^ $4) & _alu_mask, flag_cf = 0, flag_of = 0)) || : ;;
	1) ((_alu_r = ($3 | $4) & _alu_mask, flag_cf = 0, flag_of = 0)) || : ;;
	2)
		((_alu_carry = flag_cf,
			_alu_r = ($3 + $4 + _alu_carry) & _alu_mask,
			flag_cf = _alu_carry ? ((_alu_r ^ INT64_MIN) <= ($3 ^ INT64_MIN)) : ((_alu_r ^ INT64_MIN) < ($3 ^ INT64_MIN)),
			flag_of = ((($3 ^ _alu_r) & ($4 ^ _alu_r)) >> _alu_sbit) & 1)) || :
		;;
	3)
		((_alu_carry = flag_cf,
			_alu_r = ($3 - $4 - _alu_carry) & _alu_mask,
			flag_cf = _alu_carry ? (($3 ^ INT64_MIN) <= ($4 ^ INT64_MIN)) : (($3 ^ INT64_MIN) < ($4 ^ INT64_MIN)),
			flag_of = ((($3 ^ $4) & ($3 ^ _alu_r)) >> _alu_sbit) & 1)) || :
		;;
	esac
	((flag_af = (($3 ^ $4 ^ _alu_r) >> 4) & 1,
		flag_zf = _alu_r == 0,
		flag_sf = (_alu_r >> _alu_sbit) & 1,
		flag_pf = parity_table[_alu_r & 0xff],
		val = _alu_r)) || :
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
	((_ibo_op = ($1 >> 3) & 7,
		_ibo_w = ($1 & 1) == 0 ? 1 : rex_w ? 8 : operand_size_prefix ? 2 : 4)) || :
	operands_modrm "$2"
	read_rm "${_ibo_w}"
	_ibo_a=${val}
	read_reg "${_ibo_w}" "${modrm_reg}"
	_ibo_b=${val}
	if ((($1 & 0xfe) == 0x84)); then
		alu 4 "${_ibo_w}" "${_ibo_a}" "${_ibo_b}" # test
		return 0
	fi
	if ((($1 >> 1) & 1)); then
		alu "${_ibo_op}" "${_ibo_w}" "${_ibo_b}" "${_ibo_a}"
		if ((_ibo_op != 7)); then
			write_reg "${_ibo_w}" "${modrm_reg}" "${val}"
		fi
	else
		alu "${_ibo_op}" "${_ibo_w}" "${_ibo_a}" "${_ibo_b}"
		if ((_ibo_op != 7)); then
			write_rm "${_ibo_w}" "${val}"
		fi
	fi
}

# 88-8B
function inst_mov() {
	((_ibo_w = ($1 & 1) == 0 ? 1 : rex_w ? 8 : operand_size_prefix ? 2 : 4)) || :
	operands_modrm "$2"
	if ((($1 >> 1) & 1)); then
		read_rm "${_ibo_w}"
		write_reg "${_ibo_w}" "${modrm_reg}" "${val}"
	else
		read_reg "${_ibo_w}" "${modrm_reg}"
		write_rm "${_ibo_w}" "${val}"
	fi
}

function inst_lea() {
	seg_base=0
	operands_modrm "$2"
	write_reg "$((rex_w ? 8 : operand_size_prefix ? 2 : 4))" "${modrm_reg}" "${modrm_address}"
}

# B0-BF. B8-BF with REX.W is movabs with a 64-bit immediate.
function inst_mov_imm() {
	((_ibo_w = $1 < 184 ? 1 : rex_w ? 8 : operand_size_prefix ? 2 : 4)) || :
	disp_width "${_ibo_w}"
	write_reg "${_ibo_w}" "$(($1 & 7 | rex_b << 3))" "${displacement}"
}

function inst_push() {
	push64 "${registers[$1]}"
}

# Bit test helper: $1=op (0=bt,1=bts,2=btr,3=btc), $2=width, $3=bit, $4=is_mem, $5=addr.
function exec_bit_op() {
	if (($4 == 0)); then
		read_reg "$2" "${modrm_rm}"
		((flag_cf = (val >> $3) & 1)) || :
		case $1 in
		1) write_reg "$2" "${modrm_rm}" "$((val | (1 << $3)))" ;;
		2) write_reg "$2" "${modrm_rm}" "$((val & ~(1 << $3)))" ;;
		3) write_reg "$2" "${modrm_rm}" "$((val ^ (1 << $3)))" ;;
		esac
	else
		read_mem "$2" "$5"
		((flag_cf = (val >> $3) & 1)) || :
		case $1 in
		1) write_mem "$2" "$5" "$((val | (1 << $3)))" ;;
		2) write_mem "$2" "$5" "$((val & ~(1 << $3)))" ;;
		3) write_mem "$2" "$5" "$((val ^ (1 << $3)))" ;;
		esac
	fi
}

### SSE / SSE2 helpers ###

function read_xmm_rm() {
	if ((modrm_mod == 3)); then
		((slo = xmm_lo[modrm_rm], shi = xmm_hi[modrm_rm])) || :
	else
		((_rma = modrm_address,
			slo = memory[_rma] | memory[_rma + 1] << 8 | memory[_rma + 2] << 16 |
				memory[_rma + 3] << 24 | memory[_rma + 4] << 32 | memory[_rma + 5] << 40 |
				memory[_rma + 6] << 48 | memory[_rma + 7] << 56,
			_rma += 8,
			shi = memory[_rma] | memory[_rma + 1] << 8 | memory[_rma + 2] << 16 |
				memory[_rma + 3] << 24 | memory[_rma + 4] << 32 | memory[_rma + 5] << 40 |
				memory[_rma + 6] << 48 | memory[_rma + 7] << 56)) || :
	fi
}

function write_xmm_rm() {
	if ((modrm_mod == 3)); then
		((xmm_lo[modrm_rm] = $1, xmm_hi[modrm_rm] = $2)) || :
	else
		write_mem 8 "${modrm_address}" "$1"
		write_mem 8 "$((modrm_address + 8))" "$2"
	fi
}

function sse_unpack_bw() {
	((rlo = ($1 & 0xff) | (($2 & 0xff) << 8) |
		((($1 >> 8) & 0xff) << 16) | ((($2 >> 8) & 0xff) << 24) |
		((($1 >> 16) & 0xff) << 32) | ((($2 >> 16) & 0xff) << 40) |
		((($1 >> 24) & 0xff) << 48) | ((($2 >> 24) & 0xff) << 56),
		rhi = (($1 >> 32) & 0xff) | ((($2 >> 32) & 0xff) << 8) |
			((($1 >> 40) & 0xff) << 16) | ((($2 >> 40) & 0xff) << 24) |
			((($1 >> 48) & 0xff) << 32) | ((($2 >> 48) & 0xff) << 40) |
			((($1 >> 56) & 0xff) << 48) | ((($2 >> 56) & 0xff) << 56))) || :
}

function sse_unpack_wd() {
	((rlo = ($1 & 0xffff) | (($2 & 0xffff) << 16) |
		((($1 >> 16) & 0xffff) << 32) | ((($2 >> 16) & 0xffff) << 48),
		rhi = (($1 >> 32) & 0xffff) | ((($2 >> 32) & 0xffff) << 16) |
			((($1 >> 48) & 0xffff) << 32) | ((($2 >> 48) & 0xffff) << 48))) || :
}

# Byte-wise op ($1: 0=pminub 1=pmaxub 2=pcmpgtb 3=psubusb 4=paddusb) on 8 bytes of $2 and $3 -> _xres.
function sse_byte_half() {
	_xres=0
	for ((_xi = 0; _xi < 64; _xi += 8)); do
		((_xda = ($2 >> _xi) & 0xff, _xsb = ($3 >> _xi) & 0xff)) || :
		case $1 in
		0) ((_xv = _xda < _xsb ? _xda : _xsb)) || : ;;
		1) ((_xv = _xda > _xsb ? _xda : _xsb)) || : ;;
		2) ((_xv = ((_xda ^ 0x80) - 0x80) > ((_xsb ^ 0x80) - 0x80) ? 0xff : 0)) || : ;;
		3) ((_xv = _xda > _xsb ? _xda - _xsb : 0)) || : ;;
		4) ((_xv = _xda + _xsb > 255 ? 255 : _xda + _xsb)) || : ;;
		esac
		((_xres |= _xv << _xi)) || :
	done
}

# Word-wise compare ($1: 0=pcmpeqw 1=pcmpgtw) on 4 words of $2 and $3 -> _xres.
function sse_word_half() {
	_xres=0
	for ((_xi = 0; _xi < 64; _xi += 16)); do
		((_xda = ($2 >> _xi) & 0xffff, _xsb = ($3 >> _xi) & 0xffff)) || :
		if (($1 == 0)); then
			((_xv = _xda == _xsb ? 0xffff : 0)) || :
		else
			((_xv = ((_xda ^ 0x8000) - 0x8000) > ((_xsb ^ 0x8000) - 0x8000) ? 0xffff : 0)) || :
		fi
		((_xres |= _xv << _xi)) || :
	done
}

# Shifts XMM[$1] by signed/unsigned count $3 with mode $2:
# 0=psrlw 1=psraw 2=psllw 3=psrld 4=psrad 5=pslld 6=psrlq 7=psllq
function sse_shift_xmm() {
	((_xlo = xmm_lo[$1], _xhi = xmm_hi[$1], _xv = $3)) || :
	case $2 in
	0) # psrlw
		if ((_xv < 0 || _xv >= 16)); then
			_xlo=0 _xhi=0
		elif ((_xv > 0)); then
			((_xmask = (0xffff >> _xv) * 0x0001000100010001,
				_xlo = (_xlo >> _xv) & _xmask, _xhi = (_xhi >> _xv) & _xmask)) || :
		fi
		;;
	1) # psraw
		if ((_xv < 0 || _xv > 15)); then _xv=15; fi
		if ((_xv > 0)); then
			rlo=0 rhi=0
			for ((_xi = 0; _xi < 64; _xi += 16)); do
				((_xda = ((((_xlo >> _xi) & 0xffff) ^ 0x8000) - 0x8000) >> _xv,
					_xsb = ((((_xhi >> _xi) & 0xffff) ^ 0x8000) - 0x8000) >> _xv,
					rlo |= (_xda & 0xffff) << _xi,
					rhi |= (_xsb & 0xffff) << _xi)) || :
			done
			_xlo=${rlo} _xhi=${rhi}
		fi
		;;
	2) # psllw
		if ((_xv < 0 || _xv >= 16)); then
			_xlo=0 _xhi=0
		elif ((_xv > 0)); then
			((_xmask = (0xffff >> _xv) * 0x0001000100010001,
				_xlo = (_xlo & _xmask) << _xv, _xhi = (_xhi & _xmask) << _xv)) || :
		fi
		;;
	3) # psrld
		if ((_xv < 0 || _xv >= 32)); then
			_xlo=0 _xhi=0
		elif ((_xv > 0)); then
			((_xmask = (0xffffffff >> _xv) | ((0xffffffff >> _xv) << 32),
				_xlo = (_xlo >> _xv) & _xmask, _xhi = (_xhi >> _xv) & _xmask)) || :
		fi
		;;
	4) # psrad
		if ((_xv < 0 || _xv > 31)); then _xv=31; fi
		if ((_xv > 0)); then
			((rlo = (((((_xlo & 0xffffffff) ^ 0x80000000) - 0x80000000) >> _xv) & 0xffffffff) |
				(((((((_xlo >> 32) & 0xffffffff) ^ 0x80000000) - 0x80000000) >> _xv) & 0xffffffff) << 32),
				rhi = (((((_xhi & 0xffffffff) ^ 0x80000000) - 0x80000000) >> _xv) & 0xffffffff) |
					(((((((_xhi >> 32) & 0xffffffff) ^ 0x80000000) - 0x80000000) >> _xv) & 0xffffffff) << 32),
				_xlo = rlo, _xhi = rhi)) || :
		fi
		;;
	5) # pslld
		if ((_xv < 0 || _xv >= 32)); then
			_xlo=0 _xhi=0
		elif ((_xv > 0)); then
			((_xmask = (0xffffffff >> _xv) | ((0xffffffff >> _xv) << 32),
				_xlo = (_xlo & _xmask) << _xv, _xhi = (_xhi & _xmask) << _xv)) || :
		fi
		;;
	6) # psrlq
		if ((_xv < 0 || _xv >= 64)); then
			_xlo=0 _xhi=0
		elif ((_xv > 0)); then
			((_xmask = (1 << (64 - _xv)) - 1,
				_xlo = (_xlo >> _xv) & _xmask, _xhi = (_xhi >> _xv) & _xmask)) || :
		fi
		;;
	7) # psllq
		if ((_xv < 0 || _xv >= 64)); then
			_xlo=0 _xhi=0
		elif ((_xv > 0)); then
			((_xlo <<= _xv, _xhi <<= _xv)) || :
		fi
		;;
	esac
	((xmm_lo[$1] = _xlo, xmm_hi[$1] = _xhi)) || :
}

# Executes 2-byte `0f <step_op2>` instructions.
function step_0f() {
	((step_op2 = memory[rip + advance], advance++)) || :
	case $((step_op2 & 0xf0)) in
	64) # 0x40-0x4f: cmovcc
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "${step_width}"
		eval_cond "${step_op2}"
		if ((cond)); then
			write_reg "${step_width}" "${modrm_reg}" "${val}"
		elif ((step_width == 4)); then
			# Upper bits are cleared even if the condition is false.
			((registers[modrm_reg] &= 0xffffffff)) || :
		fi
		return 0
		;;
	128) # 0x80-0x8f: jcc rel32
		disp32
		eval_cond "${step_op2}"
		if ((cond)); then ((advance += displacement)) || :; fi
		return 0
		;;
	144) # 0x90-0x9f: setcc
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		eval_cond "${step_op2}"
		write_rm 1 "${cond}"
		return 0
		;;
	esac

	case ${step_op2} in
	5) # 0x05: syscall
		inst_syscall
		;;
	1) # 0x01: xgetbv / rdtscp
		((modrm = memory[rip + advance], advance++)) || :
		case ${modrm} in
		208) # 0xd0: xgetbv (x87 + XMM enabled, YMM/AVX disabled)
			write_reg 4 0 3
			write_reg 4 2 0
			;;
		249) # 0xf9: rdtscp
			((GLOBAL_tsc += 100)) || :
			write_reg 4 0 "$((GLOBAL_tsc & 0xffffffff))"
			write_reg 4 2 "$(((GLOBAL_tsc >> 32) & 0xffffffff))"
			write_reg 4 1 0
			;;
		*)
			unknown_insruction "$(printf '0f 01 %02x' $((modrm)))" "unsupported 0f 01 instruction"
			;;
		esac
		;;
	11) # 0x0b: ud2
		die "Undefined instruction (ud2) at 0x%x" $((rip))
		;;
	16) # 0x10: movups / 66 movupd / f3 movss / f2 movsd (load)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((rep_prefix == 243)); then
			if ((modrm_mod == 3)); then
				((xmm_lo[modrm_reg] = (xmm_lo[modrm_reg] & ~0xffffffff) | (xmm_lo[modrm_rm] & 0xffffffff))) || :
			else
				read_mem 4 "${modrm_address}"
				((xmm_lo[modrm_reg] = val & 0xffffffff, xmm_hi[modrm_reg] = 0)) || :
			fi
		elif ((rep_prefix == 242)); then
			if ((modrm_mod == 3)); then
				((xmm_lo[modrm_reg] = xmm_lo[modrm_rm])) || :
			else
				read_mem 8 "${modrm_address}"
				((xmm_lo[modrm_reg] = val, xmm_hi[modrm_reg] = 0)) || :
			fi
		else
			read_xmm_rm
			((xmm_lo[modrm_reg] = slo, xmm_hi[modrm_reg] = shi)) || :
		fi
		;;
	17) # 0x11: movups / 66 movupd / f3 movss / f2 movsd (store)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((rep_prefix == 243)); then
			if ((modrm_mod == 3)); then
				((xmm_lo[modrm_rm] = (xmm_lo[modrm_rm] & ~0xffffffff) | (xmm_lo[modrm_reg] & 0xffffffff))) || :
			else
				write_mem 4 "${modrm_address}" "$((xmm_lo[modrm_reg] & 0xffffffff))"
			fi
		elif ((rep_prefix == 242)); then
			if ((modrm_mod == 3)); then
				((xmm_lo[modrm_rm] = xmm_lo[modrm_reg])) || :
			else
				write_mem 8 "${modrm_address}" "${xmm_lo[modrm_reg]}"
			fi
		else
			write_xmm_rm "${xmm_lo[modrm_reg]}" "${xmm_hi[modrm_reg]}"
		fi
		;;
	18) # 0x12: f2 movddup / f3 movsldup / movhlps / movlps / 66 movlpd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((rep_prefix == 242)); then
			if ((modrm_mod == 3)); then
				((slo = xmm_lo[modrm_rm])) || :
			else
				read_mem 8 "${modrm_address}"
				slo=${val}
			fi
			((xmm_lo[modrm_reg] = slo, xmm_hi[modrm_reg] = slo)) || :
		elif ((rep_prefix == 243)); then
			read_xmm_rm
			((xmm_lo[modrm_reg] = (slo & 0xffffffff) | ((slo & 0xffffffff) << 32),
				xmm_hi[modrm_reg] = (shi & 0xffffffff) | ((shi & 0xffffffff) << 32))) || :
		elif ((modrm_mod == 3)); then
			((xmm_lo[modrm_reg] = xmm_hi[modrm_rm])) || :
		else
			read_mem 8 "${modrm_address}"
			((xmm_lo[modrm_reg] = val)) || :
		fi
		;;
	19) # 0x13: movlps / 66 movlpd (store)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		write_mem 8 "${modrm_address}" "${xmm_lo[modrm_reg]}"
		;;
	20) # 0x14: unpcklps / 66 unpcklpd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		if ((operand_size_prefix)); then
			((xmm_hi[modrm_reg] = slo)) || :
		else
			((dlo = xmm_lo[modrm_reg],
				xmm_lo[modrm_reg] = (dlo & 0xffffffff) | ((slo & 0xffffffff) << 32),
				xmm_hi[modrm_reg] = ((dlo >> 32) & 0xffffffff) | (((slo >> 32) & 0xffffffff) << 32))) || :
		fi
		;;
	21) # 0x15: unpckhps / 66 unpckhpd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		if ((operand_size_prefix)); then
			((xmm_lo[modrm_reg] = xmm_hi[modrm_reg], xmm_hi[modrm_reg] = shi)) || :
		else
			((dhi = xmm_hi[modrm_reg],
				xmm_lo[modrm_reg] = (dhi & 0xffffffff) | ((shi & 0xffffffff) << 32),
				xmm_hi[modrm_reg] = ((dhi >> 32) & 0xffffffff) | (((shi >> 32) & 0xffffffff) << 32))) || :
		fi
		;;
	22) # 0x16: f3 movshdup / movlhps / movhps / 66 movhpd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((rep_prefix == 243)); then
			read_xmm_rm
			((slo = (slo >> 32) & 0xffffffff, shi = (shi >> 32) & 0xffffffff,
				xmm_lo[modrm_reg] = slo | (slo << 32), xmm_hi[modrm_reg] = shi | (shi << 32))) || :
		elif ((modrm_mod == 3)); then
			((xmm_hi[modrm_reg] = xmm_lo[modrm_rm])) || :
		else
			read_mem 8 "${modrm_address}"
			((xmm_hi[modrm_reg] = val)) || :
		fi
		;;
	23) # 0x17: movhps / 66 movhpd (store)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		write_mem 8 "${modrm_address}" "${xmm_hi[modrm_reg]}"
		;;
	24 | 25 | 26 | 27 | 28 | 29 | 30 | 31) # 0x18-0x1f: hint nops, prefetch, endbr64
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		;;
	40 | 111 | 240) # 0x28 movaps/pd, 0x6f movdqa/dqu, 0xf0 lddqu (load)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] = slo, xmm_hi[modrm_reg] = shi)) || :
		;;
	41 | 43 | 127 | 231) # 0x29 movaps/pd, 0x2b movntps/pd, 0x7f movdqa/dqu, 0xe7 movntdq (store)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		write_xmm_rm "${xmm_lo[modrm_reg]}" "${xmm_hi[modrm_reg]}"
		;;
	49) # 0x31: rdtsc
		((GLOBAL_tsc += 100)) || :
		write_reg 4 0 "$((GLOBAL_tsc & 0xffffffff))"
		write_reg 4 2 "$(((GLOBAL_tsc >> 32) & 0xffffffff))"
		;;
	80) # 0x50: movmskps / 66 movmskpd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		((slo = xmm_lo[modrm_rm], shi = xmm_hi[modrm_rm])) || :
		if ((operand_size_prefix)); then
			write_reg 4 "${modrm_reg}" "$((((slo >> 63) & 1) | (((shi >> 63) & 1) << 1)))"
		else
			write_reg 4 "${modrm_reg}" "$((((slo >> 31) & 1) | (((slo >> 63) & 1) << 1) | (((shi >> 31) & 1) << 2) | (((shi >> 63) & 1) << 3)))"
		fi
		;;
	84 | 219) # 0x54 andps/pd, 0xdb pand
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] &= slo, xmm_hi[modrm_reg] &= shi)) || :
		;;
	85 | 223) # 0x55 andnps/pd, 0xdf pandn
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] = ~xmm_lo[modrm_reg] & slo, xmm_hi[modrm_reg] = ~xmm_hi[modrm_reg] & shi)) || :
		;;
	86 | 235) # 0x56 orps/pd, 0xeb por
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] |= slo, xmm_hi[modrm_reg] |= shi)) || :
		;;
	87 | 239) # 0x57 xorps/pd, 0xef pxor
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] ^= slo, xmm_hi[modrm_reg] ^= shi)) || :
		;;
	96) # 0x60: punpcklbw
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_unpack_bw "${xmm_lo[modrm_reg]}" "${slo}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = rhi)) || :
		;;
	97) # 0x61: punpcklwd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_unpack_wd "${xmm_lo[modrm_reg]}" "${slo}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = rhi)) || :
		;;
	98) # 0x62: punpckldq
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((dlo = xmm_lo[modrm_reg],
			xmm_lo[modrm_reg] = (dlo & 0xffffffff) | ((slo & 0xffffffff) << 32),
			xmm_hi[modrm_reg] = ((dlo >> 32) & 0xffffffff) | (((slo >> 32) & 0xffffffff) << 32))) || :
		;;
	100) # 0x64: pcmpgtb
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_byte_half 2 "${xmm_lo[modrm_reg]}" "${slo}"
		rlo=${_xres}
		sse_byte_half 2 "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = _xres)) || :
		;;
	101) # 0x65: pcmpgtw
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_word_half 1 "${xmm_lo[modrm_reg]}" "${slo}"
		rlo=${_xres}
		sse_word_half 1 "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = _xres)) || :
		;;
	102) # 0x66: pcmpgtd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((((dlo & 0xffffffff) ^ 0x80000000) - 0x80000000) > (((slo & 0xffffffff) ^ 0x80000000) - 0x80000000) ? 0xffffffff : 0) |
				((((((dlo >> 32) & 0xffffffff) ^ 0x80000000) - 0x80000000) > ((((slo >> 32) & 0xffffffff) ^ 0x80000000) - 0x80000000) ? 0xffffffff : 0) << 32),
			xmm_hi[modrm_reg] = ((((dhi & 0xffffffff) ^ 0x80000000) - 0x80000000) > (((shi & 0xffffffff) ^ 0x80000000) - 0x80000000) ? 0xffffffff : 0) |
				((((((dhi >> 32) & 0xffffffff) ^ 0x80000000) - 0x80000000) > ((((shi >> 32) & 0xffffffff) ^ 0x80000000) - 0x80000000) ? 0xffffffff : 0) << 32))) || :
		;;
	104) # 0x68: punpckhbw
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_unpack_bw "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = rhi)) || :
		;;
	105) # 0x69: punpckhwd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_unpack_wd "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = rhi)) || :
		;;
	106) # 0x6a: punpckhdq
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = (dhi & 0xffffffff) | ((shi & 0xffffffff) << 32),
			xmm_hi[modrm_reg] = ((dhi >> 32) & 0xffffffff) | (((shi >> 32) & 0xffffffff) << 32))) || :
		;;
	108) # 0x6c: punpcklqdq
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_hi[modrm_reg] = slo)) || :
		;;
	109) # 0x6d: punpckhqdq
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] = xmm_hi[modrm_reg], xmm_hi[modrm_reg] = shi)) || :
		;;
	110) # 0x6e: 66 movd / movq r/m -> xmm
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((rex_w)); then
			read_rm 8
			((xmm_lo[modrm_reg] = val, xmm_hi[modrm_reg] = 0)) || :
		else
			read_rm 4
			((xmm_lo[modrm_reg] = val & 0xffffffff, xmm_hi[modrm_reg] = 0)) || :
		fi
		;;
	112) # 0x70: 66 pshufd / f2 pshuflw / f3 pshufhw imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		read_xmm_rm
		disp8
		((step_b = displacement & 0xff)) || :
		if ((rep_prefix == 242)); then
			((xmm_lo[modrm_reg] = ((slo >> (((step_b >> 0) & 3) * 16)) & 0xffff) |
				(((slo >> (((step_b >> 2) & 3) * 16)) & 0xffff) << 16) |
				(((slo >> (((step_b >> 4) & 3) * 16)) & 0xffff) << 32) |
				(((slo >> (((step_b >> 6) & 3) * 16)) & 0xffff) << 48),
				xmm_hi[modrm_reg] = shi)) || :
		elif ((rep_prefix == 243)); then
			((xmm_lo[modrm_reg] = slo,
				xmm_hi[modrm_reg] = ((shi >> (((step_b >> 0) & 3) * 16)) & 0xffff) |
					(((shi >> (((step_b >> 2) & 3) * 16)) & 0xffff) << 16) |
					(((shi >> (((step_b >> 4) & 3) * 16)) & 0xffff) << 32) |
					(((shi >> (((step_b >> 6) & 3) * 16)) & 0xffff) << 48))) || :
		else
			for ((_xi = 0; _xi < 4; _xi++)); do
				((step_c = (step_b >> (_xi * 2)) & 3,
					_xv = step_c < 2 ? ((slo >> (step_c * 32)) & 0xffffffff) : ((shi >> ((step_c - 2) * 32)) & 0xffffffff))) || :
				case ${_xi} in
				0) rlo=${_xv} ;;
				1) ((rlo |= _xv << 32)) || : ;;
				2) rhi=${_xv} ;;
				3) ((rhi |= _xv << 32)) || : ;;
				esac
			done
			((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = rhi)) || :
		fi
		;;
	113) # 0x71: 66 group 12 (psrlw /2, psraw /4, psllw /6) imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		disp8
		((step_b = displacement & 0xff)) || :
		case $(((modrm >> 3) & 7)) in
		2) sse_shift_xmm "${modrm_rm}" 0 "${step_b}" ;;
		4) sse_shift_xmm "${modrm_rm}" 1 "${step_b}" ;;
		6) sse_shift_xmm "${modrm_rm}" 2 "${step_b}" ;;
		*) unknown_insruction "$(printf '66 0f 71 /%d' $(((modrm >> 3) & 7)))" "invalid SSE2 shift" ;;
		esac
		;;
	114) # 0x72: 66 group 13 (psrld /2, psrad /4, pslld /6) imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		disp8
		((step_b = displacement & 0xff)) || :
		case $(((modrm >> 3) & 7)) in
		2) sse_shift_xmm "${modrm_rm}" 3 "${step_b}" ;;
		4) sse_shift_xmm "${modrm_rm}" 4 "${step_b}" ;;
		6) sse_shift_xmm "${modrm_rm}" 5 "${step_b}" ;;
		*) unknown_insruction "$(printf '66 0f 72 /%d' $(((modrm >> 3) & 7)))" "invalid SSE2 shift" ;;
		esac
		;;
	115) # 0x73: 66 group 14 (psrlq /2, psrldq /3, psllq /6, pslldq /7) imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		disp8
		((step_b = displacement & 0xff)) || :
		case $(((modrm >> 3) & 7)) in
		2) sse_shift_xmm "${modrm_rm}" 6 "${step_b}" ;;
		6) sse_shift_xmm "${modrm_rm}" 7 "${step_b}" ;;
		3) # psrldq (byte shift right)
			((_xlo = xmm_lo[modrm_rm], _xhi = xmm_hi[modrm_rm])) || :
			if ((step_b >= 16)); then
				_xlo=0 _xhi=0
			elif ((step_b == 8)); then
				_xlo=${_xhi} _xhi=0
			elif ((step_b > 8)); then
				((_xv = (step_b - 8) * 8, _xmask = (1 << (64 - _xv)) - 1,
					_xlo = (_xhi >> _xv) & _xmask, _xhi = 0)) || :
			elif ((step_b > 0)); then
				((_xv = step_b * 8, _xmask = (1 << (64 - _xv)) - 1,
					_xlo = ((_xlo >> _xv) & _xmask) | (_xhi << (64 - _xv)),
					_xhi = (_xhi >> _xv) & _xmask)) || :
			fi
			((xmm_lo[modrm_rm] = _xlo, xmm_hi[modrm_rm] = _xhi)) || :
			;;
		7) # pslldq (byte shift left)
			((_xlo = xmm_lo[modrm_rm], _xhi = xmm_hi[modrm_rm])) || :
			if ((step_b >= 16)); then
				_xlo=0 _xhi=0
			elif ((step_b == 8)); then
				_xhi=${_xlo} _xlo=0
			elif ((step_b > 8)); then
				((_xv = (step_b - 8) * 8, _xhi = _xlo << _xv, _xlo = 0)) || :
			elif ((step_b > 0)); then
				((_xv = step_b * 8, _xmask = (1 << _xv) - 1,
					_xhi = (_xhi << _xv) | ((_xlo >> (64 - _xv)) & _xmask),
					_xlo = _xlo << _xv)) || :
			fi
			((xmm_lo[modrm_rm] = _xlo, xmm_hi[modrm_rm] = _xhi)) || :
			;;
		*) unknown_insruction "$(printf '66 0f 73 /%d' $(((modrm >> 3) & 7)))" "invalid SSE2 shift" ;;
		esac
		;;
	116) # 0x74: 66 pcmpeqb (SWAR 8 bytes at a time)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((_xmask = 0x7f7f7f7f7f7f7f7f,
			_xda = xmm_lo[modrm_reg] ^ slo,
			_xv = ~((((_xda & _xmask) + _xmask) | _xda) | _xmask),
			xmm_lo[modrm_reg] = _xv | (((_xv >> 7) & 0x0101010101010101) * 0x7f),
			_xda = xmm_hi[modrm_reg] ^ shi,
			_xv = ~((((_xda & _xmask) + _xmask) | _xda) | _xmask),
			xmm_hi[modrm_reg] = _xv | (((_xv >> 7) & 0x0101010101010101) * 0x7f))) || :
		;;
	117) # 0x75: 66 pcmpeqw
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_word_half 0 "${xmm_lo[modrm_reg]}" "${slo}"
		rlo=${_xres}
		sse_word_half 0 "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = _xres)) || :
		;;
	118) # 0x76: 66 pcmpeqd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((dlo & 0xffffffff) == (slo & 0xffffffff) ? 0xffffffff : 0) |
				((((dlo >> 32) & 0xffffffff) == ((slo >> 32) & 0xffffffff) ? 0xffffffff : 0) << 32),
			xmm_hi[modrm_reg] = ((dhi & 0xffffffff) == (shi & 0xffffffff) ? 0xffffffff : 0) |
				((((dhi >> 32) & 0xffffffff) == ((shi >> 32) & 0xffffffff) ? 0xffffffff : 0) << 32))) || :
		;;
	126) # 0x7e: f3 movq xmm/m64->xmm | 66 movd/movq xmm->r/m
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((rep_prefix == 243)); then
			if ((modrm_mod == 3)); then
				((slo = xmm_lo[modrm_rm])) || :
			else
				read_mem 8 "${modrm_address}"
				slo=${val}
			fi
			((xmm_lo[modrm_reg] = slo, xmm_hi[modrm_reg] = 0)) || :
		elif ((rex_w)); then
			write_rm 8 "${xmm_lo[modrm_reg]}"
		else
			write_rm 4 "$((xmm_lo[modrm_reg] & 0xffffffff))"
		fi
		;;
	162) # 0xa2: cpuid (baseline x86_64 + SSE + SSE2, no SSSE3/SSE4/AVX)
		((step_a = registers[RAX] & 0xffffffff)) || :
		case ${step_a} in
		0)
			write_reg 4 0 7
			write_reg 4 3 $((0x756e6547)) # "Genu"
			write_reg 4 2 $((0x49656e69)) # "ineI"
			write_reg 4 1 $((0x6c65746e)) # "ntel"
			;;
		1)
			write_reg 4 0 $((0x000006f1))
			write_reg 4 3 $((0x00010800))
			write_reg 4 1 $((1 << 23))    # POPCNT only; SSE3/SSSE3/SSE4/AVX = 0
			write_reg 4 2 $((0x078bfbfd)) # FPU..SSE2
			;;
		$((0x80000000)))
			write_reg 4 0 $((0x80000008))
			write_reg 4 3 0
			write_reg 4 1 0
			write_reg 4 2 0
			;;
		$((0x80000001)))
			write_reg 4 0 0
			write_reg 4 3 0
			write_reg 4 1 1                                  # LAHF_LM
			write_reg 4 2 $(((1 << 29) | (1 << 20) | 0x800)) # LM | NX | SYSCALL
			;;
		$((0x80000008)))
			write_reg 4 0 $((0x00003030))
			write_reg 4 3 0
			write_reg 4 1 0
			write_reg 4 2 0
			;;
		*)
			write_reg 4 0 0
			write_reg 4 3 0
			write_reg 4 1 0
			write_reg 4 2 0
			;;
		esac
		;;
	163 | 171 | 179 | 187) # 0xa3 bt, 0xab bts, 0xb3 btr, 0xbb btc (r/m, r)
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_reg "${step_width}" "${modrm_reg}"
		step_b=${val}
		if ((modrm_mod == 3)); then
			exec_bit_op "$(((step_op2 >> 3) & 3))" "${step_width}" "$((step_b & (step_width * 8 - 1)))" 0 0
		else
			sign_extend "${step_width}" "${step_b}"
			((step_c = step_width == 2 ? 4 : step_width == 4 ? 5 : 6,
				step_d = modrm_address + (val >> step_c) * step_width)) || :
			exec_bit_op "$(((step_op2 >> 3) & 3))" "${step_width}" "$((val & (step_width * 8 - 1)))" 1 "${step_d}"
		fi
		;;
	164 | 165 | 172 | 173) # 0xa4, 0xa5, 0xac, 0xad: shld, shrd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" "$((step_op2 & 1 ? 0 : 1))"
		read_rm "${step_width}"
		step_a=${val}
		if ((step_op2 & 1)); then
			((step_b = registers[RCX])) || :
		else
			disp8
			step_b=${displacement}
		fi
		read_reg "${step_width}" "${modrm_reg}"
		double_shift "$((step_op2 < 172))" "${step_width}" "${step_a}" "${val}" "${step_b}"
		write_rm "${step_width}" "${val}"
		;;
	174) # 0xae: ldmxcsr / stmxcsr / lfence / mfence / sfence / clflush
		((modrm = memory[rip + advance], advance++)) || :
		if (((modrm >> 6) == 3)); then
			if ((rep_prefix == 243)); then
				# rdfsbase / rdgsbase / wrfsbase / wrgsbase
				((step_a = (modrm & 7) | (rex_b << 3))) || :
				case $(((modrm >> 3) & 7)) in
				0) write_reg "${step_width}" "${step_a}" "${GLOBAL_fs_base}" ;;
				1) write_reg "${step_width}" "${step_a}" "${GLOBAL_gs_base}" ;;
				2) read_reg "${step_width}" "${step_a}"; GLOBAL_fs_base=${val} ;;
				3) read_reg "${step_width}" "${step_a}"; GLOBAL_gs_base=${val} ;;
				esac
			fi
		else
			operands_modrm "${modrm}"
			case $(((modrm >> 3) & 7)) in
			2) read_mem 4 "${modrm_address}"; GLOBAL_mxcsr=${val} ;; # ldmxcsr
			3) write_mem 4 "${modrm_address}" "${GLOBAL_mxcsr}" ;;   # stmxcsr
			0 | 1 | 7) ;;                                            # fxsave/fxrstor/clflush no-op
			*) unknown_insruction "$(printf '0f ae /%d' $(((modrm >> 3) & 7)))" "unsupported 0f ae" ;;
			esac
		fi
		;;
	175) # 0xaf: imul r, r/m
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "${step_width}"
		step_a=${val}
		read_reg "${step_width}" "${modrm_reg}"
		imul_op "${step_width}" "${val}" "${step_a}"
		write_reg "${step_width}" "${modrm_reg}" "${prod_lo}"
		;;
	176 | 177) # 0xb0, 0xb1: cmpxchg r/m, r
		((step_op2 == 176)) && step_width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "${step_width}"
		step_a=${val}
		read_reg "${step_width}" 0
		alu 7 "${step_width}" "${val}" "${step_a}"
		if ((flag_zf)); then
			read_reg "${step_width}" "${modrm_reg}"
			write_rm "${step_width}" "${val}"
		else
			write_reg "${step_width}" 0 "${step_a}"
		fi
		;;
	182 | 183 | 190 | 191) # 0xb6, 0xb7, 0xbe, 0xbf: movzx, movsx
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "$(((step_op2 & 1) + 1))"
		if ((step_op2 & 8)); then
			sign_extend "$(((step_op2 & 1) + 1))" "${val}"
		fi
		write_reg "${step_width}" "${modrm_reg}" "${val}"
		;;
	184) # 0xb8: f3 popcnt
		((rep_prefix == 243)) || unknown_insruction "0f b8" "popcnt requires f3 prefix"
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "${step_width}"
		((_xda = val - ((val >> 1) & 0x5555555555555555),
			_xda = (_xda & 0x3333333333333333) + ((_xda >> 2) & 0x3333333333333333),
			_xda = (_xda + (_xda >> 4)) & 0x0f0f0f0f0f0f0f0f,
			step_b = (_xda * 0x0101010101010101) >> 56 & 0xff,
			flag_zf = val == 0, flag_cf = 0, flag_of = 0, flag_sf = 0, flag_af = 0, flag_pf = 0)) || :
		write_reg "${step_width}" "${modrm_reg}" "${step_b}"
		;;
	186) # 0xba: group 8 bt/bts/btr/btc r/m, imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		disp8
		((step_c = (modrm >> 3) & 7)) || :
		((step_c >= 4)) || unknown_insruction "$(printf '0f ba /%d' $((step_c)))" "invalid group 8"
		exec_bit_op "$((step_c & 3))" "${step_width}" "$((displacement & (step_width * 8 - 1)))" "$((modrm_mod != 3))" "${modrm_address}"
		;;
	188 | 189) # 0xbc bsf/tzcnt, 0xbd bsr/lzcnt
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "${step_width}"
		if ((rep_prefix == 243)); then
			if ((val == 0)); then
				flag_cf=1 flag_zf=0
				write_reg "${step_width}" "${modrm_reg}" "$((step_width * 8))"
			else
				if ((step_op2 == 188)); then
					for ((step_b = 0; !((val >> step_b) & 1); step_b++)); do :; done
				else
					for ((step_b = step_width * 8 - 1; !((val >> step_b) & 1); step_b--)); do :; done
					((step_b = step_width * 8 - 1 - step_b)) || :
				fi
				((flag_cf = 0, flag_zf = step_b == 0)) || :
				write_reg "${step_width}" "${modrm_reg}" "${step_b}"
			fi
		elif ((val == 0)); then
			flag_zf=1
		else
			flag_zf=0
			if ((step_op2 == 188)); then
				for ((step_b = 0; !((val >> step_b) & 1); step_b++)); do :; done
			else
				for ((step_b = step_width * 8 - 1; !((val >> step_b) & 1); step_b--)); do :; done
			fi
			write_reg "${step_width}" "${modrm_reg}" "${step_b}"
		fi
		;;
	192 | 193) # 0xc0, 0xc1: xadd r/m, r
		((step_op2 == 192)) && step_width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "${step_width}"
		step_a=${val}
		read_reg "${step_width}" "${modrm_reg}"
		alu 0 "${step_width}" "${step_a}" "${val}"
		step_b=${val}
		write_reg "${step_width}" "${modrm_reg}" "${step_a}"
		write_rm "${step_width}" "${step_b}"
		;;
	196) # 0xc4: 66 pinsrw xmm, r32/m16, imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		if ((modrm_mod == 3)); then
			((step_a = registers[modrm_rm] & 0xffff)) || :
		else
			read_mem 2 "${modrm_address}"
			step_a=${val}
		fi
		disp8
		((step_b = displacement & 7)) || :
		if ((step_b < 4)); then
			((step_c = step_b * 16, xmm_lo[modrm_reg] = (xmm_lo[modrm_reg] & ~(0xffff << step_c)) | (step_a << step_c))) || :
		else
			((step_c = (step_b - 4) * 16, xmm_hi[modrm_reg] = (xmm_hi[modrm_reg] & ~(0xffff << step_c)) | (step_a << step_c))) || :
		fi
		;;
	197) # 0xc5: 66 pextrw r32, xmm, imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		disp8
		((step_b = displacement & 7)) || :
		if ((step_b < 4)); then
			write_reg 4 "${modrm_reg}" "$(((xmm_lo[modrm_rm] >> (step_b * 16)) & 0xffff))"
		else
			write_reg 4 "${modrm_reg}" "$(((xmm_hi[modrm_rm] >> ((step_b - 4) * 16)) & 0xffff))"
		fi
		;;
	198) # 0xc6: shufps / 66 shufpd imm8
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" 1
		read_xmm_rm
		disp8
		((step_b = displacement & 0xff, dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg])) || :
		if ((operand_size_prefix)); then
			((xmm_lo[modrm_reg] = (step_b & 1) ? dhi : dlo,
				xmm_hi[modrm_reg] = (step_b & 2) ? shi : slo)) || :
		else
			((step_c = step_b & 3,
				rlo = step_c < 2 ? ((dlo >> (step_c * 32)) & 0xffffffff) : ((dhi >> ((step_c - 2) * 32)) & 0xffffffff),
				step_c = (step_b >> 2) & 3,
				rlo |= (step_c < 2 ? ((dlo >> (step_c * 32)) & 0xffffffff) : ((dhi >> ((step_c - 2) * 32)) & 0xffffffff)) << 32,
				step_c = (step_b >> 4) & 3,
				rhi = step_c < 2 ? ((slo >> (step_c * 32)) & 0xffffffff) : ((shi >> ((step_c - 2) * 32)) & 0xffffffff),
				step_c = (step_b >> 6) & 3,
				rhi |= (step_c < 2 ? ((slo >> (step_c * 32)) & 0xffffffff) : ((shi >> ((step_c - 2) * 32)) & 0xffffffff)) << 32,
				xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = rhi)) || :
		fi
		;;
	200 | 201 | 202 | 203 | 204 | 205 | 206 | 207) # 0xc8-0xcf: bswap
		((step_a = (step_op2 & 7) | (rex_b << 3), step_b = registers[step_a])) || :
		if ((rex_w)); then
			((registers[step_a] = ((step_b & 0xff) << 56) | (((step_b >> 8) & 0xff) << 48) |
				(((step_b >> 16) & 0xff) << 40) | (((step_b >> 24) & 0xff) << 32) |
				(((step_b >> 32) & 0xff) << 24) | (((step_b >> 40) & 0xff) << 16) |
				(((step_b >> 48) & 0xff) << 8) | ((step_b >> 56) & 0xff))) || :
		else
			((registers[step_a] = (((step_b & 0xff) << 24) | (((step_b >> 8) & 0xff) << 16) |
				(((step_b >> 16) & 0xff) << 8) | ((step_b >> 24) & 0xff)) & 0xffffffff)) || :
		fi
		;;
	209) # 0xd1: 66 psrlw xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 0 "${slo}"
		;;
	210) # 0xd2: 66 psrld xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 3 "${slo}"
		;;
	211) # 0xd3: 66 psrlq xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 6 "${slo}"
		;;
	212) # 0xd4: 66 paddq
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] += slo, xmm_hi[modrm_reg] += shi)) || :
		;;
	214) # 0xd6: 66 movq xmm -> xmm/m64
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((modrm_mod == 3)); then
			((xmm_lo[modrm_rm] = xmm_lo[modrm_reg], xmm_hi[modrm_rm] = 0)) || :
		else
			write_mem 8 "${modrm_address}" "${xmm_lo[modrm_reg]}"
		fi
		;;
	215) # 0xd7: 66 pmovmskb r32, xmm
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		((slo = xmm_lo[modrm_rm], shi = xmm_hi[modrm_rm],
			step_a = (((slo >> 7) & 0x0101010101010101) * 0x0102040810204080 >> 56 & 0xff) |
				((((shi >> 7) & 0x0101010101010101) * 0x0102040810204080 >> 56 & 0xff) << 8))) || :
		write_reg 4 "${modrm_reg}" "${step_a}"
		;;
	216) # 0xd8: 66 psubusb
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_byte_half 3 "${xmm_lo[modrm_reg]}" "${slo}"
		rlo=${_xres}
		sse_byte_half 3 "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = _xres)) || :
		;;
	218) # 0xda: 66 pminub
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_byte_half 0 "${xmm_lo[modrm_reg]}" "${slo}"
		rlo=${_xres}
		sse_byte_half 0 "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = _xres)) || :
		;;
	220) # 0xdc: 66 paddusb
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_byte_half 4 "${xmm_lo[modrm_reg]}" "${slo}"
		rlo=${_xres}
		sse_byte_half 4 "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = _xres)) || :
		;;
	222) # 0xde: 66 pmaxub
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_byte_half 1 "${xmm_lo[modrm_reg]}" "${slo}"
		rlo=${_xres}
		sse_byte_half 1 "${xmm_hi[modrm_reg]}" "${shi}"
		((xmm_lo[modrm_reg] = rlo, xmm_hi[modrm_reg] = _xres)) || :
		;;
	225) # 0xe1: 66 psraw xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 1 "${slo}"
		;;
	226) # 0xe2: 66 psrad xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 4 "${slo}"
		;;
	241) # 0xf1: 66 psllw xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 2 "${slo}"
		;;
	242) # 0xf2: 66 pslld xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 5 "${slo}"
		;;
	243) # 0xf3: 66 psllq xmm, xmm/m128
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		sse_shift_xmm "${modrm_reg}" 7 "${slo}"
		;;
	248) # 0xf8: 66 psubb
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((_xmask = 0x7f7f7f7f7f7f7f7f,
			dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((dlo | ~_xmask) - (slo & _xmask)) ^ ((dlo ^ ~slo) & ~_xmask),
			xmm_hi[modrm_reg] = ((dhi | ~_xmask) - (shi & _xmask)) ^ ((dhi ^ ~shi) & ~_xmask))) || :
		;;
	249) # 0xf9: 66 psubw
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((_xmask = 0x7fff7fff7fff7fff,
			dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((dlo | ~_xmask) - (slo & _xmask)) ^ ((dlo ^ ~slo) & ~_xmask),
			xmm_hi[modrm_reg] = ((dhi | ~_xmask) - (shi & _xmask)) ^ ((dhi ^ ~shi) & ~_xmask))) || :
		;;
	250) # 0xfa: 66 psubd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((_xmask = 0x7fffffff7fffffff,
			dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((dlo | ~_xmask) - (slo & _xmask)) ^ ((dlo ^ ~slo) & ~_xmask),
			xmm_hi[modrm_reg] = ((dhi | ~_xmask) - (shi & _xmask)) ^ ((dhi ^ ~shi) & ~_xmask))) || :
		;;
	251) # 0xfb: 66 psubq
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((xmm_lo[modrm_reg] -= slo, xmm_hi[modrm_reg] -= shi)) || :
		;;
	252) # 0xfc: 66 paddb
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((_xmask = 0x7f7f7f7f7f7f7f7f,
			dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((dlo & _xmask) + (slo & _xmask)) ^ ((dlo ^ slo) & ~_xmask),
			xmm_hi[modrm_reg] = ((dhi & _xmask) + (shi & _xmask)) ^ ((dhi ^ shi) & ~_xmask))) || :
		;;
	253) # 0xfd: 66 paddw
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((_xmask = 0x7fff7fff7fff7fff,
			dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((dlo & _xmask) + (slo & _xmask)) ^ ((dlo ^ slo) & ~_xmask),
			xmm_hi[modrm_reg] = ((dhi & _xmask) + (shi & _xmask)) ^ ((dhi ^ shi) & ~_xmask))) || :
		;;
	254) # 0xfe: 66 paddd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_xmm_rm
		((_xmask = 0x7fffffff7fffffff,
			dlo = xmm_lo[modrm_reg], dhi = xmm_hi[modrm_reg],
			xmm_lo[modrm_reg] = ((dlo & _xmask) + (slo & _xmask)) ^ ((dlo ^ slo) & ~_xmask),
			xmm_hi[modrm_reg] = ((dhi & _xmask) + (shi & _xmask)) ^ ((dhi ^ shi) & ~_xmask))) || :
		;;
	*)
		unknown_insruction "$(printf '0f %02x' $((step_op2)))" "unsupported 2 byte instruction"
		;;
	esac
}

# Executes the instruction at `rip` and moves `rip` to the next instruction.
function step() {
	((step_op = memory[rip], advance = 1)) || :
	if (((step_op & 0xf0) == 0x40)); then
		((rex = step_op, rex_w = (step_op >> 3) & 1, rex_r = (step_op >> 2) & 1,
			rex_x = (step_op >> 1) & 1, rex_b = step_op & 1,
			step_op = memory[rip + 1], advance = 2)) || :
	else
		rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0
	fi
	operand_size_prefix=0 addr_size_prefix=0 seg_override=0 seg_base=0 rep_prefix=0

	# Full prefix loop when legacy or multiple prefixes are present.
	if (((step_op & 0xfc) == 0x64 || (step_op & 0xf0) == 0x40 || step_op == 0xf0 || step_op == 0xf2 || step_op == 0xf3 || (step_op & 0xe7) == 0x26)); then
		rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 advance=0
		while :; do
			((step_op = memory[rip + advance], advance++)) || :
			if (((step_op & 0xf0) == 0x40)); then
				((rex = step_op, rex_w = (step_op >> 3) & 1, rex_r = (step_op >> 2) & 1,
					rex_x = (step_op >> 1) & 1, rex_b = step_op & 1)) || :
				continue
			fi
			case ${step_op} in
			102) operand_size_prefix=1 ;;                       # 0x66
			103) addr_size_prefix=1 ;;                          # 0x67
			242 | 243) rep_prefix=${step_op} ;;                 # 0xf2, 0xf3
			100) seg_override=100 seg_base=${GLOBAL_fs_base} ;; # 0x64 (FS)
			101) seg_override=101 seg_base=${GLOBAL_gs_base} ;; # 0x65 (GS)
			46 | 62 | 38 | 54) seg_override=0 seg_base=0 ;;     # 0x2e, 0x3e, 0x26, 0x36 (CS/DS/ES/SS)
			240) ;;                                             # 0xf0 (LOCK)
			*) break ;;
			esac
			# A legacy prefix after REX cancels REX.
			rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0
		done
	fi

	if [[ ${enable_debug_messages} = true ]]; then
		debug "rip=0x%x opcode=0x%02x" $((rip)) $((step_op))
	fi

	((step_width = rex_w ? 8 : operand_size_prefix ? 2 : 4)) || :

	# add/or/adc/sbb/and/sub/xor/cmp: 00-05, 08-0D, ... 38-3D
	if ((step_op < 64 && (step_op & 7) < 6)); then
		if (((step_op & 7) < 4)); then
			((modrm = memory[rip + advance], advance++,
				_ibo_op = (step_op >> 3) & 7,
				_ibo_w = (step_op & 1) == 0 ? 1 : step_width)) || :
			if ((modrm >= 192 && _ibo_w >= 4)); then
				((modrm_reg = ((modrm >> 3) & 7) | (rex_r << 3),
					modrm_rm = (modrm & 7) | (rex_b << 3),
					_ibo_a = _ibo_w == 8 ? registers[modrm_rm] : (registers[modrm_rm] & 0xffffffff),
					_ibo_b = _ibo_w == 8 ? registers[modrm_reg] : (registers[modrm_reg] & 0xffffffff))) || :
				if (((step_op >> 1) & 1)); then
					alu "${_ibo_op}" "${_ibo_w}" "${_ibo_b}" "${_ibo_a}"
					if ((_ibo_op != 7)); then
						((registers[modrm_reg] = _ibo_w == 8 ? val : (val & 0xffffffff))) || :
					fi
				else
					alu "${_ibo_op}" "${_ibo_w}" "${_ibo_a}" "${_ibo_b}"
					if ((_ibo_op != 7)); then
						((registers[modrm_rm] = _ibo_w == 8 ? val : (val & 0xffffffff))) || :
					fi
				fi
			else
				inst_binary_op "${step_op}" "${modrm}"
			fi
		else
			# AL/eAX, imm
			(((step_op & 1) == 0)) && step_width=1
			disp_width "$((step_width == 8 ? 4 : step_width))"
			read_reg "${step_width}" 0
			alu "$((step_op >> 3))" "${step_width}" "${val}" "$((displacement & (step_width == 8 ? -1 : (1 << (step_width * 8)) - 1)))"
			if (((step_op >> 3) != 7)); then
				write_reg "${step_width}" 0 "${val}"
			fi
		fi
		((rip += advance)) || :
		return 0
	fi

	case ${step_op} in
	136 | 137 | 138 | 139) # 0x88-0x8b: mov r/m, r and mov r, r/m
		((modrm = memory[rip + advance], advance++,
			_ibo_w = (step_op & 1) == 0 ? 1 : step_width)) || :
		if ((modrm >= 192 && _ibo_w >= 4)); then
			((modrm_reg = ((modrm >> 3) & 7) | (rex_r << 3),
				modrm_rm = (modrm & 7) | (rex_b << 3))) || :
			if (((step_op >> 1) & 1)); then
				((registers[modrm_reg] = _ibo_w == 8 ? registers[modrm_rm] : (registers[modrm_rm] & 0xffffffff))) || :
			else
				((registers[modrm_rm] = _ibo_w == 8 ? registers[modrm_reg] : (registers[modrm_reg] & 0xffffffff))) || :
			fi
		else
			operands_modrm "${modrm}"
			if (((step_op >> 1) & 1)); then
				read_rm "${_ibo_w}"
				write_reg "${_ibo_w}" "${modrm_reg}" "${val}"
			else
				read_reg "${_ibo_w}" "${modrm_reg}"
				write_rm "${_ibo_w}" "${val}"
			fi
		fi
		;;
	141) # 0x8d: lea (effective offset without segment base)
		((modrm = memory[rip + advance], advance++)) || :
		seg_base=0
		operands_modrm "${modrm}"
		write_reg "${step_width}" "${modrm_reg}" "${modrm_address}"
		;;
	116) # 0x74: je / jz rel8
		((displacement = (memory[rip + advance] ^ 0x80) - 0x80, advance += 1 + (flag_zf ? displacement : 0))) || :
		;;
	117) # 0x75: jne / jnz rel8
		((displacement = (memory[rip + advance] ^ 0x80) - 0x80, advance += 1 + (flag_zf ? 0 : displacement))) || :
		;;
	112 | 113 | 114 | 115 | 118 | 119 | 120 | 121 | 122 | 123 | 124 | 125 | 126 | 127) # other jcc rel8
		((displacement = (memory[rip + advance] ^ 0x80) - 0x80, advance++)) || :
		eval_cond "${step_op}"
		if ((cond)); then ((advance += displacement)) || :; fi
		;;
	128 | 129 | 131) # 0x80, 0x81, 0x83: group 1 alu r/m, imm
		((step_op == 128)) && step_width=1
		((step_imm_bytes = step_op == 129 ? (step_width == 8 ? 4 : step_width) : 1,
			modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" "${step_imm_bytes}"
		read_rm "${step_width}"
		step_a=${val}
		disp_width "${step_imm_bytes}"
		alu "$(((modrm >> 3) & 7))" "${step_width}" "${step_a}" "$((displacement & (step_width == 8 ? -1 : (1 << (step_width * 8)) - 1)))"
		if ((((modrm >> 3) & 7) != 7)); then
			write_rm "${step_width}" "${val}"
		fi
		;;
	132 | 133) # 0x84, 0x85: test r/m, r
		((modrm = memory[rip + advance], advance++)) || :
		inst_binary_op "${step_op}" "${modrm}"
		;;
	15) # 0x0f: two-byte instructions
		step_0f
		;;
	80 | 81 | 82 | 83 | 84 | 85 | 86 | 87) # 0x50-0x57: push r64
		push64 "${registers[(step_op & 7) | (rex_b << 3)]}"
		;;
	88 | 89 | 90 | 91 | 92 | 93 | 94 | 95) # 0x58-0x5f: pop r64
		pop64
		((registers[(step_op & 7) | (rex_b << 3)] = val)) || :
		;;
	176 | 177 | 178 | 179 | 180 | 181 | 182 | 183 | 184 | 185 | 186 | 187 | 188 | 189 | 190 | 191) # 0xb0-0xbf: mov reg, imm
		inst_mov_imm "${step_op}"
		;;
	254 | 255) # 0xfe, 0xff: group 4/5
		((step_op == 254)) && step_width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		case $(((modrm >> 3) & 7)) in
		0 | 1) # inc, dec: CF is preserved.
			read_rm "${step_width}"
			step_b=${flag_cf}
			alu "$((((modrm >> 3) & 7) ? 5 : 0))" "${step_width}" "${val}" 1
			flag_cf=${step_b}
			write_rm "${step_width}" "${val}"
			;;
		2) # call r/m64
			((step_op == 255)) || unknown_insruction "fe /2" "invalid"
			read_rm 8
			step_a=${val}
			push64 "$((rip + advance))"
			((advance = step_a - rip)) || :
			;;
		4) # jmp r/m64
			((step_op == 255)) || unknown_insruction "fe /4" "invalid"
			read_rm 8
			((advance = val - rip)) || :
			;;
		6) # push r/m64
			((step_op == 255)) || unknown_insruction "fe /6" "invalid"
			read_rm 8
			push64 "${val}"
			;;
		*)
			unknown_insruction "$(printf '%02x /%d' $((step_op)) $(((modrm >> 3) & 7)))" "unsupported group 5 instruction"
			;;
		esac
		;;
	232) # 0xe8: call rel32
		disp32
		push64 "$((rip + advance))"
		((advance += displacement)) || :
		;;
	233) # 0xe9: jmp rel32
		disp32
		((advance += displacement)) || :
		;;
	235) # 0xeb: jmp rel8
		((displacement = (memory[rip + advance] ^ 0x80) - 0x80, advance += 1 + displacement)) || :
		;;
	194 | 195) # 0xc2, 0xc3: ret, ret imm16
		if ((step_op == 194)); then
			disp16
			((step_b = displacement & 0xffff)) || :
		else
			step_b=0
		fi
		pop64
		((registers[RSP] += step_b, advance = val - rip)) || :
		;;
	198 | 199) # 0xc6, 0xc7: mov r/m, imm
		((step_op == 198)) && step_width=1
		((step_imm_bytes = step_op == 198 ? 1 : (step_width == 8 ? 4 : step_width),
			modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" "${step_imm_bytes}"
		disp_width "${step_imm_bytes}"
		write_rm "${step_width}" "${displacement}"
		;;
	192 | 193 | 208 | 209 | 210 | 211) # 0xc0, 0xc1, 0xd0-0xd3: group 2 shifts
		(((step_op & 1) == 0)) && step_width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" "$((step_op < 208 ? 1 : 0))"
		read_rm "${step_width}"
		step_a=${val}
		if ((step_op < 208)); then
			disp8
			((step_b = displacement & 0xff)) || :
		elif ((step_op < 210)); then
			step_b=1
		else
			((step_b = registers[RCX] & 0xff)) || :
		fi
		shift_op "$(((modrm >> 3) & 7))" "${step_width}" "${step_a}" "${step_b}"
		write_rm "${step_width}" "${val}"
		;;
	246 | 247) # 0xf6, 0xf7: group 3
		((step_op == 246)) && step_width=1
		((modrm = memory[rip + advance], advance++,
			step_imm_bytes = ((modrm >> 3) & 7) < 2 ? (step_width == 8 ? 4 : step_width) : 0)) || :
		operands_modrm "${modrm}" "${step_imm_bytes}"
		read_rm "${step_width}"
		step_a=${val}
		case $(((modrm >> 3) & 7)) in
		0 | 1) # test
			disp_width "${step_imm_bytes}"
			alu 4 "${step_width}" "${step_a}" "$((displacement & (step_width == 8 ? -1 : (1 << (step_width * 8)) - 1)))"
			;;
		2) # not
			write_rm "${step_width}" "$((~step_a))"
			;;
		3) # neg
			alu 5 "${step_width}" 0 "${step_a}"
			write_rm "${step_width}" "${val}"
			;;
		*)
			inst_muldiv "$(((modrm >> 3) & 7))" "${step_width}" "${step_a}"
			;;
		esac
		;;
	99) # 0x63: movsxd
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		if ((rex_w)); then
			read_rm 4
			sign_extend 4 "${val}"
		else
			read_rm "${step_width}"
		fi
		write_reg "${step_width}" "${modrm_reg}" "${val}"
		;;
	104 | 106) # 0x68, 0x6a: push imm32/imm8
		disp_width "$((step_op == 104 ? 4 : 1))"
		push64 "${displacement}"
		;;
	105 | 107) # 0x69, 0x6b: imul r, r/m, imm
		((step_imm_bytes = step_op == 107 ? 1 : (step_width == 8 ? 4 : step_width),
			modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}" "${step_imm_bytes}"
		read_rm "${step_width}"
		step_a=${val}
		disp_width "${step_imm_bytes}"
		imul_op "${step_width}" "${step_a}" "${displacement}"
		write_reg "${step_width}" "${modrm_reg}" "${prod_lo}"
		;;
	134 | 135) # 0x86, 0x87: xchg r/m, r
		((step_op == 134)) && step_width=1
		((modrm = memory[rip + advance], advance++)) || :
		operands_modrm "${modrm}"
		read_rm "${step_width}"
		step_a=${val}
		read_reg "${step_width}" "${modrm_reg}"
		write_rm "${step_width}" "${val}"
		write_reg "${step_width}" "${modrm_reg}" "${step_a}"
		;;
	143) # 0x8f: pop r/m64
		((modrm = memory[rip + advance], advance++)) || :
		pop64
		step_a=${val}
		operands_modrm "${modrm}"
		write_rm 8 "${step_a}"
		;;
	144 | 145 | 146 | 147 | 148 | 149 | 150 | 151) # 0x90-0x97: nop / pause / xchg rAX, r
		if ((((step_op & 7) | (rex_b << 3)) != 0)); then
			read_reg "${step_width}" 0
			step_a=${val}
			read_reg "${step_width}" "$(((step_op & 7) | (rex_b << 3)))"
			write_reg "${step_width}" 0 "${val}"
			write_reg "${step_width}" "$(((step_op & 7) | (rex_b << 3)))" "${step_a}"
		fi
		;;
	152) # 0x98: cbw, cwde, cdqe
		read_reg "$((step_width / 2))" 0
		sign_extend "$((step_width / 2))" "${val}"
		write_reg "${step_width}" 0 "${val}"
		;;
	153) # 0x99: cwd, cdq, cqo
		read_reg "${step_width}" 0
		write_reg "${step_width}" 2 "$((((val >> (step_width * 8 - 1)) & 1) ? -1 : 0))"
		;;
	156) # 0x9c: pushfq / pushfw
		((step_a = flag_cf | 2 | (flag_pf << 2) | (flag_af << 4) | (flag_zf << 6) |
			(flag_sf << 7) | (flag_df << 10) | (flag_of << 11))) || :
		if ((operand_size_prefix)); then
			((registers[RSP] -= 2)) || :
			write_mem 2 "${registers[RSP]}" "$((step_a & 0xffff))"
		else
			push64 "${step_a}"
		fi
		;;
	157) # 0x9d: popfq / popfw
		if ((operand_size_prefix)); then
			read_mem 2 "${registers[RSP]}"
			((registers[RSP] += 2)) || :
		else
			pop64
		fi
		((flag_cf = val & 1, flag_pf = (val >> 2) & 1, flag_af = (val >> 4) & 1,
			flag_zf = (val >> 6) & 1, flag_sf = (val >> 7) & 1,
			flag_df = (val >> 10) & 1, flag_of = (val >> 11) & 1)) || :
		;;
	158) # 0x9e: sahf
		((step_a = (registers[RAX] >> 8) & 0xff,
			flag_cf = step_a & 1, flag_pf = (step_a >> 2) & 1,
			flag_af = (step_a >> 4) & 1, flag_zf = (step_a >> 6) & 1,
			flag_sf = (step_a >> 7) & 1)) || :
		;;
	159) # 0x9f: lahf
		((step_a = flag_cf | 2 | (flag_pf << 2) | (flag_af << 4) | (flag_zf << 6) | (flag_sf << 7),
			registers[RAX] = (registers[RAX] & ~0xff00) | (step_a << 8))) || :
		;;
	160 | 161 | 162 | 163) # 0xa0-0xa3: mov AL/rAX, moffs / mov moffs, AL/rAX
		(((step_op & 1) == 0)) && step_width=1
		if ((addr_size_prefix)); then
			((_da = rip + advance,
				step_a = (memory[_da] | memory[_da + 1] << 8 | memory[_da + 2] << 16 | memory[_da + 3] << 24) & 0xffffffff,
				advance += 4)) || :
		else
			disp64
			step_a=${displacement}
		fi
		((step_a += seg_base)) || :
		if ((step_op < 162)); then
			read_mem "${step_width}" "${step_a}"
			write_reg "${step_width}" 0 "${val}"
		else
			read_reg "${step_width}" 0
			write_mem "${step_width}" "${step_a}" "${val}"
		fi
		;;
	164 | 165 | 170 | 171 | 172 | 173) # 0xa4/a5 movs, 0xaa/ab stos, 0xac/ad lods
		(((step_op & 1) == 0)) && step_width=1
		((step_d = flag_df ? -step_width : step_width)) || :
		while ((!rep_prefix || (addr_size_prefix ? (registers[RCX] & 0xffffffff) : registers[RCX]) != 0)); do
			if ((step_op < 166)); then
				# movs: DS:[RSI] (overridable by FS/GS) -> ES:[RDI]
				((step_a = seg_base + (addr_size_prefix ? (registers[RSI] & 0xffffffff) : registers[RSI]),
					step_b = addr_size_prefix ? (registers[RDI] & 0xffffffff) : registers[RDI])) || :
				read_mem "${step_width}" "${step_a}"
				write_mem "${step_width}" "${step_b}" "${val}"
				((registers[RSI] += step_d, registers[RDI] += step_d)) || :
			elif ((step_op < 172)); then
				# stos: rAX -> ES:[RDI]
				read_reg "${step_width}" 0
				((step_b = addr_size_prefix ? (registers[RDI] & 0xffffffff) : registers[RDI])) || :
				write_mem "${step_width}" "${step_b}" "${val}"
				((registers[RDI] += step_d)) || :
			else
				# lods: DS:[RSI] (overridable by FS/GS) -> rAX
				((step_a = seg_base + (addr_size_prefix ? (registers[RSI] & 0xffffffff) : registers[RSI]))) || :
				read_mem "${step_width}" "${step_a}"
				write_reg "${step_width}" 0 "${val}"
				((registers[RSI] += step_d)) || :
			fi
			((rep_prefix)) || break
			((registers[RCX]--)) || :
			if ((addr_size_prefix)); then ((registers[RCX] &= 0xffffffff)) || :; fi
		done
		;;
	166 | 167 | 174 | 175) # 0xa6/a7 cmps, 0xae/af scas
		(((step_op & 1) == 0)) && step_width=1
		((step_d = flag_df ? -step_width : step_width)) || :
		while ((!rep_prefix || (addr_size_prefix ? (registers[RCX] & 0xffffffff) : registers[RCX]) != 0)); do
			if ((step_op < 168)); then
				# cmps: [RSI] - [RDI]
				((step_a = seg_base + (addr_size_prefix ? (registers[RSI] & 0xffffffff) : registers[RSI]))) || :
				read_mem "${step_width}" "${step_a}"
				step_c=${val}
				((registers[RSI] += step_d)) || :
			else
				# scas: rAX - [RDI]
				read_reg "${step_width}" 0
				step_c=${val}
			fi
			((step_b = addr_size_prefix ? (registers[RDI] & 0xffffffff) : registers[RDI])) || :
			read_mem "${step_width}" "${step_b}"
			((registers[RDI] += step_d)) || :
			alu 7 "${step_width}" "${step_c}" "${val}"
			((rep_prefix)) || break
			((registers[RCX]--)) || :
			if ((addr_size_prefix)); then ((registers[RCX] &= 0xffffffff)) || :; fi
			if ((rep_prefix == 243)); then
				((flag_zf)) || break # repe/repz: stop when ZF == 0
			else
				((flag_zf)) && break # repne/repnz: stop when ZF == 1
			fi
		done
		;;
	168 | 169) # 0xa8, 0xa9: test al/eAX, imm
		((step_op == 168)) && step_width=1
		disp_width "$((step_width == 8 ? 4 : step_width))"
		read_reg "${step_width}" 0
		alu 4 "${step_width}" "${val}" "$((displacement & (step_width == 8 ? -1 : (1 << (step_width * 8)) - 1)))"
		;;
	200) # 0xc8: enter imm16, imm8
		disp16
		((step_a = displacement & 0xffff)) || :
		disp8
		push64 "${registers[RBP]}"
		((registers[RBP] = registers[RSP], registers[RSP] -= step_a)) || :
		;;
	201) # 0xc9: leave
		((registers[RSP] = registers[RBP])) || :
		pop64
		((registers[RBP] = val)) || :
		;;
	204) # 0xcc: int3
		die "Breakpoint (int3) at 0x%x" $((rip))
		;;
	215) # 0xd7: xlatb
		((step_a = seg_base + (addr_size_prefix ? (registers[RBX] & 0xffffffff) : registers[RBX]) + (registers[RAX] & 0xff))) || :
		read_mem 1 "${step_a}"
		write_reg 1 0 "${val}"
		;;
	224 | 225 | 226) # 0xe0 loopne, 0xe1 loope, 0xe2 loop
		disp8
		if ((addr_size_prefix)); then
			((step_a = (registers[RCX] - 1) & 0xffffffff, registers[RCX] = step_a)) || :
		else
			((step_a = --registers[RCX])) || :
		fi
		if ((step_a != 0 && (step_op == 226 || (step_op == 225 && flag_zf) || (step_op == 224 && !flag_zf)))); then
			((advance += displacement)) || :
		fi
		;;
	227) # 0xe3: jrcxz / jecxz
		disp8
		if (((addr_size_prefix ? (registers[RCX] & 0xffffffff) : registers[RCX]) == 0)); then
			((advance += displacement)) || :
		fi
		;;
	244) # 0xf4: hlt
		die "HLT instruction at 0x%x" $((rip))
		;;
	245) ((flag_cf = !flag_cf)) || : ;; # 0xf5: cmc
	248) flag_cf=0 ;;                   # 0xf8: clc
	249) flag_cf=1 ;;                   # 0xf9: stc
	252) flag_df=0 ;;                   # 0xfc: cld
	253) flag_df=1 ;;                   # 0xfd: std
	*)
		unknown_insruction "$(printf '%02x' $((step_op)))" "unsupported instruction"
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
	case $1 in
	1 | 2 | 4 | 8)
		write_mem "$1" "$2" "$3"
		;;
	*)
		declare -ri width="$1" address="$2" value="$3"
		declare -i i
		for ((i = 0; i < width; i++)); do
			((memory[address + i] = (value >> (8 * i)) & 0xff)) || :
		done
		;;
	esac
}

function get_register() {
	case $1 in
	8) echo $((registers[$2])) ;;
	4) echo $((registers[$2] & 0xffffffff)) ;;
	2) echo $((registers[$2] & 0xffff)) ;;
	1) echo $((registers[$2] & 0xff)) ;;
	*) die "Unsupported data width in get_register: $1" ;;
	esac
}

function get_memory() {
	case $1 in
	1 | 2 | 4 | 8)
		read_mem "$1" "$2"
		echo $((val))
		;;
	*)
		declare -ri width="$1" address="$2"
		declare -i value=0 i
		for ((i = 0; i < width; i++)); do
			((value += memory[address + i] << (8 * i))) || :
		done
		echo $((value))
		;;
	esac
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
declare -ri LINUX_EBADF=9
declare -ri LINUX_ENOMEM=12
declare -ri LINUX_EFAULT=14
declare -ri LINUX_ENODEV=19
declare -ri LINUX_EINVAL=22
declare -ri LINUX_ENOTTY=25
declare -ri LINUX_ENOSYS=38

declare -ri LINUX_PAGE_SIZE=4096
declare -ri LINUX_DEFAULT_BRK_START=$((0x10000000))
declare -ri LINUX_MAP_FIXED=$((0x10))
declare -ri LINUX_MAP_ANONYMOUS=$((0x20))
declare -ri LINUX_ARCH_SET_GS=$((0x1001))
declare -ri LINUX_ARCH_SET_FS=$((0x1002))
declare -ri LINUX_ARCH_GET_FS=$((0x1003))
declare -ri LINUX_ARCH_GET_GS=$((0x1004))
# Value stored in r11 by `syscall`. spleen does not emulate RFLAGS yet, so we
# report IF set plus the always-one reserved bit 1.
declare -ri LINUX_SYSCALL_RFLAGS=$((0x202))

# Writes `len` bytes of emulated memory starting at `address` to stdout, byte
# for byte. NUL bytes, newlines, '%' and '\' are all emitted verbatim.
function print_memory_bytes() {
	declare -ri address="$1" len="$2"
	declare -i i
	declare escaped="" byte
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

# Zeroes emulated memory in [address, address + len). Memory is a sparse
# array, so only the bytes that were ever written need clearing.
function zero_memory_range() {
	declare -ri address="$1" len="$2"
	declare -i i
	for i in "${!memory[@]}"; do
		if ((i >= address && i < address + len)); then
			unset 'memory[i]'
		fi
	done
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

# read(fd, buf, count): only fd 0 is supported. Reads at most `count` bytes
# from stdin, returning early after a newline (like a terminal would), or at
# end of file.
function linux_sys_read() {
	declare -ri fd="$1" buf="$2" count="$3"
	if ((fd != 0)); then
		ret=-LINUX_EBADF
		return
	fi
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
}

# write(fd, buf, count) for fd 1 (stdout) and 2 (stderr).
function linux_sys_write() {
	declare -ri fd="$1" buf="$2" count="$3"
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
	declare -ri fd="$1" iov="$2" iovcnt="$3"
	if ((fd != 1 && fd != 2)); then
		ret=-LINUX_EBADF
		return
	fi
	declare -i i base len total=0
	for ((i = 0; i < iovcnt; i++)); do
		base=$(get_memory 8 $((iov + 16 * i)))
		len=$(get_memory 8 $((iov + 16 * i + 8)))
		print_memory_bytes $((base)) $((len)) >&$((fd))
		((total += len)) || :
	done
	ret=$((total))
}

# brk(addr): returns the new program break, or the current one if `addr` is 0
# or below the initial break. Memory is sparse, so growing needs no work;
# shrinking zeroes the released bytes so that growing again reads zeros.
function linux_sys_brk() {
	declare -ri addr="$1"
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

# mmap(addr, length, prot, flags, fd, offset): anonymous mappings only.
# Without MAP_FIXED, memory comes from a bump allocator and is never reused.
function linux_sys_mmap() {
	declare -ri addr="$1" length="$2" prot="$3" flags="$4" fd="$5" offset="$6"
	if ((length <= 0)); then
		ret=-LINUX_EINVAL
		return
	fi
	if (((flags & LINUX_MAP_ANONYMOUS) == 0)); then
		debug "mmap: file backed mappings are not supported (fd %d)" $((fd))
		ret=-LINUX_ENODEV
		return
	fi
	declare -ri size=$(((length + LINUX_PAGE_SIZE - 1) & ~(LINUX_PAGE_SIZE - 1)))
	if ((flags & LINUX_MAP_FIXED)); then
		if ((addr & (LINUX_PAGE_SIZE - 1))); then
			ret=-LINUX_EINVAL
			return
		fi
		zero_memory_range $((addr)) $((size))
		ret=$((addr))
		return
	fi
	if ((GLOBAL_linux_mmap_next + size > 0x7ffffffff000)); then
		ret=-LINUX_ENOMEM
		return
	fi
	ret=$((GLOBAL_linux_mmap_next))
	((GLOBAL_linux_mmap_next += size)) || :
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
	3) # close
		if ((a0 >= 0 && a0 <= 2)); then ret=0; else ret=-LINUX_EBADF; fi
		;;
	9) # mmap
		linux_sys_mmap $((a0)) $((a1)) $((a2)) $((a3)) $((a4)) $((a5))
		;;
	10 | 11) # mprotect, munmap: nothing to do, memory is not protected
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
	20) # writev
		linux_sys_writev $((a0)) $((a1)) $((a2))
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
	96) # gettimeofday
		linux_sys_gettimeofday $((a0))
		;;
	102) # getuid
		ret=${UID}
		;;
	107) # geteuid
		ret=${EUID}
		;;
	104 | 108) # getgid, getegid
		ret=${GROUPS[0]:-0}
		;;
	158) # arch_prctl
		linux_sys_arch_prctl $((a0)) $((a1))
		;;
	201) # time
		linux_sys_time $((a0))
		;;
	218) # set_tid_address: returns the thread id
		ret=$$
		;;
	228) # clock_gettime
		linux_sys_clock_gettime $((a0)) $((a1))
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
	for ((i = 0; i < 16; i++)); do
		registers[$i]=0
		xmm_lo[$i]=0
		xmm_hi[$i]=0
	done
	registers[${RSP}]=$((0x10000))
	GLOBAL_mxcsr=$((0x1f80))
	seg_override=0 seg_base=0 addr_size_prefix=0 rep_prefix=0
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
