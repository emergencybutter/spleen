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
# Operating system ABI of the loaded binary: "macos" (Mach-O) or "linux" (ELF).
# Syscall emulation dispatches on this.
declare GLOBAL_os_abi="macos"

# Insanity
declare -a memory

declare -a registers

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

	declare -i phdr_addr=0 text_vmaddr=-1
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
	# run() starts at GLOBAL_text_vmaddr + GLOBAL_entryoff.
	((GLOBAL_text_vmaddr = text_vmaddr)) || :
	((GLOBAL_entryoff = load_base + e_entry - text_vmaddr)) || :
	debug "ELF: entry point: %x" $((load_base + e_entry))

	setup_linux_stack $((load_base + e_entry)) $((phdr_addr)) \
		$((e_phentsize)) $((e_phnum)) "$@"
}

function inst_push() {
	declare -i reg="$1"
	((registers[${RSP}] -= 8)) || :
	((memory[registers[RSP]]=registers[reg])) || :
}

function unknown_insruction() {
	declare instruction="$1"
	declare msg="$2"
	die "Unknown instruction at 0x%x: ${instruction} (${msg})\n" $((rip))
}

# Modifies variables `displacement` and `advance`
function disp32() {
	declare -ri i0=$((memory[rip + advance]))
	declare -ri i1=$((memory[rip + advance + 1]))
	declare -ri i2=$((memory[rip + advance + 2]))
	declare -ri i3=$((memory[rip + advance + 3]))
	((advance += 4)) || :
	displacement=$(print_le32 $((i0)) $((i1)) $((i2)) $((i3)))
}

# Modifies variables `displacement` and `advance`
function disp16() {
	declare -ri i0=$((memory[rip + advance]))
	declare -ri i1=$((memory[rip + advance + 1]))
	((advance += 2)) || :
	displacement=$(print_le16 $((i0)) $((i1)))
}

# Modifies variables `displacement` and `advance`
function disp8() {
	declare -ri i0=$((memory[rip + advance]))
	((advance += 1)) || :
	((displacement = i0)) || :
}

# Modifies variables `displacement` and `advance`
function disp_width() {
	declare -i width="$1"
	case $((width)) in
	$((WIDTH8)))
		disp8
		;;
	$((WIDTH16)))
		disp16
		;;
	$((WIDTH32)))
		disp32
		;;
	*)
		# I've never seen a 64 bit immediate value or displacement.
		# Yolo. Assume it does not exist.
		die "Invalid width for immediate value or displacement."
		;;
	esac
}

# Sets modrm_mod modrm_rm modrm_reg modrm_address
function operands_modrm() {
	declare -i modrm="$1"
	modrm_mod=$((modrm >> 6 & 0x3))
	modrm_reg=$(((modrm >> 3) & 0x7 | rex_b << 3))
	modrm_rm=$(((modrm) & 0x7 | rex_r << 3))
	modrm_address=0

	case $((modrm_mod)) in
	0)
		case $((modrm_rm)) in
		$((RSP)))
			die "Unimplemented modrm: SIB"
			;;
		$((R13)))
			die "Unimplemented modrm: SIB"
			;;
		$((RBP)))
			declare -i displacement
			disp32
			# RIP addressing, we add the displacement to rip *after* the current instruction.
			# disp32 already modified `advance`, so adding advance should point to the next
			# instruction.
			modrm_address=$((rip + displacement + advance))
			;;
		*)
			modrm_address=$((registers[modrm_rm]))
			;;
		esac
		;;
	1)
		case $((modrm_rm)) in
		$((RSP)))
			die "Unimplemented modrm: SIB"
			;;
		$((R13)))
			die "Unimplemented modrm: SIB"
			;;
		*)
			declare -i displacement
			disp8
			modrm_address=$((registers[modrm_rm] + displacement))
			;;
		esac
		;;
	2)
		case $((modrm_rm)) in
		$((RSP)))
			die "Unimplemented modrm: SIB"
			;;
		$((R13)))
			die "Unimplemented modrm: SIB"
			;;
		*)
			declare -i displacement
			disp32
			modrm_address=$((registers[modrm_rm] + displacement))
			;;
		esac
		;;
	3) ;;

	*)
		die "Internal error, invalid modrm: 0x%x" $((modrm))
		;;
	esac
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
		((registers[reg]=registers[reg] & (~0 << 32) | (value & 0xfffffff) )) || :
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

function inst_mov() {
	declare -ri mov="$1"
	declare -ri modrm="$2"
	declare -ri direction=$(((mov >> 1) & 0x1))
	declare -ri width_is_byte=$((~mov & 0x1))

	declare -ri width=$((width_is_byte ? WIDTH8 : $(get_width)))

	declare -i modrm_mod modrm_reg modrm_rm modrm_address
	operands_modrm $((modrm))

	case $((modrm_mod)) in
	3)
		if ((direction)); then
			set_register $((width)) $((modrm_reg)) "$(get_register $((width)) $((modrm_rm)))"
		else
			set_register $((width)) $((modrm_rm)) "$(get_register $((width)) $((modrm_reg)))"
		fi
		;;
	*)
		if ((direction)); then
			set_register $((width)) $((modrm_reg)) "$(get_memory $((width)) $((modrm_address)))"
		else
			set_memory $((width)) $((modrm_address)) "$(get_register $((width)) $((modrm_reg)))"
		fi
		;;
	esac
}

function binary_op_xor() {
	declare -ri operand0="$1"
	declare -ri operand1="$2"
	echo $((operand0 ^ operand1))
}

function inst_binary_op() {
	declare -r binary_op="$1"
	declare -ri binary_instruction="$2"
	declare -ri modrm="$3"
	declare -ri direction=$(((binary_instruction >> 1) & 0x1))
	declare -ri width_is_byte=$((~binary_instruction & 0x1))

	declare -ri width=$((width_is_byte ? WIDTH8 : $(get_width)))

	declare -i modrm_mod modrm_reg modrm_rm modrm_address
	operands_modrm $((modrm))

	case $((modrm_mod)) in
	3)
		declare -ri operand0=$(get_register $((width)) $((modrm_rm)))
		declare -ri operand1=$(get_register $((width)) $((modrm_reg)))
		if ((direction)); then
			declare -ri result=$("${binary_op}" "${operand0}" "${operand1}")
			set_register $((width)) $((modrm_reg)) $((result))
		else
			declare -ri result=$("${binary_op}" "${operand1}" "${operand0}")
			set_register $((width)) $((modrm_rm)) $((result))
		fi
		;;
	*)
		declare -ri operand0=$(get_register $((width)) $((modrm_reg)))
		declare -ri operand1=$(get_memory $((width)) $((modrm_address)))
		if ((direction)); then
			declare -ri result=$("${binary_op}" "${operand0}" "${operand1}")
			set_register $((width)) $((modrm_reg)) "$(get_memory $((width)) $((modrm_address)))"
		else
			declare -ri result=$("${binary_op}" "${operand1}" "${operand0}")
			set_memory $((width)) $((modrm_address)) $((result))
		fi
		;;
	esac
}

function inst_lea() {
	declare -i lea="$1"
	declare -i modrm="$2"
	declare -i modrm_mod modrm_reg modrm_rm modrm_address
	operands_modrm $((modrm))
	set_register WIDTH64 $((modrm_reg)) $((modrm_address))
}

function inst_mov_imm() {
	declare -ri mov="$1"
	declare -ri reg=$((mov & 0x7 | rex_b << 3))
	declare -i displacement
	disp_width $((width))
	set_register $((width)) $((reg)) $((displacement))
}

# This function is basically an OSX kernel emulator written in bash.
function inst_syscall() {
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

function run() {
	declare -i rip=$((GLOBAL_text_vmaddr + GLOBAL_entryoff))
	declare -i rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 operand_size_prefix=0

	while true; do
		declare -i prefix_set=0
		declare -i advance=1
		declare -i instruction=$((memory[rip]))

		case $((instruction & 0xF0)) in
		$((0x30)))
			if (((instruction & 0xF) < 5)); then
				declare -i modrm=$((memory[rip + advance]))
				((advance++)) || :
				inst_binary_op binary_op_xor $((instruction)) $((modrm))
			else
				unknown_insruction "$(printf '%02x' $((instruction)))" "maybe a xor"
			fi
			;;
		$((0x40)))
			((rex = instruction)) || :
			((rex_w = rex >> 3 & 0x1)) || :
			((rex_r = rex >> 2 & 0x1)) || :
			((rex_x = rex >> 1 & 0x1)) || :
			((rex_b = rex & 0x1)) || :
			((prefix_set = 1)) || :
			;;
		$((0x60)))
			case $((instruction)) in
			0x66)
				operand_size_prefix=$((instruction))
				;;
			esac
			;;
		$((0x50)))
			inst_push $((instruction & 0x0F))
			;;
		$((0x80)))
			case $((instruction & 0xF)) in
			$((0x9)))
				declare -i modrm=${memory[$((rip + advance))]}
				((advance++)) || :
				inst_mov $((instruction)) $((modrm))
				;;
			$((0xd)))
				declare -i modrm=${memory[$((rip + advance))]}
				((advance++)) || :
				inst_lea $((instruction)) $((modrm))
				;;
			*)
				unknown_insruction "$(printf '%02x' $((instruction)))" "maybe a mov"
				;;
			esac
			;;
		$((0xb0)))
			declare -i width
			if ((instruction & 0xF < 8)); then
				((width = WIDTH8)) || :
			else
				width=$(get_width)
			fi
			inst_mov_imm $((instruction))
			;;
		$((0)))
			case $((instruction)) in
			$((0x0f)))
				declare -i instruction_byte_2=${memory[$((rip + advance))]}
				((advance++)) || :
				case $((instruction_byte_2)) in
				$((0x05)))
					inst_syscall
					;;
				*)
					die "Unsupported 2 byte instruction: %02x%02x" \
						$((instruction)) $((instruction_byte_2))
					;;
				esac
				;;
			esac
			;;
		*)
			die "Unsupported instruction: 0x%x" $((instruction))
			;;
		esac

		((rip += advance)) || :
		((advance = 1)) || :

		# Reset prefix variable unless we just set a prefix
		if ((prefix_set)); then
			((prefix_set = 0)) || :
		else
			rex=0
			rex_w=0
			rex_r=0
			rex_x=0
			rex_b=0
			operand_size_prefix=0
		fi
	done
}

function init() {
	typeset -i i
	for ((i = 0; i < $((0xf)); i++)); do
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
	case "${format}" in
	macho)
		dump_file | (
			init
			load_macho_file
			run
		)
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
