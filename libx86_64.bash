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

### Runtime global variables ###

declare -i GLOBAL_text_vmaddr
declare -i GLOBAL_entryoff
declare -i GLOBAL_stacksize

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
		step
	done
}

function init() {
	typeset -i i
	for ((i = 0; i < 16; i++)); do
		registers[$i]=0
	done
	registers[${RSP}]=$((0x10000))
}

function main() {
	declare -r binary_file="$1"
	dump_file | (
		init
		load_macho_file
		run
	)
}
