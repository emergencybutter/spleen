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
		consume "${offset}"
		head -n "${size}"
	)
}

function consume_uint8() {
	declare -i i0
	read i0
	echo "${i0}"
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
	print_le32 "${i0}" "${i1}" "${i2}" "${i3}"
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
			printf "$(printf '\\x%x' ${i0})"
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
		echo "(2^32)*${i1} + ${i0}" | bc -l
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
	if [[ ! ${COMMAND_NR_TO_NAME[${cmd}]+_} ]]; then
		echo "UNKNOWN"
	else
		echo "$(command_nr_to_name $((cmd)))${req_dyld}"
	fi
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
		typeset -i i="${vmaddr}"
		typeset -i value
		while read value; do
			#printf "loading %x at %x\n" ${value} $((offset + i))
			memory[$((i + offset))]=${value}
			((i++)) || :
		done < <(dump_at "${offset}" "${size}")
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
		${vmaddr} ${vmsize}
	debug "	fileoff: %x filesize: %x maxprot: %x nsects: %x flags: %x" \
		${fileoff} ${filesize} ${maxprot} ${nsects} ${flags}
	if [[ ${segname} = "__TEXT" ]]; then
		((GLOBAL_text_vmaddr = vmaddr)) || :
	fi

	declare -i i
	for ((i = 0; i < nsects; i++)); do
		consume_section_64 ${i}
	done
}

function consume_entry_point() {
	declare -ri load_command_cmdsize="$1"
	GLOBAL_entryoff=$(consume_uint64)  # file (__TEXT) offset of main()
	GLOBAL_stacksize=$(consume_uint64) # if not zero, initial stack size
	debug "Found entry point: ${GLOBAL_entryoff}"
}

function consume_command() {
	declare -ri load_command_cmd=$(consume_uint32)
	declare -ri load_command_cmdsize=$(consume_uint32)

	declare req_dyld=""

	debug "Command: ${load_command_cmd}: $(command_name "${load_command_cmd}") ${LC_MAIN}"

	case ${load_command_cmd} in
	${LC_SEGMENT_64})
		consume_segment_64 "${load_command_cmdsize}"
		;;
	${LC_MAIN})
		consume_entry_point "${load_command_cmdsize}"
		;;
	*)
		consume "$((load_command_cmdsize - 8))"
		;;
	esac
}

function inst_push() {
	declare -i reg="$1"
	((registers[${RSP}] -= 8)) || :
	memory[${registers[${RSP}]}]=${registers[${reg}]}
}

function unknown_insruction() {
	declare instruction="$1"
	declare msg="$2"
	die "Unknown instruction at 0x%x: ${instruction} (${msg})\n" $((rip))
}

# Modifies variables `displacement` and `advance`
function disp32() {
	declare -ri i0=${memory[$((rip + advance))]}
	declare -ri i1=${memory[$((rip + advance + 1))]}
	declare -ri i2=${memory[$((rip + advance + 2))]}
	declare -ri i3=${memory[$((rip + advance + 3))]}
	((advance += 4)) || :
	displacement=$(print_le32 "${i0}" "${i1}" "${i2}" "${i3}")
}

# Modifies variables `displacement` and `advance`
function disp16() {
	declare -ri i0=${memory[$((rip + advance))]}
	declare -ri i1=${memory[$((rip + advance + 1))]}
	((advance += 2)) || :
	displacement=$(print_le16 "${i0}" "${i1}")
}

# Modifies variables `displacement` and `advance`
function disp8() {
	declare -ri i0=${memory[$((rip + advance))]}
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
		registers[$((reg))]=$((registers[reg] & (~0 << 8) | (value & 0xff)))
		;;
	2)
		registers[$((reg))]=$((registers[reg] & (~0 << 16) | (value & 0xffff)))
		;;
	4)
		registers[$((reg))]=$((registers[reg] & (~0 << 32) | (value & 0xfffffff)))
		;;
	8)
		registers[$((reg))]=$((value))
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
		memory[address + i]=${value_bytes[i]}
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
				declare -i modrm=${memory[$((rip + advance))]}
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

function main() {
	declare -r binary_file="$1"
	dump_file | (
		init
		load_macho_file
		run
	)
}
