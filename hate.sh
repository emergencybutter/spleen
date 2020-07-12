#!/usr/bin/env bash

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

enable_debug_messages=false

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
	((bash_major >= 4)) || die "$0 needs bash version 4 or higher"
}

# Check the version before initializing variables. We declare associative arrays that fail on old bash.
check_version

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

# Constants for the cmd field of all load commands, the type
declare -ri LC_SEGMENT=$((0x1))         # segment of this file to be mapped
declare -ri LC_SYMTAB=$((0x2))          # link-edit stab symbol table info
declare -ri LC_SYMSEG=$((0x3))          # link-edit gdb symbol table info (obsolete)
declare -ri LC_THREAD=$((0x4))          # thread
declare -ri LC_UNIXTHREAD=$((0x5))      # unix thread (includes a stack)
declare -ri LC_LOADFVMLIB=$((0x6))      # load a specified fixed VM shared library
declare -ri LC_IDFVMLIB=$((0x7))        # fixed VM shared library identification
declare -ri LC_IDENT=$((0x8))           # object identification info (obsolete)
declare -ri LC_FVMFILE=$((0x9))         # fixed VM file inclusion (internal use)
declare -ri LC_PREPAGE=$((0xa))         # prepage command (internal use)
declare -ri LC_DYSYMTAB=$((0xb))        # dynamic link-edit symbol table info
declare -ri LC_LOAD_DYLIB=$((0xc))      # load a dynamically linked shared library
declare -ri LC_ID_DYLIB=$((0xd))        # dynamically linked shared lib ident
declare -ri LC_LOAD_DYLINKER=$((0xe))   # load a dynamic linker
declare -ri LC_ID_DYLINKER=$((0xf))     # dynamic linker identification
declare -ri LC_PREBOUND_DYLIB=$((0x10)) # modules prebound for a dynamically
#  linked shared library
declare -ri LC_ROUTINES=$((0x11))       # image routines
declare -ri LC_SUB_FRAMEWORK=$((0x12))  # sub framework
declare -ri LC_SUB_UMBRELLA=$((0x13))   # sub umbrella
declare -ri LC_SUB_CLIENT=$((0x14))     # sub client
declare -ri LC_SUB_LIBRARY=$((0x15))    # sub library
declare -ri LC_TWOLEVEL_HINTS=$((0x16)) # two-level namespace lookup hints
declare -ri LC_PREBIND_CKSUM=$((0x17))  # prebind checksum

declare -ri LC_REQ_DYLD=$((0x80000000))

declare -ri LC_LOAD_WEAK_DYLIB=$((0x18 | LC_REQ_DYLD))

declare -ri LC_SEGMENT_64=$((0x19))                      # 64-bit segment of this file to be mapped
declare -ri LC_ROUTINES_64=$((0x1a))                     # 64-bit image routines
declare -ri LC_UUID=$((0x1b))                            # the uuid
declare -ri LC_RPATH=$((0x1c | LC_REQ_DYLD))             # runpath additions
declare -ri LC_CODE_SIGNATURE=$((0x1d))                  # local of code signature
declare -ri LC_SEGMENT_SPLIT_INFO=$((0x1e))              # local of info to split segments
declare -ri LC_REEXPORT_DYLIB=$((0x1f | LC_REQ_DYLD))    # load and re-export dylib
declare -ri LC_LAZY_LOAD_DYLIB=$((0x20))                 # delay load of dylib until first use
declare -ri LC_ENCRYPTION_INFO=$((0x21))                 # encrypted segment information
declare -ri LC_DYLD_INFO=$((0x22))                       # compressed dyld information
declare -ri LC_DYLD_INFO_ONLY=$((0x22 | LC_REQ_DYLD))    # compressed dyld information only
declare -ri LC_LOAD_UPWARD_DYLIB=$((0x23 | LC_REQ_DYLD)) # load upward dylib
declare -ri LC_VERSION_MIN_MACOSX=$((0x24))              # build for MacOSX min OS version
declare -ri LC_VERSION_MIN_IPHONEOS=$((0x25))            # build for iPhoneOS min OS version
declare -ri LC_FUNCTION_STARTS=$((0x26))                 # compressed table of function start addresses
declare -ri LC_DYLD_ENVIRONMENT=$((0x27))                # string for dyld to treat like environment variable
declare -ri LC_MAIN=$((0x28 | LC_REQ_DYLD))              # replacement for LC_UNIXTHREAD
declare -ri LC_DATA_IN_CODE=$((0x29))                    # table of non-instructions in __text
declare -ri LC_SOURCE_VERSION=$((0x2A))                  # source version used to build binary
declare -ri LC_DYLIB_CODE_SIGN_DRS=$((0x2B))             # Code signing DRs copied from linked dylibs

declare -ri WIDTH64=8
declare -ri WIDTH32=4
declare -ri WIDTH16=2
declare -ri WIDTH8=1

declare -A COMMAND_NR_TO_NAME=(
	[$((0x1))]="LC_SEGMENT"
	[$((0x2))]="LC_SYMTAB"
	[$((0x3))]="LC_SYMSEG"
	[$((0x4))]="LC_THREAD"
	[$((0x5))]="LC_UNIXTHREAD"
	[$((0x6))]="LC_LOADFVMLIB"
	[$((0x7))]="LC_IDFVMLIB"
	[$((0x8))]="LC_IDENT"
	[$((0x9))]="LC_FVMFILE"
	[$((0xa))]="LC_PREPAGE"
	[$((0xb))]="LC_DYSYMTAB"
	[$((0xc))]="LC_LOAD_DYLIB"
	[$((0xd))]="LC_ID_DYLIB"
	[$((0xe))]="LC_LOAD_DYLINKER"
	[$((0xf))]="LC_ID_DYLINKER"
	[$((0x10))]="LC_PREBOUND_DYLIB"
	[$((0x11))]="LC_ROUTINES"
	[$((0x12))]="LC_SUB_FRAMEWORK"
	[$((0x13))]="LC_SUB_UMBRELLA"
	[$((0x14))]="LC_SUB_CLIENT"
	[$((0x15))]="LC_SUB_LIBRARY"
	[$((0x16))]="LC_TWOLEVEL_HINTS"
	[$((0x17))]="LC_PREBIND_CKSUM"
	[$((0x19))]="LC_SEGMENT_64"
	[$((0x1a))]="LC_ROUTINES_64"
	[$((0x1b))]="LC_UUID"
	[$((0x1d))]="LC_CODE_SIGNATURE"
	[$((0x1e))]="LC_SEGMENT_SPLIT_INFO"
	[$((0x20))]="LC_LAZY_LOAD_DYLIB"
	[$((0x21))]="LC_ENCRYPTION_INFO"
	[$((0x22))]="LC_DYLD_INFO"
	[$((0x22))]="LC_DYLD_INFO_ONLY"
	[$((0x23))]="LC_LOAD_UPWARD_DYLIB"
	[$((0x24))]="LC_VERSION_MIN_MACOSX"
	[$((0x25))]="LC_VERSION_MIN_IPHONEOS"
	[$((0x26))]="LC_FUNCTION_STARTS"
	[$((0x27))]="LC_DYLD_ENVIRONMENT"
	[$((0x28))]="LC_MAIN"
	[$((0x29))]="LC_DATA_IN_CODE"
	[$((0x2A))]="LC_SOURCE_VERSION"
	[$((0x2B))]="LC_DYLIB_CODE_SIGN_DRS"
)

# Insanity
declare -a memory

declare -a registers

function dump_file() {
	hexdump -v -e '/1 "%u\n"' /tmp/hi
}

function dump_at() {
	declare -ri offset="$1"
	declare -ri size="$2"
	hexdump -v -e '/1 "%u\n"' /tmp/hi | (
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
		echo "${COMMAND_NR_TO_NAME[${cmd}]}${req_dyld}"
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

	info "Segment.Section: ${segname}.${sectname} addr: %x size: %x offset: %x align: %x" \
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
		declare -g text_vmaddr=${vmaddr}
	fi

	declare -i i
	for ((i = 0; i < nsects; i++)); do
		consume_section_64 ${i}
	done
}

function consume_entry_point() {
	declare -ri load_command_cmdsize="$1"
	declare -g entryoff=$(consume_uint64)  # file (__TEXT) offset of main()
	declare -g stacksize=$(consume_uint64) # if not zero, initial stack size
	debug "Found entry point: ${entryoff}"
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
	declare -i mov="$1"
	declare -i modrm="$2"
	declare -i direction=$(((mov >> 1) & 0x1))
	declare -i width_is_byte=$((mov & 0x1))

	declare -i width=$((width_is_byte ? WIDTH8 : $(get_width)))

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
	debug "Syscall: %0x\n" ${registers[$((RAX))]}
	case ${registers[$((RAX))]} in
	$((0x02000004)))
		inst_syscall_write
		;;
	*)
		die "Unimplemented syscall"
		;;
	esac
}

function inst_syscall_write() {
	declare -ri out_fd=${registers[$((RDI))]}
	declare -ri buf=${registers[$((RSI))]}
	declare -ri len=${registers[$((RDX))]}
	declare -i i
	declare string=

	for ((i = 0; i < len; i++)); do
		string="${string}$(printf '\\x%x' $(get_memory 1 $((buf + i))))"
	done
	debug "SYSCALL WRITE: %x %x %x %s" $((out_fd)) $((buf)) $((len)) "${string}"
	printf "${string}"
}

function run() {
	declare -i rip=$((text_vmaddr + entryoff))
	declare -i rex=0 rex_w=0 rex_r=0 rex_x=0 rex_b=0 operand_size_prefix=0

	while true; do
		declare -i prefix_set=0
		declare -i advance=1
		declare -i instruction=$((memory[rip]))

		case $((instruction & 0xF0)) in
		$((0x50)))
			inst_push $((instruction & 0x0F))
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
	gcc -o /tmp/hi hi.c

	dump_file | (
		init
		load_macho_file
		run
	)
}

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

function run_tests() {
	init
	test_set_get_register
	test_set_get_memory
}

run_tests
main
