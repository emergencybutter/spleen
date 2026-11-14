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
