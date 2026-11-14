/*
 * Minimal static, no-libc Linux x86_64 ELF "Hello World!".
 * Only uses lea, mov, xor and syscall so spleen can run it.
 *
 * Build (see gen-examples.sh):
 *   cc -nostdlib -static -no-pie -o examples-bin/hi-linux examples/hi-linux.S
 */
	.section .rodata
g_msg:
	.ascii "Hello World!\n"
	.set g_msg_len, . - g_msg

	.text
	.globl _start
_start:
	lea g_msg(%rip), %rsi      /* rsi = buf */
	mov $1, %eax               /* rax = SYS_write */
	mov $1, %edi               /* rdi = stdout */
	mov $g_msg_len, %edx       /* rdx = len */
	syscall

	mov $60, %eax              /* rax = SYS_exit */
	xor %edi, %edi             /* rdi = exit code 0 */
	syscall
