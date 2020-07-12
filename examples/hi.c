#include <unistd.h>
#include <string.h>

const char g_msg[] = "Hello World!\n"; 

int main() {
	//write(1, g_msg, strlen(g_msg));
    int64_t n;
    asm volatile(
        "syscall\n"
        : "=A"(n)
        : "a"(0x02000004),   // rax = write syscall
          "D"(1),            // rdi = stdout
          "S"(g_msg),          // rsi = buf
          "d"(strlen(g_msg))); // rdx

    asm volatile(
        "syscall\n"
        :
        : "a"(0x02000001), // rax = exit syscall
          "d"(0));         // rdx = exit code
}
