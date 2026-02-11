// SIGSEGV - stack overflow via infinite recursion
// Expected: signal=11, si_code=SEGV_MAPERR, fault_addr near stack limit
// Note: fault_addr will be near the bottom of the stack mapping, NOT near 0x0
#include <stdio.h>

volatile int depth = 0;

void recurse() {
    char buf[4096];
    buf[0] = (char)depth;
    depth++;
    recurse();
}

int main() {
    fprintf(stderr, "[native/stack_overflow] Recursing until stack exhaustion...\n");
    fflush(stderr);
    recurse();
    return 0;
}
