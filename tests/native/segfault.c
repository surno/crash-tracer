// SIGSEGV - null pointer dereference
// Expected: signal=11, si_code=SEGV_MAPERR, fault_addr near 0x0
#include <stdio.h>

int main() {
    fprintf(stderr, "[native/segfault] Dereferencing NULL pointer...\n");
    fflush(stderr);
    int *p = (int *)0;
    *p = 42;
    return 0;
}
