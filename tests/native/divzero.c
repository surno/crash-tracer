// SIGFPE - integer division by zero
// Expected: signal=8, si_code=FPE_INTDIV
#include <stdio.h>

int main() {
    fprintf(stderr, "[native/divzero] Dividing by zero...\n");
    fflush(stderr);
    volatile int a = 1;
    volatile int b = 0;
    int c = a / b;
    (void)c;
    return 0;
}
