// SIGILL - execute an invalid CPU instruction
// Expected: signal=4, si_code=ILL_ILLOPC
#include <stdio.h>

int main() {
    fprintf(stderr, "[native/illegal_instruction] Executing UD2 (undefined instruction)...\n");
    fflush(stderr);
    __asm__ volatile("ud2");
    return 0;
}
