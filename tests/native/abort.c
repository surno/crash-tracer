// SIGABRT - explicit abort()
// Expected: signal=6, typically from assert failures or runtime checks
#include <stdio.h>
#include <stdlib.h>

int main() {
    fprintf(stderr, "[native/abort] Calling abort()...\n");
    fflush(stderr);
    abort();
    return 0;
}
