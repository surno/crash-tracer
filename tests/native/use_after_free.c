// Heap use-after-free - behavior is undefined
// Expected: May SIGSEGV, may silently corrupt, may work "fine"
// This demonstrates why UAF bugs are dangerous - the crash is non-deterministic.
// With ASAN it would be caught immediately; without it, the behavior depends on
// whether the allocator has reused or unmapped the page.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    fprintf(stderr, "[native/use_after_free] Allocating, freeing, then writing...\n");
    fflush(stderr);

    // Large allocation so free() is more likely to munmap
    char *p = malloc(1024 * 1024);
    memset(p, 'A', 1024 * 1024);
    free(p);

    // Force a second large alloc to encourage the allocator to reclaim
    char *q = malloc(1024 * 1024);
    free(q);

    fprintf(stderr, "[native/use_after_free] Writing to freed pointer...\n");
    fflush(stderr);

    // This may or may not crash depending on allocator state
    memset(p, 'B', 1024 * 1024);

    fprintf(stderr, "[native/use_after_free] Survived (UAF didn't crash - this is the danger)\n");
    return 0;
}
