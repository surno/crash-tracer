// SIGBUS - access memory with wrong alignment or truncated mmap
// Expected: signal=7
// Note: On x86_64 unaligned access is usually tolerated by hardware,
//       so we use a truncated mmap to reliably trigger SIGBUS.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    fprintf(stderr, "[native/bus_error] Accessing beyond truncated file mmap...\n");
    fflush(stderr);

    // Create a temp file with 1 byte
    char template[] = "/tmp/bustest_XXXXXX";
    int fd = mkstemp(template);
    write(fd, "x", 1);

    // mmap a full page but the file is only 1 byte
    // accessing beyond the file size within the page is OK on Linux,
    // but accessing into the NEXT page triggers SIGBUS
    char *ptr = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    // Access second page - beyond the file's single-byte backing
    ptr[4096] = 'A';

    close(fd);
    unlink(template);
    munmap(ptr, 8192);
    return 0;
}
