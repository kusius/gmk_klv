#define KLV_IMPLEMENTATION
#include "klv.h"
#include <stdio.h>

int main(void) {
    KLVElement checksum = KLVChecksum;
    for(int i = 0; i < 16; ++i) {
        printf("%x", checksum.key[i]);
    }
    printf("\n");
    return 0;
}