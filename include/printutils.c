#include <stdio.h>
#include "definitions.h"

void println() { printf("\n"); }

void printByteHex(uint8_t b) {
    printf("%02x", b);
}

void printByteArray(byte * arr, int size) {
    for (int i = 0; i < size; i++) {
        printByteHex(arr[i]);
    }
}
