#include "utils.h"
#include <stdio.h>
#include <string.h>

#define PRETTY_ARRAY_SEPARATOR " "

void println() { printf("\n"); }

void printByteHex(byte b) { printf("%02x", b); }

//void printWordHex(word b) { printf("%08x", b); }

void printByteArray(const byte * arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", arr[i]);
    }
}

void printByteArrayPretty(const byte * arr, long size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", arr[i]);
        if (i % 4 == 3) printf(PRETTY_ARRAY_SEPARATOR);
    }
}

byte strToHexByte(char * str) {
    byte out = 0x0;
    for (unsigned char i = 0; i < 2; i++) {
        if (str[i] >= 'a' && str[i] <= 'f') {
            out |= str[i] - 'a' + 10;
        } else if (str[i] >= 'A' && str[i] <= 'F') {
            out |= str[i] - 'A' + 10;
        } else if (str[i] >= '0' && str[i] <= '9') {
            out |= str[i] - '0';
        } else {
            return 0x0;
        }
        if (i == 0) out <<= 4;
    }
    return out;
}

void convertStrToByteArray(const char * str, byte ** arr, int size) {
    for (int i = 0; i < size; i++) {
        char tmp[2];
        tmp[0] = str[i*2];
        tmp[1] = str[i*2+1];
        *arr[i] = strToHexByte(tmp);
    }
}

int compareByteArrays(const byte * a, const byte * b, int size, int verbose) {
    int mismatchCount = 0;

    if (verbose) {
        printf("In:  ");
        printByteArrayPretty(a, size);
        printf("\n     ");
    }

    for (int i = 0; i < size; i++) {
        if (a[i] != b[i]) mismatchCount++;
        if (a[i] != b[i] && verbose) {
            printf("^^");
        } else if (verbose) {
            printf("  ");
        }
        if (i % 4 == 3) printf(PRETTY_ARRAY_SEPARATOR);
    }

    if (verbose) {
        printf("\nOut: ");
        printByteArrayPretty(b, size);
    }

    return mismatchCount;
}
