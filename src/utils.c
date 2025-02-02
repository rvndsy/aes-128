#include <stdio.h>
#include "../include/utils.h"

#define PRETTY_ARRAY_SEPARATOR " "
// Just print a newline. For quick debugging.
void println() { printf("\n"); }
// Print an individual hex byte
void printByteHex(byte b) { printf("%02x", b); }

//void printWordHex(word b) { printf("%08x", b); } //words arent used currently

void printByteArray(const byte * arr, int size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", arr[i]);
    }
}
// Print easier to read hex byte arrays : 11223344 11223344 instead of 1122334411223344
void printByteArrayPretty(const byte * arr, long size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", arr[i]);
        if (i % 4 == 3) printf(PRETTY_ARRAY_SEPARATOR);
    }
}
// Convert two hex characters into a byte
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
// Convert a string of hex characters into a byte array
void convertStrToByteArray(const char * str, byte ** arr, int size) {
    for (size_t i = 0; i < size; i++) {
        char tmp[2];
        tmp[0] = str[i*2];
        tmp[1] = str[i*2+1];
        *arr[i] = strToHexByte(tmp);
    }
}
// Compare two byte arrays and return the count of mismatching bytes. verbose != 0 if you want to see mismatching bytes between the two arrays.
int compareByteArrays(const byte * a, const byte * b, int size, int verbose) {
    int mismatchCount = 0;

    if (verbose) {
        printf("In:  ");
        printByteArrayPretty(a, size);
        printf("\n     ");
    }

    for (size_t i = 0; i < size; i++) {
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
/* Returns 0 if files are identical
 *
 * Returns a non-zero positive integer if files are not identical 
 *
 * Does not rewind file pointers!*/
int compareFiles(FILE *fptr1, FILE *fptr2) {
    unsigned long pos;
    int c1, c2;
    for (pos = 0;; pos++) {
        c1 = getc(fptr1);
        c2 = getc(fptr2);
        if (c1 != c2 || c1 == EOF)
            break;
    }
    if (c1 == c2) {
        // printf("files are identical and have %lu bytes\n", pos);
        return 0;  // files are identical
    } else if (c1 == EOF) {
        // printf("file1 is included in file2, the first %lu bytes are identical\n", pos);
        return 1;
    } else if (c2 == EOF) {
        // printf("file2 is included in file1, the first %lu bytes are identical\n", pos);
        return 2;
    } else {
        // printf("file1 and file2 differ at position %lu: 0x%02X <> 0x%02X\n", pos, c1, c2);
        return 3;
    }
}
