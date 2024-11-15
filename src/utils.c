#include "utils.h"
#include <stdio.h>

void println() { printf("\n"); }

void printByteHex(byte b) { printf("%02x", b); }

void printWordHex(word b) { printf("%08x", b); }

void printByteArray(const byte * arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", arr[i]);
    }
}

void printByteArrayPretty(const byte * arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", arr[i]);
        if (i % 4 == 3) printf(" ");
    }
}

// byte charToHex(char c) {
//     if (c >= 'a' && c <= 'f') {
//         return c - 'a' + 10;
//     } else if (c >= 'A' && c <= 'F') {
//         return c - 'A' + 10;
//     } else if (c >= '0' && c <= '9') {
//         return c - '0';
//     } else {
//         return 0x10;
//     }
// }

byte strToHexByte(char * str) {
    byte out = 0x0;
    for (uint8_t i = 0; i < 2; i++) {
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
