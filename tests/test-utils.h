#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <stddef.h>
#include <stdio.h>
#include <../include/filecrypt.h>

#define TEXT_SIZE 64
#define KEY_SIZE 16
#define IV_SIZE 16

#define MAX_THREAD_COUNT 8

struct args_struct {
    filecrypt_ctx * fctx;
    FILE * readFile;
    FILE * writeFileEncrypted;
    FILE * writeFileDecrypted;
    size_t threadNumber;
};

// Pretty sure this key is used by everyone everywhere for testing
// 2b7e151628aed2a6abf7158809cf4f3c
const byte core128Key[KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                      0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                      0x09, 0xcf, 0x4f, 0x3c};

// iV - 000102030405060708090a0b0c0d0e0f
const byte iv[IV_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};



#endif // _TEST_UTILS_H
