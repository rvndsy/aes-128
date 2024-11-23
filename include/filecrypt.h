#define _FILECRYPT_H_
#ifdef _FILECRYPT_H_

// NOTE: The two functions modify the file directly in binary mode. They also do
// not close files.

#include "definitions.h"
#include <stdio.h>

// this and below is in filecrypt.h
typedef struct {
    cipher_ctx * cipherCtx; // 
    unsigned char operationMode;  // defined in filecrypto.h
    long readFileBlockSize; // in bytes
} filecrypt_ctx;

void prepareFileCtx(filecrypt_ctx *, cipher_ctx *, unsigned char, long);
void encryptFile(filecrypt_ctx *, FILE *, FILE *);
void decryptFile(filecrypt_ctx *, FILE *, FILE *);

void encryptBytes(filecrypt_ctx *, byte *, long);
void decryptBytes(filecrypt_ctx *, byte *, long);

#define ECB 0
#define CBC 1

#define ENCRYPT 0
#define DECRYPT 8

#endif // _FILECRYPT_H_
