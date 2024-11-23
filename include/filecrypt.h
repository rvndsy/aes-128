#define _FILECRYPT_H_
#ifdef _FILECRYPT_H_

// NOTE: The two functions modify the file directly in binary mode. They also do
// not close files.

#include "definitions.h"
#include <stdio.h>

// this and below is in filecrypt.h
typedef struct {
    cipher_ctx * cipherCtx;
    byte * iv;                    //iV is technically part of CBC (or other mode), not the cipher itself
    unsigned int ivSize;
    unsigned char operationMode;  // defined in filecrypto.h
    long readFileBlockSize; // in bytes
} filecrypt_ctx;

void updateFileCtx(filecrypt_ctx *, cipher_ctx *, unsigned char, long);
filecrypt_ctx * createFileCtx(cipher_ctx *, unsigned char, long);
void addFileCtxIV(filecrypt_ctx *, const byte *, int);
void freeFileCtx(filecrypt_ctx *);

void encryptFile(filecrypt_ctx *, FILE *, FILE *);
void decryptFile(filecrypt_ctx *, FILE *, FILE *);

void encryptBytes(filecrypt_ctx *, unsigned long, byte *);
void decryptBytes(filecrypt_ctx *, unsigned long, byte *);

#define ECB 0 // 0x00000000
#define CBC 1 // 0x0000000C

#define ENCRYPT 16 // 0x000E0000        CBC | ENCRYPT = 0x000E000C
#define DECRYPT 0  // 0x00000000 

#endif // _FILECRYPT_H_
