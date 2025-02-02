#ifndef _FILECRYPT_H_
#define _FILECRYPT_H_

#include "definitions.h"
#include <stdio.h>

// IMPORTANT:
// *readFile must be at least in rb mode
// *writeFile must be at in wb+ mode

struct _filecrypt_ctx {
    cipher_ctx * cipherCtx;                 //defined in definitions.h
    byte * iv;                              //iV is technically part of CBC (or other mode), not the cipher itself
    unsigned int ivSize;
    unsigned char operationMode;
    unsigned long readFileBlockSize;        // how many bytes to read, encrypt/decrypt and write at a time - size of allocated buffer in bytes
    unsigned long bufferDataEnd;
    unsigned long bytesWritten;
    unsigned char isFirstByte:1;
    unsigned char isFinalBlock:1;
}; //__attribute__((packed))
typedef struct _filecrypt_ctx filecrypt_ctx;

void updateFileCtx(filecrypt_ctx *, cipher_ctx *, unsigned char, long);
filecrypt_ctx * createFileCtx(cipher_ctx *, unsigned char, long);
void addFileCtxIV(filecrypt_ctx *, const byte *, int);
void freeFileCtx(filecrypt_ctx *);

void encryptFile(filecrypt_ctx *, FILE *, FILE *);
void decryptFile(filecrypt_ctx *, FILE *, FILE *);

void encryptBytes(filecrypt_ctx *, unsigned long, byte *);
void decryptBytes(filecrypt_ctx *, unsigned long, byte *);
/* Returns file size in bytes. FILE* must be opened in binary mode */
unsigned long readFileSize(FILE *);

#define ECB 0 // 0x00000000
#define CBC 1 // 0x0000000C

#define ENCRYPT 16 // 0x000E0000        CBC | ENCRYPT = 0x000E000C
#define DECRYPT 0  // 0x00000000 

#define TRUE 1
#define FALSE 0

#endif // _FILECRYPT_H_
