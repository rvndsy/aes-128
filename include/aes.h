#ifndef AES_H_    // Guard against including twice from the same source
#define AES_H_

#include "definitions.h" //for byte typedef

void cipher(byte *, const byte *);
void invCipher(byte *, const byte *);
void encryptECB(byte *, const byte *, int);
void decryptECB(byte *, const byte *, int);
void encryptCBC(byte *, const byte *, const byte *, int);
void decryptCBC(byte *, const byte *, const byte *, int);

#define ENCRYPT 0
#define DECRYPT 1

#define ECB 0
#define CBC 1

#define NB 4            //Number of 32-bit columns for the state/block/text - always 4
#define NB_BYTES 16     //Plaintext/Ciphertext/State size in bytes - always 32*NB/8

#endif // AES_H_
