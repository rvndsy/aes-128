#ifndef AES_H_    // Guard against including twice from the same source
#define AES_H_

#include "definitions.h"

int encrypt(byte *, const byte *, int);
int decrypt(byte *, const byte *, int);
void aes128(byte *, const byte *, uint16_t, uint8_t);

#endif // AES_H_
