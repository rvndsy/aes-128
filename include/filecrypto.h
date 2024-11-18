#define _FILECRYPTO_H_
#ifdef _FILECRYPTO_H_

// NOTE: The two functions modify the file directly in binary mode. They also do not close files.
//
// Modes (defined in aes.h):
// ECB = 0
// CBC = 1

#include <stdint.h>
#include <stdio.h>
#include "aes.h"

void encryptFile(FILE *, FILE *, const byte *, const byte *, uint8_t);
void decryptFile(FILE *, FILE *, const byte *, const byte *, uint8_t);

#endif // _FILECRYPTO_H_
