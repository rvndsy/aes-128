#ifndef UTILS_H_    // Guard against including twice from the same source
#define UTILS_H_

#include "definitions.h"

void println();
void printByteHex(byte);
void printWordHex(word);
void printByteArray(byte *, int);
byte strToHexByte(char *);
void convertStrToByteArray(const char*, byte**, int);

#endif // UTILS_H_
