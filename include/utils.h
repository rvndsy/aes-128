#ifndef UTILS_H_    // Guard against including twice from the same source
#define UTILS_H_

#include "definitions.h"
#include "stdio.h"

void println();
void printByteHex(byte);
//void printWordHex(word);
void printByteArray(const byte*, int);
void printByteArrayPretty(const byte*, long);
byte strToHexByte(char*);
void convertStrToByteArray(const char*, byte**, int);
int compareByteArrays(const byte*, const byte*, int, int);
int compareFiles(FILE *, FILE *);

#endif // UTILS_H_
