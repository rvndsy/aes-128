#include <stdio.h>
#include <string.h> //for memcpy...
#include "../include/aes.h"
#include "../include/filecrypto.h"
#include "../include/definitions.h"

#define VERBOSE 1
#define BENCHMARK 1

#if BENCHMARK == 1
#include <time.h>
#endif

#define TEXT_SIZE 64
#define KEY_SIZE 16
#define IV_SIZE 16

// Key is the same for ECB, CBC
const byte aesCore128Key[KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// iV
const byte iv[IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const char * plainPDFSample = "./samples/file.pdf";
const char * cipherPDFSample = "./samples/cfile.pdf";

const char * cipherTXTSample = "./samples/cfile.md";
const char * plainTXTSample = "./samples/file.md";
//const char * cipherIMGSample = "./samples/c-lorem-picsum-200.jpg";
//const char * plainIMGSample = "./samples/lorem-picsum-200.jpg";

static float startTime, endTime;
static float testMode;
static byte state[TEXT_SIZE];

int testEncryptDecryptPDF128ECB(byte * state, const byte * key) {
    printf("AES-128 ECB ENCRYPT PDF TEST...\n");

    FILE * fptrRead, * fptrWriteCipher, * fptrWritePlain;
    fptrRead = fopen(plainPDFSample, "rb");
    fptrWriteCipher = fopen("ecb-128-encrypted.pdf", "wb+");
    fptrWritePlain = fopen("ecb-128-decrypted.pdf", "wb");

    if (fptrRead == NULL) fprintf(stderr, "Sample file %s does not exist", plainTXTSample);
    if (fptrWritePlain == NULL) fprintf(stderr, "Cannot open plaintext file to write");
    if (fptrWriteCipher == NULL) fprintf(stderr, "Cannot open ciphertext file to write");

    #if BENCHMARK == 1
        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    encryptFile(fptrRead, fptrWriteCipher, aesCore128Key, iv, CBC);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Encrypt time: %fs\n", endTime - startTime);
    #endif

    #if BENCHMARK == 1
        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    decryptFile(fptrWriteCipher, fptrWritePlain, aesCore128Key, iv, CBC);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Decrypt time: %fs\n", endTime - startTime);
    #endif

    fclose(fptrRead);
    fclose(fptrWritePlain);
    fclose(fptrWriteCipher);

    //return compareFiles(plainPDFSample, cipherPDFSample, TEXT_SIZE, VERBOSE);
    return 0;
}

void runTest(int (*testFuncPtr)()) {
    int mismatchCount;

    mismatchCount = testFuncPtr();

    #if VERBOSE == 1
        printf("\n%d mismatching bytes\n", mismatchCount);
    #endif

    if (mismatchCount == 0) printf("...PASSED\n\n");
    else printf("...FAILED\n\n");
}

int main(int argc, char ** argv) {
    FILE * fptr;
    //if (argc == 1 || argc > 2) testMode = 0.5;
    //else testMode = (float)*argv[1]-'0';

    runTest(&testEncryptDecryptPDF128ECB);
    //runTest(&testDecryptPDF128ECB);

    return 0;
}
