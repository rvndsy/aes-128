#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //for memcpy...
#include "../include/filecrypt.h"
#include "../include/aes.h"
#include "../include/definitions.h"
#include "../include/utils.h"
#include "test-utils.h"
#include "sample-files.h"

#define VERBOSE 1
#define BENCHMARK 1

#if BENCHMARK == 1
#include <time.h>
#endif

#define THREAD_COUNT 8

static float startTime, endTime;

long printFailStatus(long value) {
    if (value != 0) {
        fprintf(stdout, "...FAIL\n");
    } else {
        fprintf(stdout, "...OK\n");
    }
    return value;
}

char * fileNameMaker(uint8_t mode, uint16_t version, uint8_t isEncrypt, uint8_t fileType, long appendValue) {
    char * fileName = malloc(sizeof(char) * 32);
    memset(fileName, '\0', 32);
    switch (mode) {
        case ECB:
            strcat(fileName, "ecb-");
            break;
        case CBC:
            strcat(fileName, "cbc-");
            break;
    }
    switch (version) {
        case 128:
            strcat(fileName, "128-");
            break;
        case 196:
            strcat(fileName, "196-");
            break;
        case 256:
            strcat(fileName, "256-");
            break;
    }
    switch (isEncrypt) {
        case ENCRYPT:
            strcat(fileName, "encrypted");
            break;
        case DECRYPT:
            strcat(fileName, "decrypted");
            break;
    }
    if (appendValue >= 0) {
        char istr[sizeof(appendValue)];
        sprintf(istr, "-%ld", appendValue);
        strcat(fileName, istr);
    }
    switch (fileType) {
        case PDF:
            strcat(fileName, ".pdf");
            break;
        case TXT:
            strcat(fileName, ".md");
            break;
    }
    return fileName;
}

void deleteWrittenFiles(uint8_t mode, uint16_t version, uint8_t fileType, size_t fileCount) {
    fprintf(stdout, "DELETING WRITTEN FILES\n");
    char * fileName;
    size_t result = 0;
    for (size_t fileNumber = 0; fileNumber < fileCount; fileNumber++) {
        fileName = fileNameMaker(mode, version, ENCRYPT, PDF, fileNumber);
        fprintf(stdout, "Deleting file: %s ", fileName);
        result += printFailStatus(remove(fileName));
    }
    for (size_t fileNumber = 0; fileNumber < fileCount; fileNumber++) {
        fileName = fileNameMaker(mode, version, DECRYPT, PDF, fileNumber);
        fprintf(stdout, "Deleting file: %s ", fileName);
        result += printFailStatus(remove(fileName));
    }
}

size_t testSingleFileEncryptDecrypt(uint8_t mode, uint16_t version, uint8_t fileType, size_t fileReadBufferSize) {
    if (mode == ECB) {
        printf("AES-128 ECB ENCRYPT PDF TEST...\n");
    } else if (mode == CBC) {
        printf("AES-128 CBC ENCRYPT PDF TEST...\n");
    }

    char * fileNameEncrypt = fileNameMaker(mode, version, ENCRYPT, fileType, -1);
    char * fileNameDecrypt = fileNameMaker(mode, version, DECRYPT, fileType, -1);

    FILE * fptrReadPlain, * fptrWriteCipher, * fptrWritePlain;
    if (fileType == PDF) {
        fptrReadPlain = fopen(plainPDFSample, "rb");
    } else if (fileType == TXT) {
        fptrReadPlain = fopen(plainTXTSample, "rb");
    }
    fptrWriteCipher = fopen(fileNameEncrypt, "wb+");
    fptrWritePlain = fopen(fileNameDecrypt, "wb+");

    if (fptrReadPlain == NULL) fprintf(stderr, "Sample file %s does not exist", plainTXTSample);
    if (fptrWritePlain == NULL) fprintf(stderr, "Cannot open plaintext file to write");
    if (fptrWriteCipher == NULL) fprintf(stderr, "Cannot open ciphertext file to write");

    #if BENCHMARK == 1
        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    cipher_ctx * aes = createAESctx(core128Key, version);
    filecrypt_ctx * fctx = createFileCtx(aes, mode, fileReadBufferSize);
    if (mode == CBC) {
        addFileCtxIV(fctx, iv, AES_STATE_SIZE);
    }

    encryptFile(fctx, fptrReadPlain, fptrWriteCipher);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Encrypt time: %fs\n", endTime - startTime);

        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    decryptFile(fctx, fptrWriteCipher, fptrWritePlain);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Decrypt time: %fs\n", endTime - startTime);
    #endif

    fclose(fptrReadPlain);
    fclose(fptrWritePlain);
    fclose(fptrWriteCipher);
    freeAESctx(aes);
    freeFileCtx(fctx);

    fptrWritePlain = fopen(fileNameDecrypt, "rb");
    fptrWriteCipher = fopen(fileNameEncrypt, "rb");
    FILE * fptrPlainSample = fopen(plainPDFSample, "rb");
    FILE * fptrCipherSample = fopen(cipherPDFSampleArray[mode], "rb");

    uint8_t result = 0;
    result += compareFiles(fptrWritePlain, fptrPlainSample);
    result += compareFiles(fptrWriteCipher, fptrCipherSample);

    fclose(fptrWriteCipher);
    fclose(fptrWritePlain);
    fclose(fptrPlainSample);
    fclose(fptrCipherSample);
    return result;
}

void * runThreadEncryptDecrypt(void * pargs) {
    struct args_struct * args = (struct args_struct*)pargs;

    #if BENCHMARK == 1
        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    encryptFile(args->fctx, args->readFile, args->writeFileEncrypted);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Thread  %ld  Encrypt time: %fs\n", args->threadNumber, endTime - startTime);

        startTime = (float)clock()/CLOCKS_PER_SEC;
    #endif

    decryptFile(args->fctx, args->writeFileEncrypted, args->writeFileDecrypted);

    #if BENCHMARK == 1
        endTime = (float)clock()/CLOCKS_PER_SEC;
        printf("Thread  %ld  Decrypt time: %fs\n", args->threadNumber, endTime - startTime);
    #endif

    freeAESctx(args->fctx->cipherCtx);
    freeFileCtx(args->fctx);
    fclose(args->writeFileEncrypted);
    fclose(args->writeFileDecrypted);
    fclose(args->readFile);
    free(pargs);
    return NULL;
}

filecrypt_ctx * generateTestingFctx(uint8_t mode, uint16_t version, uint8_t fileType, size_t appendValue, const byte * iv, size_t fileReadBufferSize) {
    cipher_ctx * aes = createAESctx(core128Key, version);
    filecrypt_ctx * fctx = createFileCtx(aes, mode, fileReadBufferSize);

    if (mode == CBC) {
        addFileCtxIV(fctx, iv, AES_STATE_SIZE);
    }
    return fctx;
}

FILE * generateWriteFilePtr(uint8_t mode, uint16_t version, uint8_t isEncrypt, uint8_t fileType, size_t fileNumber) {
    char * fileNameWrite = fileNameMaker(mode, version, isEncrypt, fileType, fileNumber);
    fprintf(stderr, "Opened file %s for writing\n", fileNameWrite);
    FILE * fptrWrite;

    fptrWrite = fopen(fileNameWrite, "wb+");
    if (fptrWrite == NULL) fprintf(stderr, "Cannot open file to write %s\n", fileNameWrite);

    return fptrWrite;
}

struct args_struct * generateThreadArgs(filecrypt_ctx * fctx, FILE * fptrRead, FILE * fptrWriteEncrypted, FILE * fptrWriteDecrypted, size_t threadNumber) {
    struct args_struct * pargs = malloc(sizeof(struct args_struct));
    pargs->fctx = fctx;
    pargs->writeFileEncrypted = fptrWriteEncrypted;
    pargs->writeFileDecrypted = fptrWriteDecrypted;
    pargs->readFile = fptrRead;
    pargs->threadNumber = threadNumber;
    return pargs;
}

size_t fileEncryptDecryptCheck(uint8_t mode, uint16_t version, uint8_t fileType, size_t fileCount) {
    const char * cipherSampleFileName;
    cipherSampleFileName = cipherPDFSampleArray[ECB];
    FILE * fptrSampleCipher;
    fptrSampleCipher = fopen(cipherSampleFileName, "rb");
    if (fptrSampleCipher == NULL) {
        fprintf(stderr, "fileEncryptDecryptCheck: Unable to open cipher PDF sample file %s", cipherSampleFileName);
        return 1;
    }

    FILE * fptrSamplePlain = fopen(plainPDFSample, "rb");
    if (fptrSamplePlain == NULL) {
        fprintf(stderr, "fileEncryptDecryptCheck: Unable to open plain PDF sample file %s", plainPDFSample);
        return 1;
    }

    char * fileNameWritten;
    FILE * fptrWrittenPlain, * fptrWrittenCipher;
    size_t fullResult = 0, compareResult = 0;
    // Decrypted, currently all sample plaintext and ciphertext files are identical
    fprintf(stdout, "Comparing plaintext/decrypted files\n");
    for (size_t threadNumber = 0; threadNumber < fileCount; threadNumber++) {
        if (fileCount > 0) fileNameWritten = fileNameMaker(mode, version, DECRYPT, fileType, threadNumber);
        fprintf(stdout, "Checking: %s ", fileNameWritten);
        fptrWrittenPlain = fopen(fileNameWritten, "rb");

        compareResult = compareFiles(fptrWrittenPlain, fptrSamplePlain);
        fullResult += printFailStatus(compareResult);

        fseek(fptrSamplePlain, 0, SEEK_SET);
        fclose(fptrWrittenPlain);
    }
    fclose(fptrSamplePlain);

    // Encrypted
    fprintf(stdout, "Comparing ciphertext/encrypted files\n");
    for (size_t threadNumber = 0; threadNumber < fileCount; threadNumber++) {
        if (fileCount > 0) fileNameWritten = fileNameMaker(mode, version, ENCRYPT, fileType, threadNumber);
        fprintf(stdout, "Checking: %s ", fileNameWritten);
        fptrWrittenCipher = fopen(fileNameWritten, "rb");

        compareResult = compareFiles(fptrWrittenCipher, fptrSampleCipher);
        fullResult += printFailStatus(compareResult);

        fseek(fptrSampleCipher, 0, SEEK_SET);
        fclose(fptrWrittenCipher);
    }
    fclose(fptrSampleCipher);
    return fullResult;
}

size_t testFileEncryptDecryptThreaded(uint8_t mode, uint16_t version, uint8_t fileType, size_t fileReadBufferSize) {
    if (mode == ECB) {
        printf("THREADED AES-128 ECB ENCRYPT PDF TEST...\n");
    } else if (mode == CBC) {
        printf("THREADED AES-128 CBC ENCRYPT PDF TEST...\n");
    }

    uint8_t result = 0;
    pthread_t threads[THREAD_COUNT];
    int threadIDs[THREAD_COUNT];
    for (size_t threadNumber = 0; threadNumber < THREAD_COUNT; threadNumber++) {
        fprintf(stdout, "Preparing for thread #%ld...\n", threadNumber);

        FILE * fptrWriteEncrypted = generateWriteFilePtr(mode, version, ENCRYPT, fileType, threadNumber);
        FILE * fptrWriteDecrypted = generateWriteFilePtr(mode, version, DECRYPT, fileType, threadNumber);

        FILE * fptrRead = fopen(plainPDFSamplesArray[threadNumber], "rb");
        if (fptrRead == NULL) {
            fprintf(stderr, "threadNumber = %ld: Sample file %s does not exist\n", threadNumber, plainPDFSamplesArray[threadNumber]);
            result++;
            continue;
        }

        filecrypt_ctx * fctx = generateTestingFctx(mode, version, fileType, threadNumber, iv, fileReadBufferSize);
        struct args_struct * pargs = generateThreadArgs(fctx, fptrRead, fptrWriteEncrypted, fptrWriteDecrypted, threadNumber);

        fprintf(stdout, "Starting thread #%ld with ID ", threadNumber);

        threadIDs[threadNumber] = pthread_create(&threads[threadNumber], NULL, &runThreadEncryptDecrypt, (void*)pargs); 

        fprintf(stdout, "%i...\n", threadIDs[threadNumber]);
    }
    fprintf(stdout, "\nWaiting for all threads to finish...\n");
    for (size_t threadNumber = 0; threadNumber < THREAD_COUNT; threadNumber++) {
        pthread_join(threads[threadNumber], NULL);
    }
    fprintf(stdout, "All threads are done!\n\n");
    fprintf(stdout, "Comparing written files...\n");

    if (fileEncryptDecryptCheck(mode, version, fileType, THREAD_COUNT) != 0) {
        result++;
    }
    return result;
}

void runTest(size_t (*testFuncPtr)(uint8_t, uint16_t, uint8_t, size_t), uint8_t mode, uint16_t version, uint8_t fileType, size_t fileReadBufferSize) {
    size_t testResult = testFuncPtr(mode, version, fileType, fileReadBufferSize);
    printFailStatus(testResult);
    fprintf(stdout, "\n");
}

int main(int argc, char ** argv) {
    if (THREAD_COUNT > MAX_THREAD_COUNT || THREAD_COUNT < 1) {
        fprintf(stderr, "THREAD_COUNT must be greater than or equal to 1 AND lower than or equal to MAX_THREAD_COUNT\n");
        exit(1);
    }

    //runTest(&testSingleFileEncryptDecrypt, ECB, 128, PDF, 512);
    //runTest(&testSingleFileEncryptDecrypt, CBC, 128, PDF, 512);
    runTest(&testFileEncryptDecryptThreaded, ECB, 128, PDF, 1);
    deleteWrittenFiles(ECB, 128, PDF, THREAD_COUNT);
    runTest(&testFileEncryptDecryptThreaded, ECB, 128, PDF, 512);
    deleteWrittenFiles(ECB, 128, PDF, THREAD_COUNT);
    runTest(&testFileEncryptDecryptThreaded, ECB, 128, PDF, 16384);
    deleteWrittenFiles(ECB, 128, PDF, THREAD_COUNT);

    return 0;
}
