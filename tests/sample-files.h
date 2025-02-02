#ifndef _SAMPLE_FILES_H
#define _SAMPLE_FILES_H

#include "test-utils.h"

#define PDF 0x1
#define TXT 0x2

const char * plainPDFSamplesArray[MAX_THREAD_COUNT] = {
    "./samples/file.pdf", "./samples/file-2.pdf", "./samples/file-3.pdf", "./samples/file-4.pdf",
    "./samples/file-5.pdf", "./samples/file-6.pdf", "./samples/file-7.pdf", "./samples/file-8.pdf"
};

const char * plainPDFSample = "./samples/file.pdf";
const char * cipherPDFSampleArray[2] = {"./samples/ecb-128-encrypted.pdf.dat", "./samples/cbc-128-encrypted.pdf.dat"};

const char * cipherTXTSample = "./samples/cfile.md";
const char * plainTXTSample = "./samples/file.md";
//const char * cipherIMGSample = "./samples/c-lorem-picsum-200.jpg";
//const char * plainIMGSample = "./samples/lorem-picsum-200.jpg";

#endif // _SAMPLE_FILES_H
