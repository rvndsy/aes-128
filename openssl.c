
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <time.h>  // For benchmarking

#define AES_KEY_SIZE 16  // AES-128 uses a 16-byte key

// Function to handle AES encryption in ECB mode
void aes_encrypt_file(const char *input_file, const char *output_file, const unsigned char *key) {
    AES_KEY aes_key;
    unsigned char inbuf[AES_BLOCK_SIZE], outbuf[AES_BLOCK_SIZE];
    FILE *in, *out;
    size_t bytes_read;

    // Set encryption key
    if (AES_set_encrypt_key(key, AES_KEY_SIZE * 8, &aes_key) < 0) {
        fprintf(stderr, "Failed to set AES key\n");
        exit(1);
    }

    // Open input and output files
    in = fopen(input_file, "rb");
    if (!in) {
        perror("Error opening input file");
        exit(1);
    }

    out = fopen(output_file, "wb");
    if (!out) {
        perror("Error opening output file");
        exit(1);
    }

    // Encrypt data in 16-byte blocks
    while ((bytes_read = fread(inbuf, 1, AES_BLOCK_SIZE, in)) > 0) {
        // If the block is less than 16 bytes, pad it
        if (bytes_read < AES_BLOCK_SIZE) {
            memset(inbuf + bytes_read, AES_BLOCK_SIZE - bytes_read, AES_BLOCK_SIZE - bytes_read);
        }

        // Perform AES encryption
        AES_ecb_encrypt(inbuf, outbuf, &aes_key, AES_ENCRYPT);

        // Write the encrypted block to the output file
        fwrite(outbuf, 1, AES_BLOCK_SIZE, out);
    }

    // Close files
    fclose(in);
    fclose(out);
}

int main() {
    const char *input_file = "file.pdf";   // Input file path
    const char *output_file = "file.pdf.enc"; // Output file path

    // 128-bit key for AES-128 (16 bytes)
    unsigned char key[AES_KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                                       0xab, 0xf7, 0x97, 0x75, 0x46, 0x34, 0x8c, 0x35};

    // Start benchmarking
    clock_t start_time = clock();

    aes_encrypt_file(input_file, output_file, key);

    // End benchmarking
    clock_t end_time = clock();

    // Calculate the time taken
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("File encrypted successfully!\n");
    printf("Encryption time: %.4f seconds\n", elapsed_time);

    return 0;
}

