// Implementation of AES-128. Based on NIST FIPS-197.
#include <stdint.h>
#include <stdio.h>

#define NK 4    //
#define NB 4
#define NR 10

typedef uint8_t byte;
typedef uint32_t word;

byte hexStrToHexNum(char * hexStr) {
    byte hex = 0x0;

    for (int i = 0; hexStr[i] != '\0'; i++) {
        if (hexStr[i] >= 'a' && hexStr[i] <= 'f') {
            hex |= hexStr[i] - 87;
        } else if (hexStr[i] >= 'A' && hexStr[i] <= 'F') {
            hex |= hexStr[i] - 55;
        } else if (hexStr[i] >= '0' && hexStr[i] <= '9') {
            hex |= hexStr[i] - '0';
        } else {
            printf("Bad hex string given!\n");
            return 0x0;
        }
        if (hexStr[i+1] != '\0') {
            hex <<= 4;
        }
    }

    return hex;
}

void println() {
    printf("\n");
}

void printArray(byte * arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%x", arr[i]);
    }
}

//void cipher(byte in[4*NB], byte out[4*NB], byte word[NB*(NR+1)]) {
//    AddRoundKey(in, w[0])
//}

void keyExpansion(byte * key, word * w, int nk) {
    byte tmp;

    for (int i = 0; i < nk; i++) {
    }
}

void ROTL4(int n, uint8_t * k4) { //circular rotate left for size of 4
    *k4 = (*k4 << n) | (*k4 >> (4 - n));
    *k4 = *k4 & 0xf;
}

void ROTR4(int n, uint8_t * k4) { //circular rotate right for size of 4
    *k4 = (*k4 >> n) | (*k4 << (4 - n));
    *k4 = *k4 & 0xf;
}

int main(int argc, char** argv)  {
    byte txt[16], key[16];
    int nk = NK;
    int nb = NB;
    int nr = NR;

    if (argc < 3 || argc > 3) {
        printf("aes: Too few arguments provided\n");
        return 0;
    } else if (argc > 3) {
        printf("aes: Too many arguments provided\n");
        return 0;
    }

    char tmp[2];
    for (int i = 0; i < 16; i++) {
        tmp[0] = argv[1][2*i-1], tmp[1] = argv[1][2*i];
        txt[i] = hexStrToHexNum(tmp);

        tmp[0] = argv[2][2*i-1], tmp[1] = argv[2][2*i];
        key[i] = hexStrToHexNum(tmp);
    }

    printf("Plaintext\n");
    printArray(key, 16);
    println();

    printf("Key\n");
    printArray(txt, 16);
    println();

    return 0;
}
