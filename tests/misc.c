#include "../include/filecrypt.h"
#include "../include/aes.h"
#include "../include/utils.h"

int main(int argc, char ** argv) {
    if (argc < 2) return 0;

    FILE * freadFile = fopen(argv[1], "rb");
    FILE * fwriteFile = fopen(argv[2], "wb+");

    byte key[16];
    byte iv[16];

    for (int i = 0; i < 16; i++) {
        char tmp[2];
        tmp[0] = argv[3][i*2];
        tmp[1] = argv[3][i*2+1];
        key[i] = strToHexByte(tmp);
    }

    for (int i = 0; i < 16; i++) {
        char tmp[2];
        tmp[0] = argv[4][i*2];
        tmp[1] = argv[4][i*2+1];
        iv[i] = strToHexByte(tmp);
    }

    printf("\nKey is supposed to be: %s\n", argv[3]);
    printByteArrayPretty(key, 16);
    printf("\nIV is supposed to be: %s\n", argv[4]);
    printByteArrayPretty(iv, 16);

    cipher_ctx * aes = createAESctx(key, 128);
    filecrypt_ctx * fctx = createFileCtx(aes, ECB, 4096);
    addFileCtxIV(fctx, iv, 16);

    //if (ui->operationModeComboBox->currentText().contains("CBC")) {
    //    if (ui->ivInputField->toPlainText().isEmpty()) {
    //        consoleLog("Please provide an initialization vector!");
    //        freeFileCtx(fctx);
    //        freeAESctx(aes);
    //        return;
    //    }
    //    if (ui->ivInputField->toPlainText().length() != 32) {
    //        consoleLog("Initialization vector must be 32 hexadecimal digits long");
    //        freeFileCtx(fctx);
    //        freeAESctx(aes);
    //        return;
    //    }
    //    byte iv = strToHexByte((char*)ui->ivInputField->toPlainText().toStdString().c_str());
    //    fctx->operationMode = CBC;
    //    addFileCtxIV(fctx, &iv, 16);
    //}

    encryptFile(fctx, freadFile, fwriteFile);

    fclose(freadFile);
    fclose(fwriteFile);
    freeFileCtx(fctx);
    freeAESctx(aes);

    return 0;
}
