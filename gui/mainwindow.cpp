#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>

extern "C" {
    #include "../include/filecrypt.h"
    #include "../include/aes.h"
    #include "../include/utils.h"
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    ui->setupUi(this);

    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::onEncryptButtonClicked);
    connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::onDecryptButtonClicked);
    connect(ui->fileSelectorButton, &QPushButton::clicked, this, &MainWindow::onSelectFileButtonClicked);
}

void MainWindow::consoleLog(const QString &msg) {
    ui->statusMessageLabel->append(msg);
}

void MainWindow::onSelectFileButtonClicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select a file", "", "All Files (*)");
    if (!filePath.isEmpty()) {
        ui->fileSelectTextLabel->setText(filePath);
    }
}

void MainWindow::onEncryptButtonClicked() {
    QFileInfo readFile (ui->fileSelectTextLabel->text());
    QString filePath = readFile.path() + QDir::separator(); //platform independant slashes from QDir
    QString writeFileName = ui->writeFileNameInput->toPlainText() + ".dat";
    QString encryptedFilePath = filePath + writeFileName;

    byte b[16];
    FILE *freadFile = fopen(readFile.absoluteFilePath().toStdString().c_str(), "rb");
    // while (fread(b, 1, 16, freadFile)) {
    //     printByteArrayPretty(b, 16);
    // }
    if (freadFile == NULL) {
        consoleLog("Failed to open file for encryption.");
        return;
    }

    FILE *fwriteFile = fopen(encryptedFilePath.toStdString().c_str(), "wb+");
    if (fwriteFile == NULL) {
        consoleLog("Failed to open file for writing encrypted data.");
        fclose(freadFile);
        return;
    }

    std::string keyStr = ui->keyInputField->toPlainText().toStdString();
    if (ui->keyInputField->toPlainText().isEmpty()) {
        consoleLog("Please provide a key!");
        return;
    }
    if (!std::all_of(keyStr.begin(), keyStr.end(), ::isxdigit)) {
        consoleLog("Key must be contain only hexadecimal characters! (0123456789abcdef)");
        return;
    }
    if (keyStr.length() != 32) {
        consoleLog("Key must be 32 hexadecimal digits long");
        return;
    }

    byte key[16];
    for (int i = 0; i < 16; i++) {
        char tmp[2];
        tmp[0] = keyStr[i*2];
        tmp[1] = keyStr[i*2+1];
        key[i] = strToHexByte(tmp);
    }

    printByteArrayPretty(key, 16);
    printf("\nKey is supposed to be: %s\n", (char*)ui->keyInputField->toPlainText().toStdString().c_str());
    consoleLog(readFile.absoluteFilePath().toStdString().c_str());
    consoleLog("Write:" +encryptedFilePath);
    cipher_ctx * aes = createAESctx(key, 128);
    filecrypt_ctx * fctx = createFileCtx(aes, ECB, 4096);

    if (ui->operationModeComboBox->currentText().contains("CBC")) {
        std::string ivStr = ui->ivInputField->toPlainText().toStdString();
        if (ui->ivInputField->toPlainText().isEmpty()) {
            consoleLog("Please provide an initialization vector!");
            freeFileCtx(fctx);
            freeAESctx(aes);
            return;
        }
        if (!std::all_of(ivStr.begin(), ivStr.end(), ::isxdigit)) {
            consoleLog("Initialization vector must be contain only hexadecimal characters! (0123456789abcdef)");
            return;
        }
        if (ivStr.length() != 32) {
            consoleLog("Initialization vector must be 32 hexadecimal digits long");
            freeFileCtx(fctx);
            freeAESctx(aes);
            return;
        }
        byte iv[16];
        for (int i = 0; i < 16; i++) {
            char tmp[2];
            tmp[0] = ui->keyInputField->toPlainText().toStdString().c_str()[i*2];
            tmp[1] = ui->keyInputField->toPlainText().toStdString().c_str()[i*2+1];
            iv[i] = strToHexByte(tmp);
        }
        fctx->operationMode = CBC;
        addFileCtxIV(fctx, iv, 16);
    }

    encryptFile(fctx, freadFile, fwriteFile);

    fclose(freadFile);
    fclose(fwriteFile);
    freeFileCtx(fctx);
    freeAESctx(aes);
    consoleLog(encryptedFilePath +" encrypted");
}

void MainWindow::onDecryptButtonClicked() {
    QFileInfo readFile (ui->fileSelectTextLabel->text());
    QString filePath = readFile.path() + QDir::separator(); //platform independant slashes from QDir
    QString writeFileName = ui->writeFileNameInput->toPlainText();
    QString encryptedFilePath = filePath + writeFileName;

    byte b[16];
    FILE *freadFile = fopen(readFile.absoluteFilePath().toStdString().c_str(), "rb");
    // while (fread(b, 1, 16, freadFile)) {
    //     printByteArrayPretty(b, 16);
    // }
    if (freadFile == NULL) {
        consoleLog("Failed to open file for encryption.");
        return;
    }

    FILE *fwriteFile = fopen(encryptedFilePath.toStdString().c_str(), "wb+");
    if (fwriteFile == NULL) {
        consoleLog("Failed to open file for writing encrypted data.");
        fclose(freadFile);
        return;
    }

    std::string keyStr = ui->keyInputField->toPlainText().toStdString();
    if (ui->keyInputField->toPlainText().isEmpty()) {
        consoleLog("Please provide a key!");
        return;
    }
    if (!std::all_of(keyStr.begin(), keyStr.end(), ::isxdigit)) {
        consoleLog("Key must be contain only hexadecimal characters! (0123456789abcdef)");
        return;
    }
    if (keyStr.length() != 32) {
        consoleLog("Key must be 32 hexadecimal digits long");
        return;
    }

    byte key[16];
    for (int i = 0; i < 16; i++) {
        char tmp[2];
        tmp[0] = ui->keyInputField->toPlainText().toStdString().c_str()[i*2];
        tmp[1] = ui->keyInputField->toPlainText().toStdString().c_str()[i*2+1];
        key[i] = strToHexByte(tmp);
    }

    printByteArrayPretty(key, 16);
    printf("\nKey is supposed to be: %s\n", (char*)ui->keyInputField->toPlainText().toStdString().c_str());
    consoleLog(readFile.absoluteFilePath().toStdString().c_str());
    consoleLog("Write:" +encryptedFilePath);
    cipher_ctx * aes = createAESctx(key, 128);
    filecrypt_ctx * fctx = createFileCtx(aes, ECB, 4096);

    if (ui->operationModeComboBox->currentText().contains("CBC")) {
        std::string ivStr = ui->ivInputField->toPlainText().toStdString();
        if (ui->ivInputField->toPlainText().isEmpty()) {
            consoleLog("Please provide an initialization vector!");
            freeFileCtx(fctx);
            freeAESctx(aes);
            return;
        }
        if (!std::all_of(ivStr.begin(), ivStr.end(), ::isxdigit)) {
            consoleLog("Initialization vector must be contain only hexadecimal characters! (0123456789abcdef)");
            return;
        }
        if (ivStr.length() != 32) {
            consoleLog("Initialization vector must be 32 hexadecimal digits long");
            freeFileCtx(fctx);
            freeAESctx(aes);
            return;
        }
        byte iv[16];
        for (int i = 0; i < 16; i++) {
            char tmp[2];
            tmp[0] = ui->keyInputField->toPlainText().toStdString().c_str()[i*2];
            tmp[1] = ui->keyInputField->toPlainText().toStdString().c_str()[i*2+1];
            iv[i] = strToHexByte(tmp);
        }
        fctx->operationMode = CBC;
        addFileCtxIV(fctx, iv, 16);
    }

    decryptFile(fctx, freadFile, fwriteFile);

    fclose(freadFile);
    fclose(fwriteFile);
    freeFileCtx(fctx);
    freeAESctx(aes);
    consoleLog(encryptedFilePath +" decrypted");
}

MainWindow::~MainWindow() {
    delete ui;
}
