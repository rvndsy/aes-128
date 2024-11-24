#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>

extern "C" {
    #include "../include/aes.h"
    #include "../include/utils.h"
};

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::onDecryptButtonClicked);
    connect(ui->fileSelectorButton, &QPushButton::clicked, this, &MainWindow::onSelectFileButtonClicked);
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::onEncryptButtonClicked);
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

byte * MainWindow::getInputKey() {
    std::string keyStr = ui->keyInputField->toPlainText().toStdString();
    if (keyStr.length() != 32 || !std::all_of(keyStr.begin(), keyStr.end(), ::isxdigit)) {
        consoleLog("Error: Key must be 32 hexadecimal digits long.");
        return nullptr;
    }
    byte * key = new byte[16];
    for (int i = 0; i < 16; i++) {
        char tmp[3];
        tmp[0] = keyStr[i * 2];
        tmp[1] = keyStr[i * 2 + 1];
        key[i] = strToHexByte(tmp);
    }
    return key;
}

byte * MainWindow::getInputIV() {
    std::string ivStr = ui->ivInputField->toPlainText().toStdString();
    if (ivStr.length() != 32 || !std::all_of(ivStr.begin(), ivStr.end(), ::isxdigit)) {
        consoleLog("Error: Initialization vector (iV) must be 32 hexadecimal digits long.");
        return nullptr;
    }
    byte * iv = new byte[16];
    for (int i = 0; i < 16; i++) {
        char tmp[3];
        tmp[0] = ivStr[i * 2];
        tmp[1] = ivStr[i * 2 + 1];
        iv[i] = strToHexByte(tmp);
    }
    return iv;
}

bool MainWindow::initializeContexts() {
    if (aes != nullptr) {
        byte * key = getInputKey();
        if (key == nullptr) {
            consoleLog("initializeContexts: Key input failed.");
            return false;
        }
        updateAESctx(aes, key, 128);
    }
    if (fctx != nullptr) {
        if (ui->operationModeComboBox->currentText().contains("ECB")) {
            updateFileCtx(fctx, aes, ECB, 4096);
        } else if (ui->operationModeComboBox->currentText().contains("CBC")) {
            byte * iv = getInputIV();
            if (iv == nullptr) {
                consoleLog("initializeContexts: IV input failed.");
                return false;
            }
            updateFileCtx(fctx, aes, CBC, 4096);
            addFileCtxIV(fctx, iv, 16);
        } else {
            consoleLog("initializeContexts: AES or file context is NULL after initialization.");
        }
    }
    if (aes == nullptr) {
        byte * key = getInputKey();
        if (key == nullptr) {
            consoleLog("initializeContexts: Key input failed.");
            return false;
        }
        aes = createAESctx(key, 128);
        if (aes == nullptr) {
            consoleLog("initializeContexts: Failed to create AES context.");
            return false;
        }
    }
    if (fctx == nullptr) {
        QString opMode = ui->operationModeComboBox->currentText();
        if (opMode.contains("ECB")) {
            fctx = createFileCtx(aes, ECB, 4096);
            if (fctx == nullptr) {
                consoleLog("initializeContexts: Failed to create ECB file context.");
                return false;
            }
        } else if (opMode.contains("CBC")) {
            byte * iv = getInputIV();
            if (iv == nullptr) {
                consoleLog("initializeContexts: IV input failed.");
                return false;
            }
            fctx = createFileCtx(aes, CBC, 4096);
            if (fctx == nullptr) {
                consoleLog("initializeContexts: Failed to create CBC file context.");
                return false;
            }
            addFileCtxIV(fctx, iv, 16);
        }
    }
    return true;
}

void MainWindow::freeContexts() {
    if (aes != nullptr) {
        freeAESctx(aes);
        aes = nullptr;
    }
    if (fctx != nullptr) {
        freeFileCtx(fctx);
        fctx = nullptr;
    }
}

void MainWindow::onEncryptButtonClicked() {
    if (!initializeContexts()) return;
    if (fctx == nullptr || aes == nullptr) {
        consoleLog("onEncryptButtonClicked: Context allocation failed");
        return;
    }

    QFileInfo readFile(ui->fileSelectTextLabel->text());
    QString filePath = readFile.path() + QDir::separator();
    QString writeFileName = ui->writeFileNameInput->toPlainText() + ".dat";
    QString encryptedFilePath = filePath + writeFileName;

    FILE *freadFile = fopen(readFile.absoluteFilePath().toStdString().c_str(), "rb");
    if (freadFile == NULL) {
        consoleLog("Error: Failed to open read file for encryption.");
        return;
    }

    FILE *fwriteFile = fopen(encryptedFilePath.toStdString().c_str(), "wb+");
    if (fwriteFile == NULL) {
        consoleLog("Error: Failed to open file for writing encrypted data.");
        fclose(freadFile);
        return;
    }

    encryptFile(fctx, freadFile, fwriteFile);

    fclose(freadFile);
    fclose(fwriteFile);
    consoleLog("Encrypted: " +encryptedFilePath);
}

void MainWindow::onDecryptButtonClicked() {
    if (!initializeContexts()) return;
    if (fctx == nullptr || aes == nullptr) {
        consoleLog("onDecryptButtonClicked: Context allocation failed");
        return;
    }

    QFileInfo readFile(ui->fileSelectTextLabel->text());
    QString filePath = readFile.path() + QDir::separator();
    QString writeFileName = ui->writeFileNameInput->toPlainText();
    QString decryptedFilePath = filePath + writeFileName;

    FILE *freadFile = fopen(readFile.absoluteFilePath().toStdString().c_str(), "rb");
    if (freadFile == NULL) {
        consoleLog("Error: Failed to open read file for decryption.");
        return;
    }

    FILE *fwriteFile = fopen(decryptedFilePath.toStdString().c_str(), "wb+");
    if (fwriteFile == NULL) {
        consoleLog("Error: Failed to open file for writing decrypted file.");
        fclose(freadFile);
        return;
    }

    decryptFile(fctx, freadFile, fwriteFile);

    fclose(freadFile);
    fclose(fwriteFile);
    consoleLog("Decrypted: " +decryptedFilePath);
}

MainWindow::~MainWindow() {
    freeContexts();
    delete ui;
}
