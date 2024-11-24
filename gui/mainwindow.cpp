#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>

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
        return NULL;
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
        return NULL;
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

void MainWindow::initializeContexts() {
    if (aes != nullptr) {
        std::unique_ptr<byte[]> key(getInputKey());
        if (key == nullptr) {
            consoleLog("initializeContexts: Key input failed.");
            return;
        }
        updateAESctx(aes, key.get(), 128);
    }
    if (fctx != nullptr) {
        if (ui->operationModeComboBox->currentText().contains("ECB")) {
            updateFileCtx(fctx, aes, ECB, 512);
        } else if (ui->operationModeComboBox->currentText().contains("CBC")) {
            std::unique_ptr<byte[]> iv(getInputIV());
            if (iv == nullptr) {
                consoleLog("initializeContexts: IV input failed.");
                return;
            }
            updateFileCtx(fctx, aes, CBC, 512);
            addFileCtxIV(fctx, iv.get(), 16);
        } else {
            consoleLog("initializeContexts: AES or file context is NULL after initialization.");
        }
    }
    if (aes == nullptr) {
        std::unique_ptr<byte[]> key(getInputKey());
        if (key == nullptr) {
            consoleLog("initializeContexts: Key input failed.");
            return;
        }
        aes = createAESctx(key.get(), 128);
        if (aes == nullptr) {
            consoleLog("initializeContexts: Failed to create AES context.");
            return;
        }
    }
    if (fctx == nullptr) {
        QString opMode = ui->operationModeComboBox->currentText();
        if (opMode.contains("ECB")) {
            fctx = createFileCtx(aes, ECB, 512);
            if (fctx == nullptr) {
                consoleLog("initializeContexts: Failed to create ECB file context.");
                return;
            }
        } else if (opMode.contains("CBC")) {
            std::unique_ptr<byte[]> iv(getInputIV());
            if (iv == nullptr) {
                consoleLog("initializeContexts: IV input failed.");
                return;
            }
            fctx = createFileCtx(aes, CBC, 512);
            if (fctx == nullptr) {
                consoleLog("initializeContexts: Failed to create CBC file context.");
                return;
            }
            addFileCtxIV(fctx, iv.get(), 16);
        }
    }
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
    initializeContexts();
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
    consoleLog(encryptedFilePath + " encrypted");
}

void MainWindow::onDecryptButtonClicked() {
    initializeContexts();
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
    consoleLog(decryptedFilePath + " decrypted");
}

MainWindow::~MainWindow() {
    freeContexts();
    delete ui;
}
