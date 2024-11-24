#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QTextEdit>

extern "C" {
    #include "../include/definitions.h"
    #include "../include/filecrypt.h"
    #include "../include/aes.h"
    #include "../include/utils.h"
};

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onEncryptButtonClicked();
    void onDecryptButtonClicked();
    void onSelectFileButtonClicked();
    void initializeContexts();
    void freeContexts();
    unsigned char * getInputIV();
    unsigned char * getInputKey();
private:
    Ui::MainWindow *ui;
    void consoleLog(const QString &message);
    cipher_ctx *aes = nullptr;      // AES context
    filecrypt_ctx *fctx = nullptr;  // File ECB/CBC context
};

#endif // MAINWINDOW_H
