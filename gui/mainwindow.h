#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QTextEdit>

QT_BEGIN_NAMESPACE
namespace Ui { class operationModeLabel; }
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

private:
    Ui::operationModeLabel *ui;
    void consoleLog(const QString &message);
};

#endif // MAINWINDOW_H
