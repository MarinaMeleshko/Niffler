#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QTableWidgetItem>

#include<stdio.h>

#include "niffler-model/sniffer.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow{
    Q_OBJECT

    public:
        explicit MainWindow(QWidget *parent = nullptr);
        ~MainWindow();

    private slots:
        void PullPackets(QList<BasePacket>*);
        void AddPacket(BasePacket*);

        void on_radioARP_clicked();

        void on_radioIp_clicked();

        void on_radioAll_clicked();

        void on_packetsTable_itemClicked(QTableWidgetItem *item);

signals:
        void PacketsRequested();

    private:
        Ui::MainWindow *ui;
        Sniffer *sniffer;

        void InitSniffer();
        void InitPacketsTable();
};

#endif // MAINWINDOW_H
