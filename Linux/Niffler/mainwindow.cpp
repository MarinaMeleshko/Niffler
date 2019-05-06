#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "niffler-model/sniffer.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow){
    InitSniffer();
    ui -> setupUi(this);
    InitPacketsTable();
}

MainWindow::~MainWindow(){
    delete sniffer;
    delete ui;
}

void MainWindow::PullPackets(QList<BasePacket> *packets){
    ui -> packetsTable -> clear();
    ui -> packetsTable -> setRowCount(0);

    int rowCounter = 0;
    QList<BasePacket>::iterator i;
    for (i = packets -> begin(); i!= packets -> end(); ++i, ++rowCounter){
        char num_buffer [50];
        sprintf(num_buffer, "%d", i -> id);
        QString str = QString::fromUtf8(num_buffer);

        ui -> packetsTable -> insertRow(rowCounter);
        ui -> packetsTable -> setItem(rowCounter, 0, new QTableWidgetItem(str));
        ui -> packetsTable -> setItem(rowCounter, 1, new QTableWidgetItem(i -> source));
        ui -> packetsTable -> setItem(rowCounter, 2, new QTableWidgetItem(i -> destination));
        ui -> packetsTable -> setItem(rowCounter, 3, new QTableWidgetItem(i -> protocol));
    }
}

void MainWindow::AddPacket(BasePacket *packet){
    int count = ui->packetsTable->rowCount();

    char num_buffer [50];
    sprintf(num_buffer, "%d", packet -> id);
    QString str = QString::fromUtf8(num_buffer);

    ui -> packetsTable -> insertRow(count);
    ui -> packetsTable -> setItem(count, 0, new QTableWidgetItem(str));
    ui -> packetsTable -> setItem(count, 1, new QTableWidgetItem(packet->source));
    ui -> packetsTable -> setItem(count, 2, new QTableWidgetItem(packet->destination));
    ui -> packetsTable -> setItem(count, 3, new QTableWidgetItem(packet->protocol));
}

void MainWindow::on_radioARP_clicked(){

}

void MainWindow::on_radioIp_clicked(){

}

void MainWindow::on_radioAll_clicked(){
}

void MainWindow::InitPacketsTable(){
    ui -> packetsTable -> setRowCount(0);
    ui -> packetsTable -> setColumnCount(4);

    QStringList tableHeader;
    tableHeader << "#" << "Source" << "Destination" << "Protocol";
    ui -> packetsTable -> setHorizontalHeaderLabels(tableHeader);
    ui -> packetsTable -> verticalHeader() -> setVisible(false);

    ui -> packetsTable -> setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui -> packetsTable -> setSelectionBehavior(QAbstractItemView::SelectRows);
    ui -> packetsTable -> setSelectionMode(QAbstractItemView::SingleSelection);
    ui -> packetsTable -> setShowGrid(false);
}

void MainWindow::InitSniffer(){
    sniffer = new Sniffer();
    sniffer -> moveToThread(sniffer);
    sniffer -> start();

    connect(sniffer, SIGNAL(PacketPushed(QList<BasePacket>*)), this, SLOT(PullPackets(QList<BasePacket>*)));
    connect(sniffer, SIGNAL(PacketRecieved(BasePacket*)), this, SLOT(AddPacket(BasePacket*)));

    connect(this, SIGNAL(destroyed()), sniffer, SLOT(quit()));
}
