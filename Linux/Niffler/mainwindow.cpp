#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "niffler-model/sniffer.h"
#include "packetfilter.h"

#include <Qt>

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

    QList<BasePacket>::iterator packet;
    for (packet = packets -> begin(); packet!= packets -> end(); ++packet){
        AddPacket(&(*packet));
    }
}

void MainWindow::AddPacket(BasePacket *packet){
    int count = ui->packetsTable->rowCount();

    char num_buffer [50];
    sprintf(num_buffer, "%d", packet -> id);
    QString str = QString::fromUtf8(num_buffer);

    ui -> packetsTable -> insertRow(count);

    CreateTableWidgetItem(str, count, 3);
    CreateTableWidgetItem(packet -> source, count, 2);
    CreateTableWidgetItem(packet -> destination, count, 1);
    CreateTableWidgetItem(packet -> protocol, count, 0);
}

void MainWindow::CreateTableWidgetItem(QString value, int row, int column){
    QTableWidgetItem* item = new QTableWidgetItem(value);
    item -> setTextAlignment(Qt::AlignCenter);
    ui -> packetsTable -> setItem(row, column, item);
}

void MainWindow::on_radioARP_clicked(){
    sniffer -> GetPackets(PacketFilter::ARP);
    InitHeaderView();
}

void MainWindow::on_radioIp_clicked(){
    sniffer -> GetPackets(PacketFilter::IP);
    InitHeaderView();
}

void MainWindow::on_radioAll_clicked(){
    sniffer -> GetPackets(PacketFilter::All);
    InitHeaderView();
}

void MainWindow::InitHeaderView(){
    QStringList tableHeader;
    tableHeader << "Protocol" << "Destination" << "Source" << "#";
    ui -> packetsTable -> setHorizontalHeaderLabels(tableHeader);
    ui -> packetsTable -> verticalHeader() -> setVisible(false);
}

void MainWindow::InitPacketsTable(){
    ui -> packetsTable -> setRowCount(0);
    ui -> packetsTable -> setColumnCount(4);

    InitHeaderView();

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

void MainWindow::on_packetsTable_itemClicked(QTableWidgetItem *item)
{
    QTableWidgetItem* packetItem = item -> tableWidget() -> item(item -> row(), 3);
    int packetId = packetItem -> text().toInt();
    QString str = sniffer -> GetPacketParsedData(packetId);

    ui -> packetInfo -> clear();
    ui -> packetInfo -> setText(str);
}
