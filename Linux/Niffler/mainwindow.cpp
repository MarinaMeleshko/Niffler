#include "mainwindow.h"
#include "ui_mainwindow.h"

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

}
