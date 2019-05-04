#include "sniffer.h"

#include <QDebug>

Sniffer::Sniffer(QThread *parent) :QThread(parent){
    packetList = new QList<BasePacket>();
    connect(this, SIGNAL(PacketProcessed(BasePacket*)), this, SLOT(savePacket(BasePacket*)));
    filterType = 0;
}

Sniffer::~Sniffer(){
    delete packetList;
    this->terminate();
    this->wait();
}

void Sniffer::GetPackets(int type){
    filterType = type;
    QList<BasePacket> *temp = new QList<BasePacket>();
    QList<BasePacket>::iterator i;
    switch(type){
    case 0:
        emit PacketPushed(packetList);
        break;
    case 1:
        for (i = packetList->begin(); i != packetList->end(); ++i){
            if (i->getTypeId() == 2 || i->getTypeId() == 3){
                temp->append(*i);
            }
        }
        emit PacketPushed(temp);
        break;
    case 2:
        for (i = packetList->begin(); i != packetList->end(); ++i){
            if (i->getTypeId() == 4){
                temp->append(*i);
            }
        }
        emit PacketPushed(temp);
        break;
    }
}

void Sniffer::savePacket(BasePacket *packet){
    packet->id = packetList->count() + 1;
    packetList->append(*packet);
    switch(filterType){
    case 0:
        emit PacketRecieved(packet);
        break;
    case 1:
        if (packet->getTypeId() == 2 || packet->getTypeId() == 3){
            emit PacketRecieved(packet);
        }
        break;
    case 2:
        if (packet->getTypeId() == 4){
            emit PacketRecieved(packet);
        }
        break;
    }
}

BasePacket *processPPPoE(const u_char *buffer, const pcap_pkthdr *header){
}

BasePacket *processIP(const u_char *buffer, const pcap_pkthdr *header){
}

void Sniffer::processPacket(u_char *args, const pcap_pkthdr *header, const u_char *buffer){
}

QString Sniffer::GetPacketParsedData(int id){
}

void Sniffer::run(){
    char errbuf[2000];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr hdr;

    handle = pcap_open_live("eth0", 65536 , 1 , 0 , errbuf);
    if (handle == NULL){
        qDebug() << "Couldn't open device";
        return;
    }

    while (1) {
        packet = pcap_next(handle, &hdr);
        if(packet != NULL){
            processPacket(NULL, &hdr, packet);
        }
    }
}
