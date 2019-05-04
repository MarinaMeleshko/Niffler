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
    struct iphdr *iph = (struct iphdr*)(buffer + 22);
    switch (iph->protocol) {
    case 6: {
        TCPPacket* packet = new TCPPacket(buffer, header, 22);
        return packet;
    }
    case 17: {
        UDPPacket* packet = new UDPPacket(buffer, header, 22);
        return packet;
    }
    default: {
        BasePacket* packet = new BasePacket(buffer);
        return packet;
    }
    }
}

BasePacket *processIP(const u_char *buffer, const pcap_pkthdr *header){
    struct iphdr *iph = (struct iphdr*)(buffer + 14);
    BasePacket* packet;
    switch (iph->protocol) {
    case 6: {
        packet = new TCPPacket(buffer, header, 14);
        return packet;
    }
    case 17: {
        packet = new UDPPacket(buffer, header, 14);
        return packet;
    }
    default: {
        packet = new BasePacket(buffer);
        return packet;
    }
    }
}

void Sniffer::processPacket(u_char *args, const pcap_pkthdr *header, const u_char *buffer){
    (void)args;
    (void)header;

    struct ethhdr *ethh = (struct ethhdr*)(buffer);

    switch (ethh->h_proto) {
    case PPPOE_SESSION_PROTOCOL_CODE:
        emit PacketProcessed(processPPPoE(buffer, header));
        break;
    case IP_PROTOCOL_CODE:
        emit PacketProcessed(processIP(buffer, header));
        break;
    case ARP_PROTOCOL_CODE:
        emit PacketProcessed(new ARPPacket(buffer, header));
        break;
    default:
        break;
    }
}

QString Sniffer::GetPacketParsedData(int id){
    QList<BasePacket>::iterator i;
    for (i = packetList->begin(); i != packetList->end(); ++i){
        if ((*i).id == id){
            return (*i).parsedData;
        }
    }
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
