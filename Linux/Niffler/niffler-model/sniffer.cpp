#include "sniffer.h"


#include <QDebug>

Sniffer::Sniffer(QThread *parent) :QThread(parent){
    packetList = new QList<BasePacket>();
    connect(this, SIGNAL(PacketProcessed(BasePacket*)), this, SLOT(savePacket(BasePacket*)));
    filterType = PacketFilter::All;
}

Sniffer::~Sniffer(){
    delete packetList;
    this->terminate();
    this->wait();
}

void Sniffer::GetPackets(PacketFilter type){
    filterType = type;
    QList<BasePacket> *temp = new QList<BasePacket>();
    QList<BasePacket>::iterator i;
    switch(type){
    case PacketFilter::All:
        emit PacketPushed(packetList);
        break;
    case PacketFilter::IP:
        for (i = packetList->begin(); i != packetList->end(); ++i){
            if (i->getTypeId() == 2 || i->getTypeId() == 3){
                temp->append(*i);
            }
        }
        emit PacketPushed(temp);
        break;
    case PacketFilter::ARP:
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
    case PacketFilter::All:
        emit PacketRecieved(packet);
        break;
    case PacketFilter::IP:
        if (packet->getTypeId() == 2 || packet->getTypeId() == 3){
            emit PacketRecieved(packet);
        }
        break;
    case PacketFilter::ARP:
        if (packet->getTypeId() == 4){
            emit PacketRecieved(packet);
        }
        break;
    }
}

BasePacket *processPPPoE(const u_char *buffer, const pcap_pkthdr *header){
    struct iphdr *iph = (struct iphdr*)(buffer + 22);
    BasePacket* packet;
    switch (iph->protocol) {
        case 6:
            packet = new TCPPacket(buffer, header, 22);
            break;
        case 17:
            packet = new UDPPacket(buffer, header, 22);
            break;
        default:
            packet = new BasePacket(buffer);
    }
    return packet;
}

BasePacket *processIP(const u_char *buffer, const pcap_pkthdr *header){
    struct iphdr *iph = (struct iphdr*)(buffer + 14);
    BasePacket* packet;
    switch (iph->protocol) {
        case 6:
            packet = new TCPPacket(buffer, header, 14);
            break;
        case 17:
            packet = new UDPPacket(buffer, header, 14);
            break;
        default:
            packet = new BasePacket(buffer);
    }
    return packet;
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
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr hdr;

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000 , errbuf);
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
