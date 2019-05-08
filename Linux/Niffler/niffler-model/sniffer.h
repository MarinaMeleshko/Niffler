#ifndef SNIFFER_H
#define SNIFFER_H

#include<pcap.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>

#include "protocol_codes.h"
#include "tcppacket.h"
#include "udppacket.h"
#include "arppacket.h"
#include "packetfilter.h"

#include <QThread>
#include <QList>

class Sniffer : public QThread{
    Q_OBJECT

    public:
        explicit Sniffer(QThread *parent = 0);
        ~Sniffer();

    public slots:
        void GetPackets(PacketFilter);
        QString GetPacketParsedData(int);

    private slots:
        void savePacket(BasePacket*);

    signals:
        void PacketRecieved(BasePacket *packet);
        void PacketProcessed(BasePacket *packet);
        void PacketPushed(QList<BasePacket>*);

    private:
        QList<BasePacket> *packetList;
        PacketFilter filterType;

        void processPacket(u_char *args, const pcap_pkthdr *header, const u_char *buffer);
    protected:
        void run();
};



#endif // SNIFFER_H
