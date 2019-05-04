#ifndef TCPPACKET_H
#define TCPPACKET_H

#include "basepacket.h"
#include <pcap.h>

class TCPPacket : public BasePacket
{
    public:
        TCPPacket(const u_char *data, const pcap_pkthdr *header, int offset);
        QString ParseHeader(const u_char *data, int size);
};

#endif // TCPPACKET_H
