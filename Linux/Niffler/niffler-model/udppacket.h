#ifndef UDPPACKET_H
#define UDPPACKET_H

#include "basepacket.h"
#include <pcap.h>

class UDPPacket : public BasePacket{
    public:
        UDPPacket(const u_char *data, const pcap_pkthdr *header, int offset);
        QString ParseHeader(const u_char *data, int size);
};

#endif // UDPPACKET_H
