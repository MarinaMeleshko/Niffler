#ifndef BASEPACKET_H
#define BASEPACKET_H

#include <QString>

#include <cstring>
#include <string.h>

#include <pcap.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>


class BasePacket{
    public:
        BasePacket(const u_char *data);
        char* source;
        char* destination;
        const char* protocol;
        int offset;
        int id;
        QString parsedData;

        QString ParseHeader(const u_char *data, int size);

        int getTypeId(){
            return type;
        }

    protected:
        int type;

};

QString Data(const u_char* data, int size);

#endif // BASEPACKET_H
