#include "udppacket.h"
#include <QDebug>

UDPPacket::UDPPacket(const u_char *data, const pcap_pkthdr *header, int offset) : BasePacket(data)
{
    protocol ="UDP";

    struct sockaddr_in src, dest;
    struct iphdr *iph = (struct iphdr *)(data + offset);

    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->saddr;
    source = strdup(inet_ntoa(src.sin_addr));

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    destination = strdup(inet_ntoa(dest.sin_addr));

    type = 3;
    this->offset = offset;
    parsedData = this->ParseHeader(data, header->len);
}


QString UDPPacket::ParseHeader(const u_char *data, int size) {
    struct udphdr *udph=(struct udphdr*)(data + offset + sizeof(struct iphdr));

    int header_size = offset + sizeof(struct udphdr) + sizeof(struct iphdr);
    QString resultString;
    char num_buffer [100];
    resultString = QString::fromUtf8("*****UDP Packet***********\n");
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Source Port      : %d\n" , ntohs(udph->source));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Destination Port : %d\n" , ntohs(udph->dest));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-UDP Length       : %d\n" , ntohs(udph->len));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    resultString += QString::fromUtf8(num_buffer);

    resultString += Data(data + header_size, size - header_size);
    return resultString;

}
