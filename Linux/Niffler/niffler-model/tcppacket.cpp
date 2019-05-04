#include "tcppacket.h"

#include <QDebug>

TCPPacket::TCPPacket(const u_char *data, const pcap_pkthdr *header, int offset) : BasePacket (data){
    protocol = "TCP";

    struct sockaddr_in src, dest;
    struct iphdr *iph = (struct iphdr *)(data + offset);

    memset(&src, 0, sizeof (src));
    src.sin_addr.s_addr = iph->saddr;
    source = strdup(inet_ntoa(src.sin_addr));

    memset(&dest, 0, sizeof (dest));
    dest.sin_addr.s_addr = iph->daddr;
    destination = strdup(inet_ntoa(dest.sin_addr));

    type = 2;
    this->offset = offset;
    parsedData = this->ParseHeader(data, header->len);
}

QString TCPPacket::ParseHeader(const u_char *data, int size) {
    struct tcphdr *tcph=(struct tcphdr*)(data + offset + sizeof(struct iphdr));
    int header_size = offset + sizeof(struct tcphdr) + sizeof(struct iphdr);
    QString resultString;
    char num_buffer [100];
    resultString = QString::fromUtf8("*****TCP Packet***********\n");

    sprintf(num_buffer, "   |-Source Port      : %u\n", ntohs(tcph->source));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Destination Port : %u\n", ntohs(tcph->dest));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Window         : %d\n",ntohs(tcph->window));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Checksum       : %d\n",ntohs(tcph->check));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    resultString += QString::fromUtf8(num_buffer);
    resultString += Data(data + header_size, size - header_size);
    return resultString;

}
