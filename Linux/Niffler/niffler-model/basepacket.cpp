#include "basepacket.h"

BasePacket::BasePacket(const u_char* data){
    (void)data;
    protocol = "OTHER";
    source = "";
    destination = "";
    type = 0;
}

QString BasePacket::ParseHeader(const u_char *data, int size){
    (void)data;
    return NULL;
}

QString Data(const u_char* data, int size){
    QString resultString, dString = QString::fromUtf8("");
    char num_buffer [100];
    resultString = QString::fromUtf8("       DATA Dump       \n");

    int i, j;
    for (i = 0; i < size; ++i){
        if ( i!=0 && i % 16 == 0){
            sprintf(num_buffer, "         ");
            resultString += QString::fromUtf8(num_buffer);
            for(j = i - 16; j < i; ++j){
                if (data[j] >= 32 && data[j] <= 128){
                    sprintf(num_buffer, "%c", (unsigned char)data[j]);
                }
                else{
                    sprintf(num_buffer, ".");
                }
                dString += QString::fromUtf8(num_buffer);
            }
            sprintf(num_buffer, "\n");
            dString += QString::fromUtf8(num_buffer);
            resultString += QString::fromUtf8(num_buffer);
        }
        sprintf(num_buffer, "%02X ", (unsigned int)data[i]);
        resultString += QString::fromUtf8(num_buffer);
        if (i == size - 1){
            for (j = 0; j < 15 - i % 16; ++j){
                sprintf(num_buffer, "   ");
                resultString += QString::fromUtf8(num_buffer);
            }
            for (j = i - i % 16; j <= i; ++j){
                if (data[j] >= 32 && data[j] <= 128){
                    sprintf(num_buffer, "%c", (unsigned char)data[j]);
                    dString += QString::fromUtf8(num_buffer);
                }
                else{
                    sprintf(num_buffer, ".");
                    dString += QString::fromUtf8(num_buffer);
                }
            }
            sprintf(num_buffer, "\n");
            dString += QString::fromUtf8(num_buffer);
            resultString += QString::fromUtf8(num_buffer);
        }
    }
    sprintf(num_buffer, "\n");
    resultString += QString::fromUtf8(num_buffer);
    return resultString + dString;
}
