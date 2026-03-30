#include "stdafx.h"
#include "IPv6Packet.h"

vector<BYTE> IPv6Packet::wrapTCP(const BYTE* srcAddr, const BYTE* dstAddr, 
                                  WORD srcPort, WORD dstPort,
                                  bool syn, bool ack, bool psh, bool fin,
                                  DWORD seqNum, DWORD ackNum, 
                                  const BYTE* data, DWORD dataLen) {
    // Создаем TCP сегмент
    vector<BYTE> tcpSegment = createTCPSegment(srcPort, dstPort, syn, ack, psh, fin,
                                                seqNum, ackNum, data, dataLen);
    
    // Вычисляем checksum с псевдозаголовком IPv6
    WORD checksum = calculateTCPChecksum(srcAddr, dstAddr, &tcpSegment[0], tcpSegment.size());
    
    // Вставляем строго в сетевом порядке байт (Big Endian)
    tcpSegment[16] = (BYTE)(checksum >> 8);   // Старший байт
    tcpSegment[17] = (BYTE)(checksum & 0xFF); // Младший байт
    
    // IPv6 Header (40 bytes)
    vector<BYTE> packet;
    packet.reserve(40 + tcpSegment.size());
    
    // Version (4 bits) = 6, Traffic Class (8 bits) = 0, Flow Label (20 bits) = 0
    packet.push_back(0x60);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    
    // Payload Length (2 bytes, big-endian)
    WORD payloadLen = (WORD)tcpSegment.size();
    packet.push_back((BYTE)((payloadLen >> 8) & 0xFF));
    packet.push_back((BYTE)(payloadLen & 0xFF));
    
    // Next Header (1 byte) = 6 (TCP)
    packet.push_back(0x06);
    
    // Hop Limit (1 byte) = 64
    packet.push_back(64);
    
    // Source Address (16 bytes)
    packet.insert(packet.end(), srcAddr, srcAddr + 16);
    
    // Destination Address (16 bytes)
    packet.insert(packet.end(), dstAddr, dstAddr + 16);
    
    // TCP Segment
    packet.insert(packet.end(), tcpSegment.begin(), tcpSegment.end());
    
    return packet;
}

vector<BYTE> IPv6Packet::createTCPSegment(WORD srcPort, WORD dstPort,
                                           bool syn, bool ack, bool psh, bool fin,
                                           DWORD seqNum, DWORD ackNum,
                                           const BYTE* data, DWORD dataLen) {
    vector<BYTE> segment;
    segment.reserve(20 + dataLen);
    
    // Source Port (2 bytes)
    segment.push_back((BYTE)((srcPort >> 8) & 0xFF));
    segment.push_back((BYTE)(srcPort & 0xFF));
    
    // Destination Port (2 bytes)
    segment.push_back((BYTE)((dstPort >> 8) & 0xFF));
    segment.push_back((BYTE)(dstPort & 0xFF));
    
    // Sequence Number (4 bytes)
    segment.push_back((BYTE)((seqNum >> 24) & 0xFF));
    segment.push_back((BYTE)((seqNum >> 16) & 0xFF));
    segment.push_back((BYTE)((seqNum >> 8) & 0xFF));
    segment.push_back((BYTE)(seqNum & 0xFF));
    
    // Acknowledgment Number (4 bytes)
    segment.push_back((BYTE)((ackNum >> 24) & 0xFF));
    segment.push_back((BYTE)((ackNum >> 16) & 0xFF));
    segment.push_back((BYTE)((ackNum >> 8) & 0xFF));
    segment.push_back((BYTE)(ackNum & 0xFF));
    
    // Data Offset (4 bits) = 5 (20 bytes), Reserved (4 bits) = 0
    segment.push_back(0x50);
    
    // Flags (1 byte)
    BYTE flags = 0;
    if (fin) flags |= 0x01;
    if (syn) flags |= 0x02;
    if (psh) flags |= 0x08;
    if (ack) flags |= 0x10;
    segment.push_back(flags);
    
    // Window Size (2 bytes) = 65535
    segment.push_back(0xFF);
    segment.push_back(0xFF);
    
    // Checksum (2 bytes) - временно 0
    segment.push_back(0x00);
    segment.push_back(0x00);
    
    // Urgent Pointer (2 bytes) = 0
    segment.push_back(0x00);
    segment.push_back(0x00);
    
    // Data
    if (dataLen > 0 && data != NULL) {
        segment.insert(segment.end(), data, data + dataLen);
    }
    
    return segment;
}

// Железобетонный расчет контрольной суммы TCP (независимый от Little/Big Endian)
WORD IPv6Packet::calculateTCPChecksum(const BYTE* srcAddr, const BYTE* dstAddr,
                                       const BYTE* tcpSegment, DWORD tcpLen) {
    DWORD sum = 0;
    
    // Псевдозаголовок IPv6 - читаем строго как Big Endian
    for (DWORD i = 0; i < 16; i += 2) {
        WORD word = (srcAddr[i] << 8) | srcAddr[i + 1];
        sum += word;
        word = (dstAddr[i] << 8) | dstAddr[i + 1];
        sum += word;
    }
    
    // Protocol (TCP = 6)
    sum += 6;
    
    // TCP Length
    sum += tcpLen;
    
    // TCP сегмент - читаем строго как Big Endian
    for (DWORD i = 0; i < tcpLen; i += 2) {
        WORD word = (tcpSegment[i] << 8); // Старший байт первый
        if (i + 1 < tcpLen) {
            word |= tcpSegment[i + 1];     // Младший байт второй
        }
        sum += word;
    }
    
    // Добавляем переносы
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Инвертируем
    return (WORD)(~sum & 0xFFFF);
}

bool IPv6Packet::unwrapTCP(const BYTE* ipv6Packet, DWORD len,
                           BYTE* outSrcAddr, BYTE* outDstAddr,
                           WORD& outSrcPort, WORD& outDstPort,
                           bool& outSyn, bool& outAck, bool& outPsh,
                           DWORD& outSeqNum, DWORD& outAckNum,
                           vector<BYTE>& outPayload) {
    if (ipv6Packet == NULL || len < 40) {
        return false;
    }
    
    // Проверяем версию IPv6
    if ((ipv6Packet[0] & 0xF0) != 0x60) {
        return false;
    }
    
    // Payload Length
    WORD payloadLen = ((ipv6Packet[4] & 0xFF) << 8) | (ipv6Packet[5] & 0xFF);
    
    // Next Header (должен быть TCP = 6)
    if (ipv6Packet[6] != 6) {
        return false;
    }
    
    if (len < 40 + payloadLen) {
        return false;
    }
    
    const BYTE* tcpSegment = ipv6Packet + 40;
    DWORD tcpLen = payloadLen;
    
    if (tcpLen < 20) {
        return false;
    }
    
    // Data Offset
    int dataOffset = ((tcpSegment[12] & 0xF0) >> 4) * 4;
    if (dataOffset < 20 || (DWORD)dataOffset > tcpLen) {
        return false;
    }
    
    // Source и Destination Address
    if (outSrcAddr) memcpy(outSrcAddr, ipv6Packet + 8, 16);
    if (outDstAddr) memcpy(outDstAddr, ipv6Packet + 24, 16);
    
    // Source Port
    outSrcPort = ((WORD)tcpSegment[0] << 8) | tcpSegment[1];
    
    // Destination Port
    outDstPort = ((WORD)tcpSegment[2] << 8) | tcpSegment[3];
    
    // Sequence Number
    outSeqNum = ((DWORD)tcpSegment[4] << 24) | ((DWORD)tcpSegment[5] << 16) | 
                ((DWORD)tcpSegment[6] << 8) | (DWORD)tcpSegment[7];
    
    // Acknowledgment Number
    outAckNum = ((DWORD)tcpSegment[8] << 24) | ((DWORD)tcpSegment[9] << 16) | 
                ((DWORD)tcpSegment[10] << 8) | (DWORD)tcpSegment[11];
    
    // Flags
    BYTE flags = tcpSegment[13];
    outSyn = (flags & 0x02) != 0;
    outAck = (flags & 0x10) != 0;
    outPsh = (flags & 0x08) != 0;
    
    // Payload
    DWORD payloadLength = tcpLen - dataOffset;
    outPayload.clear();
    if (payloadLength > 0) {
        outPayload.insert(outPayload.end(), tcpSegment + dataOffset, tcpSegment + dataOffset + payloadLength);
    }
    
    return true;
}

int IPv6Packet::getTCPFlags(const BYTE* ipv6Packet, DWORD len) {
    if (ipv6Packet == NULL || len < 41) {
        return 0;
    }
    return ipv6Packet[40 + 13] & 0xFF;
}