#pragma once

#include "stdafx.h"
#include <vector>

using namespace std;

class IPv6Packet {
public:
    // Создать IPv6+TCP пакет
    static vector<BYTE> wrapTCP(const BYTE* srcAddr, const BYTE* dstAddr, 
                                 WORD srcPort, WORD dstPort,
                                 bool syn, bool ack, bool psh, bool fin,
                                 DWORD seqNum, DWORD ackNum, 
                                 const BYTE* data, DWORD dataLen);
    
    // Извлечь TCP payload из IPv6 пакета
    static bool unwrapTCP(const BYTE* ipv6Packet, DWORD len,
                          BYTE* outSrcAddr, BYTE* outDstAddr,
                          WORD& outSrcPort, WORD& outDstPort,
                          bool& outSyn, bool& outAck, bool& outPsh,
                          DWORD& outSeqNum, DWORD& outAckNum,
                          vector<BYTE>& outPayload);
    
    // Получить TCP flags
    static int getTCPFlags(const BYTE* ipv6Packet, DWORD len);
    
private:
    // Создать TCP сегмент
    static vector<BYTE> createTCPSegment(WORD srcPort, WORD dstPort,
                                          bool syn, bool ack, bool psh, bool fin,
                                          DWORD seqNum, DWORD ackNum,
                                          const BYTE* data, DWORD dataLen);
    
    // Вычислить TCP checksum с псевдозаголовком IPv6
    static WORD calculateTCPChecksum(const BYTE* srcAddr, const BYTE* dstAddr,
                                      const BYTE* tcpSegment, DWORD tcpLen);
};