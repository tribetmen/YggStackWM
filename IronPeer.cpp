// IronPeer.cpp - Реализация работы с пирами
#include "stdafx.h"
#include "IronPeer.h"
#include "YggCrypto.h"
#include "YggBloom.h"
#include "YggdrasilCore.h"
#include "ygg_constants.h"

extern "C" {
#include "tweetnacl32.h"
}

extern void AddLog(LPCWSTR text, BYTE type);
extern HWND g_hWnd;
#define WM_PEER_DISCONNECTED (WM_USER + 102)

// ============================================================================
// СТРУКТУРЫ ДЛЯ ПОТОКОВ
// ============================================================================

struct DelayedBloomArgs {
    IronPeer* peer;
    BYTE pubKey[32];
};

struct DelayedAnnounceArgs {
    IronPeer* peer;
};

// ============================================================================
// ОТЛОЖЕННАЯ ОТПРАВКА ANNOUNCE (поток)
// ============================================================================

static DWORD WINAPI DelayedAnnounceThreadProc(LPVOID lpParam) {
    DelayedAnnounceArgs* args = (DelayedAnnounceArgs*)lpParam;
    
    Sleep(100);  // Небольшая задержка перед ANNOUNCE
    
    // Отправляем только если хендшейк пройден
    if (args->peer && args->peer->IsHandshakeComplete()) {
        AddLog(L"[ANNOUNCE] Sending async...", LOG_INFO);
        args->peer->SendAnnounce();
    } else {
        AddLog(L"[ANNOUNCE] Skipped - handshake not complete", LOG_WARN);
    }
    
    delete args;
    return 0;
}

// ============================================================================
// ОТЛОЖЕННАЯ ОТПРАВКА BLOOM (поток)
// ============================================================================

static DWORD WINAPI DelayedBloomThreadProc(LPVOID lpParam) {
    DelayedBloomArgs* args = (DelayedBloomArgs*)lpParam;
    
    AddLog(L"[BLOOM] Waiting 500ms before sending real Bloom filter...", LOG_INFO);
    Sleep(500);
    
    // Отправляем только если хендшейк пройден
    if (args->peer && args->peer->IsHandshakeComplete()) {
        args->peer->SendBloom(args->pubKey);
        AddLog(L"[BLOOM] Real Bloom filter sent! Ready for traffic.", LOG_SUCCESS);
    } else {
        AddLog(L"[BLOOM] Skipped - handshake not complete", LOG_WARN);
    }
    
    delete args;
    return 0;
}

// ============================================================================
// КОНСТРУКТОР / ДЕСТРУКТОР
// ============================================================================

IronPeer::IronPeer(SOCKET sock, const BYTE* remoteKey) {
    m_socket = sock;
    
    // Отключаем Nagle algorithm для минимальной задержки
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    
    memcpy(m_remoteKey, remoteKey, KEY_SIZE);
    memcpy(m_remoteXPub, remoteKey, KEY_SIZE);
    m_remotePort = 0;
    m_ourPortInTree = 0;
    m_bConnected = true;  // TCP соединение установлено
    m_bHandshakeComplete = false;  // Хендшейк ещё не пройден
    m_sigResReceived = false;
    memset(m_psig, 0, 64);
    
    // Инициализация новых полей
    m_remoteSeq = 0;
    m_remoteNonce = 0;
    m_gotSigReq = false;
    
    m_hReceiveThread = NULL;
    m_hKeepaliveThread = NULL;
    
    // Инициализация ключей (должны быть установлены через SetOurKeys)
    m_ourEdPub = NULL;
    m_ourEdPriv = NULL;
    
    // Инициализация координат (по умолчанию {0})
    m_myGlobalCoords.clear();
    m_myGlobalCoords.push_back(0);
    
    InitializeCriticalSection(&m_sessionsLock);
    InitializeCriticalSection(&m_routingLock);
    InitializeCriticalSection(&m_pendingLock);
    
    AddLog(L"[Peer] Created new peer", LOG_DEBUG);
}

IronPeer::~IronPeer() {
    Stop();
    DeleteCriticalSection(&m_sessionsLock);
    DeleteCriticalSection(&m_routingLock);
    DeleteCriticalSection(&m_pendingLock);
}

// ============================================================================
// УПРАВЛЕНИЕ СОЕДИНЕНИЕМ
// ============================================================================

bool IronPeer::Start() {
    m_hReceiveThread = CreateThread(NULL, 65536, ReceiveThreadProc, this, 0, NULL);
    if (m_hReceiveThread) {
        // Нормальный приоритет для receive
        SetThreadPriority(m_hReceiveThread, THREAD_PRIORITY_NORMAL);
    }
    
    m_hKeepaliveThread = CreateThread(NULL, 65536, KeepaliveThreadProc, this, 0, NULL);
    if (m_hKeepaliveThread) {
        // Высокий приоритет для keepalive, чтобы не терять соединение
        SetThreadPriority(m_hKeepaliveThread, THREAD_PRIORITY_HIGHEST);
    }
    
    return (m_hReceiveThread != NULL && m_hKeepaliveThread != NULL);
}

void IronPeer::Stop() {
    m_bConnected = false;
    
    if (m_hReceiveThread) {
        WaitForSingleObject(m_hReceiveThread, 1000);
        CloseHandle(m_hReceiveThread);
        m_hReceiveThread = NULL;
    }
    
    if (m_hKeepaliveThread) {
        WaitForSingleObject(m_hKeepaliveThread, 1000);
        CloseHandle(m_hKeepaliveThread);
        m_hKeepaliveThread = NULL;
    }
    
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    
    EnterCriticalSection(&m_sessionsLock);
    for(size_t i = 0; i < m_sessions.size(); i++) {
        m_sessions[i]->Release();
    }
    m_sessions.clear();
    LeaveCriticalSection(&m_sessionsLock);
}

// ============================================================================
// ОТПРАВКА ПАКЕТОВ
// ============================================================================

bool IronPeer::SendPacketRaw(const BYTE* data, DWORD len) {
    if (!m_bConnected) {
        AddLog(L"[SendPacketRaw] Not connected!", LOG_ERROR);
        return false;
    }
    
    WCHAR debug[256];
    wsprintf(debug, L"[SendPacketRaw] Sending %lu bytes to socket %d", len, m_socket);
    AddLog(debug, LOG_DEBUG);
    
    int sent = send(m_socket, (char*)data, len, 0);
    if (sent != (int)len) {
        wsprintf(debug, L"[SendPacketRaw] Send failed: sent=%d, expected=%lu, error=%d", 
                 sent, len, WSAGetLastError());
        AddLog(debug, LOG_ERROR);
        return false;
    }
    
    wsprintf(debug, L"[SendPacketRaw] Sent %d bytes OK", sent);
    AddLog(debug, LOG_DEBUG);
    return true;
}

bool IronPeer::SendPacket(BYTE type, const BYTE* data, DWORD dataLen) {
    if (!m_bConnected) return false;
    
    vector<BYTE> packet;
    packet.push_back(type);
    if (data && dataLen > 0) {
        packet.insert(packet.end(), data, data + dataLen);
    }
    
    // Формируем varint длину
    BYTE lenBuf[10];
    int lenPos = 0;
    unsigned long long len = packet.size();
    
    while (len >= 0x80) {
        lenBuf[lenPos++] = (BYTE)((len & 0x7F) | 0x80);
        len >>= 7;
    }
    lenBuf[lenPos++] = (BYTE)len;
    
    // Вставляем длину В НАЧАЛО
    packet.insert(packet.begin(), lenBuf, lenBuf + lenPos);
    
    // Отправляем одним пакетом
    if (send(m_socket, (char*)&packet[0], packet.size(), 0) == SOCKET_ERROR) return false;
    
    return true;
}

bool IronPeer::SendKeepAlive() {
    return SendPacket(WIRE_KEEP_ALIVE, NULL, 0);
}

bool IronPeer::SendBloom(const BYTE* ourPubKey) {
    vector<BYTE> bloom;
    YggBloom::Generate(ourPubKey, bloom);
    return SendPacket(WIRE_BLOOM, &bloom[0], bloom.size());
}

bool IronPeer::SendSigReq() {
    if (!m_bConnected) return false;
    
    vector<BYTE> packet;
    packet.push_back(WIRE_SIG_REQ);
    
    // seq = GetTickCount() / 1000
    DWORD seq = GetTickCount() / 1000;
    WriteUvarint(packet, seq);
    
    // nonce = случайное или GetTickCount()
    DWORD nonce = GetTickCount() ^ (rand() << 16);
    WriteUvarint(packet, nonce);
    
    return SendPacket(WIRE_SIG_REQ, &packet[1], packet.size() - 1);
}

// ============================================================================
// VARINT УТИЛИТЫ
// ============================================================================

bool IronPeer::ReadUvarint(unsigned long long& value) {
    value = 0;
    int shift = 0;
    BYTE b;
    
    while (true) {
        int r = recv(m_socket, (char*)&b, 1, 0);
        if (r != 1) {
            AddLog(L"[ReadUvarint] Failed to read byte", LOG_ERROR);
            return false;
        }
        
        value |= (unsigned long long)(b & 0x7F) << shift;
        shift += 7;
        
        if (!(b & 0x80)) break;
        
        // Предотвращаем переполнение 64-битного типа
        if (shift >= 64) {
            AddLog(L"[ReadUvarint] Varint overflow", LOG_ERROR);
            return false;
        }
    }
    
    return true;
}

bool IronPeer::WriteUvarint(vector<BYTE>& out, unsigned long long value) {
    while (value >= 0x80) {
        out.push_back((BYTE)((value & 0x7F) | 0x80));
        value >>= 7;
    }
    out.push_back((BYTE)value);
    return true;
}

// ============================================================================
// HANDSHAKE
// ============================================================================

void IronPeer::SetRemoteSigReq(unsigned long long seq, unsigned long long nonce) {
    m_remoteSeq = seq;
    m_remoteNonce = nonce;
    m_gotSigReq = true;
    
    WCHAR debug[256];
    wsprintf(debug, L"[Peer] Set remote SIG_REQ: seq=%I64u, nonce=%I64u", seq, nonce);
    AddLog(debug, LOG_DEBUG);
}

bool IronPeer::SendHandshakeBundle(const BYTE* ourPubKey, const BYTE* ourPrivKey,
                                    unsigned long long remoteSeq, unsigned long long remoteNonce) {
    WCHAR debug[256];
    AddLog(L"=== SENDING HANDSHAKE BUNDLE ===", LOG_INFO);
    
    vector<BYTE> bundle;
    
    // БЛОК 1: SIG_REQ
    {
        vector<BYTE> block;
        block.push_back(WIRE_SIG_REQ);
        
        unsigned long long seq = GetTickCount() / 1000;
        unsigned long long nonce = GetTickCount() ^ (rand() << 16);
        
        WriteUvarint(block, seq);
        WriteUvarint(block, nonce);
        
        wsprintf(debug, L"Block1 (SIG_REQ): seq=%I64u, nonce=%I64u, size=%d", seq, nonce, block.size());
        AddLog(debug, LOG_INFO);
        
        WriteUvarint(bundle, block.size());
        bundle.insert(bundle.end(), block.begin(), block.end());
    }
    
    // БЛОК 2: SIG_RES
    {
        vector<BYTE> block;
        block.push_back(WIRE_SIG_RES);
        
        WriteUvarint(block, remoteSeq);
        WriteUvarint(block, remoteNonce);
        WriteUvarint(block, 0);  // port = 0
        
        BYTE msgToSign[256];
        int msgLen = 0;
        
        memcpy(msgToSign + msgLen, m_remoteKey, 32);
        msgLen += 32;
        memcpy(msgToSign + msgLen, ourPubKey, 32);
        msgLen += 32;
        
        // Добавляем remoteSeq как varint
        unsigned long long tmp = remoteSeq;
        while (tmp >= 0x80) {
            msgToSign[msgLen++] = (BYTE)((tmp & 0x7F) | 0x80);
            tmp >>= 7;
        }
        msgToSign[msgLen++] = (BYTE)tmp;
        
        // Добавляем remoteNonce как varint
        tmp = remoteNonce;
        while (tmp >= 0x80) {
            msgToSign[msgLen++] = (BYTE)((tmp & 0x7F) | 0x80);
            tmp >>= 7;
        }
        msgToSign[msgLen++] = (BYTE)tmp;
        
        // port = 0
        msgToSign[msgLen++] = 0;
        
        wsprintf(debug, L"Signing %d bytes message", msgLen);
        AddLog(debug, LOG_DEBUG);
        
        // Подписываем
        BYTE expandedSk[64];
        memcpy(expandedSk, ourPrivKey, 32);
        memcpy(expandedSk + 32, ourPubKey, 32);
        
        BYTE signedBuf[256];
        unsigned int signedLen = 0;
        
        DWORD signStart = GetTickCount();
        int signRes = crypto_sign(signedBuf, &signedLen, msgToSign, msgLen, expandedSk);
        DWORD signTime = GetTickCount() - signStart;
        
        if (signRes != 0 || signedLen < 64) {
            wsprintf(debug, L"Signing failed! res=%d, len=%u, time=%lums", signRes, signedLen, signTime);
            AddLog(debug, LOG_ERROR);
            return false;
        }
        
        wsprintf(debug, L"Signature generated, len=%u, time=%lums", signedLen, signTime);
        AddLog(debug, LOG_SUCCESS);
        
        // Добавляем подпись
        block.insert(block.end(), signedBuf, signedBuf + 64);
        
        wsprintf(debug, L"Block2 (SIG_RES): remoteSeq=%I64u, remoteNonce=%I64u, size=%d",
                 remoteSeq, remoteNonce, block.size());
        AddLog(debug, LOG_INFO);
        
        WriteUvarint(bundle, block.size());
        bundle.insert(bundle.end(), block.begin(), block.end());
    }
    
    wsprintf(debug, L"Total bundle size: %d bytes", bundle.size());
    AddLog(debug, LOG_INFO);
    
    int sent = send(m_socket, (char*)&bundle[0], bundle.size(), 0);
    return sent == (int)bundle.size();
}

// ============================================================================
// ПОЛУЧЕНИЕ ПАКЕТОВ
// ============================================================================

bool IronPeer::ReceivePacket(BYTE* buffer, DWORD bufferSize, DWORD& bytesReceived) {
    if (!m_bConnected || m_socket == INVALID_SOCKET) return false;
    
    WCHAR debug[256];
    
    // Читаем varint длину пакета
    DWORD packetLen = 0;
    int shift = 0;
    BYTE b;
    int headerBytes = 0;
    
    AddLog(L"[RECV] Reading varint length...", LOG_DEBUG);
    
    do {
        int r = recv(m_socket, (char*)&b, 1, 0);
        if (r != 1) {
            wsprintf(debug, L"[RECV] Failed to read length byte: %d", WSAGetLastError());
            AddLog(debug, LOG_ERROR);
            return false;
        }
        headerBytes++;
        
        packetLen |= (DWORD)(b & 0x7F) << shift;
        shift += 7;

        if (headerBytes > 1 || (b & 0x80)) {
            wsprintf(debug, L"[RECV] Byte %d: 0x%02x, packetLen now: %lu",
                     headerBytes, b, packetLen);
            AddLog(debug, LOG_DEBUG);
        }
        
        if (shift > 28) {
            AddLog(L"[RECV] Varint overflow!", LOG_ERROR);
            return false;
        }
    } while (b & 0x80);
    
    wsprintf(debug, L"[RECV] Packet length: %lu bytes", packetLen);
    AddLog(debug, LOG_INFO);
    
    if (packetLen == 0 || packetLen > bufferSize) {
        wsprintf(debug, L"[RECV] Invalid length: %lu", packetLen);
        AddLog(debug, LOG_ERROR);
        return false;
    }
    
    // Читаем данные пакета
    DWORD totalRead = 0;
    while (totalRead < packetLen) {
        int r = recv(m_socket, (char*)buffer + totalRead, packetLen - totalRead, 0);
        if (r <= 0) {
            wsprintf(debug, L"[RECV] Read failed: %d", WSAGetLastError());
            AddLog(debug, LOG_ERROR);
            return false;
        }
        totalRead += r;
    }
    
    wsprintf(debug, L"[RECV] Read %lu bytes", totalRead);
    AddLog(debug, LOG_SUCCESS);
    
    bytesReceived = totalRead;
    return true;
}

void IronPeer::HandleReceivedData(const BYTE* data, DWORD len) {
    WCHAR debug[256];
    
    AddLog(L"=== HANDLE PACKET ===", LOG_INFO);
    wsprintf(debug, L"Packet size: %lu bytes", len);
    AddLog(debug, LOG_INFO);
    
    if (len < 1) {
        AddLog(L"Packet too short", LOG_ERROR);
        return;
    }
    
    BYTE packetType = data[0];
    
    LPCWSTR typeName = L"UNKNOWN";
    switch(packetType) {
        case 0x01: typeName = L"KEEP_ALIVE"; break;
        case 0x02: typeName = L"SIG_REQ"; break;
        case 0x03: typeName = L"SIG_RES"; break;
        case 0x04: typeName = L"ANNOUNCE"; break;
        case 0x05: typeName = L"BLOOM"; break;
        case 0x06: typeName = L"PATH_LOOKUP"; break;
        case 0x07: typeName = L"PATH_NOTIFY"; break;
        case 0x09: typeName = L"TRAFFIC"; break;
    }
    
    wsprintf(debug, L"Packet type: 0x%02x (%s)", packetType, typeName);
    AddLog(debug, LOG_INFO);
    
    switch (packetType) {
        case WIRE_KEEP_ALIVE:
            AddLog(L"KEEP_ALIVE received", LOG_DEBUG);
            break;
            
        case WIRE_SIG_REQ:
            AddLog(L"Delegating to HandleSigReq...", LOG_SUCCESS);
            HandleSigReq(data, len);
            break;
            
        case WIRE_SIG_RES:
            AddLog(L"Delegating to HandleSigRes...", LOG_SUCCESS);
            HandleSigRes(data, len);
            break;
            
        case WIRE_ANNOUNCE:
            AddLog(L"Delegating to HandleAnnounce...", LOG_INFO);
            HandleAnnounce(data, len);
            break;
            
        case WIRE_BLOOM:
            AddLog(L"BLOOM filter received", LOG_INFO);
            break;
            
        case WIRE_PATH_LOOKUP:
            HandlePathLookup(data, len);
            break;
            
        case WIRE_PATH_NOTIFY:
            HandlePathNotify(data, len);
            break;
            
        case WIRE_TRAFFIC:
            HandleTraffic(data, len);
            break;
            
        default:
            wsprintf(debug, L"Unknown packet type: 0x%02x", packetType);
            AddLog(debug, LOG_WARN);
            break;
    }
    
    AddLog(L"=== PACKET PROCESSED ===", LOG_INFO);
}

// ============================================================================
// ОБРАБОТЧИКИ ПАКЕТОВ
// ============================================================================

void IronPeer::HandleSigReq(const BYTE* packet, DWORD len) {
    if (!m_bConnected || len < 3) return;
    if (!m_ourEdPub) return; // Ключи не установлены
    
    WCHAR debug[256];
    AddLog(L"[SIG_REQ] Received", LOG_DEBUG);
    
    const BYTE* p = packet + 1;
    DWORD remaining = len - 1;
    
    unsigned long long remoteSeq = 0;
    int shift = 0;
    while (remaining > 0) {
        BYTE b = *p++;
        remaining--;
        remoteSeq |= (unsigned long long)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    
    unsigned long long remoteNonce = 0;
    shift = 0;
    while (remaining > 0) {
        BYTE b = *p++;
        remaining--;
        remoteNonce |= (unsigned long long)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    
    wsprintf(debug, L"[SIG_REQ] seq=%I64u, nonce=%I64u", remoteSeq, remoteNonce);
    AddLog(debug, LOG_SUCCESS);
    
    SetRemoteSigReq(remoteSeq, remoteNonce);
    
    // Автоматически отправляем HandshakeBundle с ответом
    if (!SendHandshakeBundle(m_ourEdPub, m_ourEdPriv, remoteSeq, remoteNonce)) {
        AddLog(L"[SIG_REQ] Failed to send handshake bundle!", LOG_ERROR);
    } else {
        AddLog(L"[SIG_REQ] Handshake bundle sent automatically", LOG_SUCCESS);
    }
}

void IronPeer::HandleSigRes(const BYTE* packet, DWORD len) {
    if (!m_bConnected || len < 10) return;
    
    WCHAR debug[256];
    AddLog(L"[SIG_RES] Received", LOG_DEBUG);
    
    const BYTE* p = packet + 1; 
    DWORD remaining = len - 1;
    
    unsigned long long seq = 0;
    int shift = 0;
    int seqBytes = 0;
    while (remaining > 0) {
        BYTE b = *p++;
        remaining--;
        seqBytes++;
        seq |= (unsigned long long)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    wsprintf(debug, L"  seq=%I64u (%d bytes)", seq, seqBytes);
    AddLog(debug, LOG_INFO);
    
    unsigned long long nonce = 0;
    shift = 0;
    int nonceBytes = 0;
    while (remaining > 0) {
        BYTE b = *p++;
        remaining--;
        nonceBytes++;
        nonce |= (unsigned long long)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    wsprintf(debug, L"  nonce=%I64u (%d bytes)", nonce, nonceBytes);
    AddLog(debug, LOG_INFO);
    
    unsigned long long port = 0;
    shift = 0;
    int portBytes = 0;
    while (remaining > 0) {
        BYTE b = *p++;
        remaining--;
        portBytes++;
        port |= (unsigned long long)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    wsprintf(debug, L"  port=%I64u (%d bytes)", port, portBytes);
    AddLog(debug, LOG_INFO);
    
    m_ourPortInTree = port;
    m_remoteSeq = seq;
    m_remoteNonce = nonce;
    
    if (remaining >= 64) {
        memcpy(m_psig, p, 64);
        remaining -= 64;
        p += 64;
        wsprintf(debug, L"  signature: 64 bytes, remaining=%d", remaining);
        AddLog(debug, LOG_DEBUG);
        
        // Проверяем, есть ли ещё данные (возможно координаты?)
        if (remaining > 0) {
            wsprintf(debug, L"  EXTRA DATA in SIG_RES: %d bytes", remaining);
            AddLog(debug, LOG_WARN);
            // Выводим первые байты
            for (int i = 0; i < min(remaining, 16); i++) {
                wsprintf(debug + i*3, L"%02x ", p[i]);
            }
            AddLog(debug, LOG_WARN);
        }
    }
    
    m_sigResReceived = true;
    m_bHandshakeComplete = true;

    wsprintf(debug, L"[SIG_RES] seq=%I64u, nonce=%I64u, port=%I64u", seq, nonce, port);
    AddLog(debug, LOG_SUCCESS);
    AddLog(L"[Peer] Handshake complete - peer is now ACTIVE", LOG_SUCCESS);

    // ANNOUNCE и BLOOM — только если нет активных ESTABLISHED сессий.
    // При keepalive SIG_RES во время активной передачи данных BLOOM не отправляем
    // чтобы не сбивать маршрутизацию у удалённых узлов.
    bool hasEstablished = false;
    EnterCriticalSection(&m_sessionsLock);
    for (size_t i = 0; i < m_sessions.size(); i++) {
        if (m_sessions[i]->GetTcpState() == TCP_ESTABLISHED) {
            hasEstablished = true;
            break;
        }
    }
    LeaveCriticalSection(&m_sessionsLock);

    if (hasEstablished) {
        AddLog(L"[SIG_RES] Active sessions exist - skipping ANNOUNCE/BLOOM to avoid disruption", LOG_DEBUG);
        return;
    }

    // ANNOUNCE, затем BLOOM (с задержкой 500ms чтобы ANNOUNCE дошёл первым)
    DelayedAnnounceArgs* announceArgs = new DelayedAnnounceArgs();
    announceArgs->peer = this;

    HANDLE hAnnounceThread = CreateThread(NULL, 0, DelayedAnnounceThreadProc, announceArgs, 0, NULL);
    if (hAnnounceThread) {
        CloseHandle(hAnnounceThread);
    } else {
        delete announceArgs;
        SendAnnounce();
    }

    CYggdrasilCore* core = CYggdrasilCore::GetInstance();

    DelayedBloomArgs* bloomArgs = new DelayedBloomArgs();
    bloomArgs->peer = this;
    memcpy(bloomArgs->pubKey, core->GetKeys().publicKey, 32);

    HANDLE hThread = CreateThread(NULL, 0, DelayedBloomThreadProc, bloomArgs, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    } else {
        delete bloomArgs;
        SendBloom(core->GetKeys().publicKey);
    }
}

void IronPeer::HandleAnnounce(const BYTE* packet, DWORD len) {
    if (!m_bConnected || len < 128) return;
    
    WCHAR debug[256];
    AddLog(L"[ANNOUNCE] Received", LOG_DEBUG);
    
    const BYTE* p = packet + 1;
    DWORD remaining = len - 1;
    
    while (remaining >= 32) {
        BYTE nodeKey[32];
        BYTE parentKey[32];
        
        memcpy(nodeKey, p, 32); p += 32; remaining -= 32;
        if (remaining < 32) break;
        
        memcpy(parentKey, p, 32); p += 32; remaining -= 32;
        
        unsigned long long seq = 0;
        int shift = 0;
        while (remaining > 0) {
            BYTE b = *p++;
            remaining--;
            seq |= (unsigned long long)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        
        unsigned long long nonce = 0;
        shift = 0;
        while (remaining > 0) {
            BYTE b = *p++;
            remaining--;
            nonce |= (unsigned long long)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        
        unsigned long long port = 0;
        shift = 0;
        while (remaining > 0) {
            BYTE b = *p++;
            remaining--;
            port |= (unsigned long long)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        
        if (remaining < 128) break;
        
        p += 128; // Пропускаем подписи
        remaining -= 128;
        
        // Сохраняем в таблицу маршрутизации
        string prefix = GetKeyPrefix(nodeKey);
        
        // Строим путь: parentPath + port
        vector<BYTE> newPath;
        NodeRoute* parentRoute = GetRoute(GetKeyPrefix(parentKey));
        if (parentRoute && parentRoute->path.size() > 0) {
            // Копируем путь родителя без завершающего 0
            newPath.insert(newPath.end(), parentRoute->path.begin(), parentRoute->path.end() - 1);
        }
        // Добавляем порт текущего узла
        WriteUvarint(newPath, port);
        newPath.push_back(0); // Завершающий 0
        
        NodeRoute route(nodeKey, newPath, parentKey, port);
        UpdateRoute(prefix, route);
        
        wsprintf(debug, L"[ANNOUNCE] Node added, port=%I64u, pathSize=%d", port, newPath.size());
        AddLog(debug, LOG_DEBUG);
    }
}

bool IronPeer::SendAnnounce() {
    if (!m_bConnected || m_psig[0] == 0) {
        AddLog(L"[ANNOUNCE] Cannot send - no signature", LOG_WARN);
        return false;
    }
    
    WCHAR debug[256];
    AddLog(L"[ANNOUNCE] Sending announce...", LOG_DEBUG);
    
    vector<BYTE> packet;
    packet.push_back(WIRE_ANNOUNCE);
    
    // 1. Наш публичный ключ (32 байта)
    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* ourPub = core->GetKeys().publicKey;
    packet.insert(packet.end(), ourPub, ourPub + 32);
    
    // 2. Ключ пира (32 байта)
    packet.insert(packet.end(), m_remoteKey, m_remoteKey + 32);
    
    // 3. remoteSeq (varint)
    vector<BYTE> temp;
    WriteUvarint(temp, m_remoteSeq);
    wsprintf(debug, L"[ANNOUNCE] seq varint size=%d", temp.size());
    AddLog(debug, LOG_INFO);
    packet.insert(packet.end(), temp.begin(), temp.end());
    temp.clear();

    // 4. remoteNonce (varint)
    WriteUvarint(temp, m_remoteNonce);
    wsprintf(debug, L"[ANNOUNCE] nonce varint size=%d", temp.size());
    AddLog(debug, LOG_INFO);
    packet.insert(packet.end(), temp.begin(), temp.end());
    temp.clear();

    // 5. Наш порт (varint)
    WriteUvarint(temp, m_ourPortInTree);
    wsprintf(debug, L"[ANNOUNCE] port varint size=%d", temp.size());
    AddLog(debug, LOG_INFO);
    packet.insert(packet.end(), temp.begin(), temp.end());
    temp.clear();
    
    // 6. Подпись пира (64 байта) - из SIG_RES
    packet.insert(packet.end(), m_psig, m_psig + 64);
    
    // ===== НАША ПОДПИСЬ =====
    BYTE msgToSign[256];
    int msgLen = 0;
    
    memcpy(msgToSign + msgLen, ourPub, 32);
    msgLen += 32;
    memcpy(msgToSign + msgLen, m_remoteKey, 32);
    msgLen += 32;
    
    unsigned long long tmp;
    
    // Добавляем remoteSeq как varint
    tmp = m_remoteSeq;
    while (tmp >= 0x80) {
        msgToSign[msgLen++] = (BYTE)((tmp & 0x7F) | 0x80);
        tmp >>= 7;
    }
    msgToSign[msgLen++] = (BYTE)tmp;
    
    // Добавляем remoteNonce как varint
    tmp = m_remoteNonce;
    while (tmp >= 0x80) {
        msgToSign[msgLen++] = (BYTE)((tmp & 0x7F) | 0x80);
        tmp >>= 7;
    }
    msgToSign[msgLen++] = (BYTE)tmp;
    
    // Добавляем наш порт
    tmp = m_ourPortInTree;
    while (tmp >= 0x80) {
        msgToSign[msgLen++] = (BYTE)((tmp & 0x7F) | 0x80);
        tmp >>= 7;
    }
    msgToSign[msgLen++] = (BYTE)tmp;
    
    wsprintf(debug, L"[ANNOUNCE] Signing %d bytes", msgLen);
    AddLog(debug, LOG_DEBUG);
    
    // Подписываем нашим приватным ключом
    BYTE expandedSk[64];
    memcpy(expandedSk, core->GetKeys().privateKey, 32);
    memcpy(expandedSk + 32, ourPub, 32);
    
    BYTE signedBuf[256];
    unsigned int signedLen = 0;
    
    DWORD signStart = GetTickCount();
    int signRes = crypto_sign(signedBuf, &signedLen, msgToSign, msgLen, expandedSk);
    DWORD signTime = GetTickCount() - signStart;
    
    if (signRes != 0 || signedLen < 64) {
        wsprintf(debug, L"[ANNOUNCE] Signing failed! res=%d, len=%u, time=%lums", signRes, signedLen, signTime);
        AddLog(debug, LOG_ERROR);
        return false;
    }
    
    wsprintf(debug, L"[ANNOUNCE] Signed in %lums", signTime);
    AddLog(debug, LOG_INFO);
    
    // 7. Наша подпись (первые 64 байта)
    packet.insert(packet.end(), signedBuf, signedBuf + 64);
    
    wsprintf(debug, L"[ANNOUNCE] Payload size: %d bytes", packet.size());
    AddLog(debug, LOG_INFO);
    
    // Отправка с varint длиной в начале
    BYTE lenBuf[10];
    int lenPos = 0;
    unsigned long long lenVar = packet.size(); 
    
    while (lenVar >= 0x80) {
        lenBuf[lenPos++] = (BYTE)((lenVar & 0x7F) | 0x80);
        lenVar >>= 7;
    }
    lenBuf[lenPos++] = (BYTE)lenVar;
    
    packet.insert(packet.begin(), lenBuf, lenBuf + lenPos);
    
    int sent = send(m_socket, (char*)&packet[0], packet.size(), 0);
    if (sent != (int)packet.size()) {
        AddLog(L"[ANNOUNCE] Send failed", LOG_ERROR);
        return false;
    }
    
    AddLog(L"[ANNOUNCE] Sent successfully", LOG_SUCCESS);
    return true;
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ПУТЕЙ
// ============================================================================

string IronPeer::GetKeyPrefix(const BYTE* key) {
    // Возвращает hex-строку первых 16 байт ключа (32 символа)
    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i * 2, "%02x", key[i]);
    }
    hex[32] = '\0';
    return string(hex);
}

void IronPeer::GetEdSeed(BYTE* outSeed) {
    // Ed25519 seed - первые 32 байта приватного ключа (expanded format)
    if (m_ourEdPriv && m_ourEdPriv[0] != 0) {
        memcpy(outSeed, m_ourEdPriv, 32);
    } else {
        memset(outSeed, 0, 32);
    }
}

bool IronPeer::SignEd25519(const BYTE* seed, const BYTE* data, DWORD dataLen, BYTE* signature) {
    // Расширяем seed до полного приватного ключа
    BYTE expandedSk[64];
    memcpy(expandedSk, seed, 32);
    // Вторая половина - публичный ключ
    if (m_ourEdPub) {
        memcpy(expandedSk + 32, m_ourEdPub, 32);
    } else {
        memset(expandedSk + 32, 0, 32);
    }
    
    BYTE signedBuf[256];
    unsigned int signedLen = 0;
    
    int signRes = crypto_sign(signedBuf, &signedLen, data, dataLen, expandedSk);
    
    if (signRes != 0 || signedLen < 64) {
        return false;
    }
    
    memcpy(signature, signedBuf, 64);
    return true;
}

vector<BYTE> IronPeer::GetOurPathFromRoot() {
    WCHAR debug[256];
    
    // Если есть глобальные координаты и они длиннее 1 байта - возвращаем их
    if (m_myGlobalCoords.size() > 1) {
        wsprintf(debug, L"[GetOurPathFromRoot] Using global coords, size=%d", m_myGlobalCoords.size());
        AddLog(debug, LOG_DEBUG);
        return m_myGlobalCoords;
    }
    
    AddLog(L"[GetOurPathFromRoot] Building from routing table...", LOG_DEBUG);
    
    // Иначе строим путь из таблицы маршрутизации
    vector<unsigned long long> ports;
    BYTE currentKey[32];
    memcpy(currentKey, m_remoteKey, 32);
    
    EnterCriticalSection(&m_routingLock);
    
    for (int i = 0; i < 15; i++) {
        string prefix = GetKeyPrefix(currentKey);
        map<string, NodeRoute>::iterator it = m_routingTable.find(prefix);
        if (it == m_routingTable.end()) break;
        
        NodeRoute& route = it->second;
        if (route.port > 0) {
            ports.push_back(route.port);
        }
        
        // Проверяем наличие родительского ключа
        bool hasParent = false;
        for (int j = 0; j < 32; j++) {
            if (route.parentKey[j] != 0) {
                hasParent = true;
                break;
            }
        }
        
        if (!hasParent || memcmp(route.parentKey, currentKey, 32) == 0) break;
        memcpy(currentKey, route.parentKey, 32);
    }
    
    LeaveCriticalSection(&m_routingLock);
    
    // Разворачиваем порты (от корня к нам)
    vector<BYTE> result;
    for (int i = ports.size() - 1; i >= 0; i--) {
        WriteUvarint(result, ports[i]);
    }
    
    // Добавляем наш порт в дереве
    if (m_ourPortInTree != (unsigned long long)-1 && m_ourPortInTree != 0) {
        WriteUvarint(result, m_ourPortInTree);
    }
    
    // Завершаем нулём
    result.push_back(0);
    
    wsprintf(debug, L"[GetOurPathFromRoot] Built path size=%d from %d ports", result.size(), ports.size());
    AddLog(debug, LOG_DEBUG);
    
    return result;
}

// ============================================================================
// PATH_LOOKUP (0x06) - Обработка входящего поиска пути
// ============================================================================

void IronPeer::HandlePathLookup(const BYTE* packet, DWORD len) {
    if (!m_bConnected || len < 65) return;
    if (!m_ourEdPub) {
        AddLog(L"[PATH_LOOKUP] Keys not set!", LOG_ERROR);
        return;
    }
    
    AddLog(L"[PATH_LOOKUP] Received", LOG_DEBUG);
    
    const BYTE* p = packet + 1;  // Пропускаем тип
    DWORD remaining = len - 1;
    
    // Читаем ключ удаленной ноды (32 байта)
    BYTE remoteNodeKey[32];
    if (remaining < 32) return;
    memcpy(remoteNodeKey, p, 32); p += 32; remaining -= 32;
    
    // Читаем целевой ключ (32 байта)
    BYTE targetKey[32];
    if (remaining < 32) return;
    memcpy(targetKey, p, 32); p += 32; remaining -= 32;
    
    // Отладка: показываем ключи
    WCHAR debug[256];
    WCHAR targetHex[33] = {0}, ourHex[33] = {0};
    for (int i = 0; i < 16; i++) {
        WCHAR b[4];
        wsprintf(b, L"%02x", targetKey[i]);
        wcscat(targetHex, b);
    }
    for (int i = 0; i < 16; i++) {
        WCHAR b[4];
        wsprintf(b, L"%02x", m_ourEdPub[i]);
        wcscat(ourHex, b);
    }
    
    wsprintf(debug, L"[PATH_LOOKUP] Target prefix: %s", targetHex);
    AddLog(debug, LOG_INFO);
    wsprintf(debug, L"[PATH_LOOKUP] Our prefix: %s", ourHex);
    AddLog(debug, LOG_INFO);
    
    // Проверяем, запрос к нам?
    // Клиент знает только первые 113 бит (14 байт + 1 бит)
    // 15-й байт в targetKey заполнен 7f (0111 1111), т.к. биты 114-128 неизвестны
    // Сравниваем по 14 байтам (112 бит) + проверяем старший бит 15-го байта
    if (memcmp(targetKey, m_ourEdPub, 14) != 0) {
        AddLog(L"[PATH_LOOKUP] Prefix mismatch (first 14 bytes)", LOG_DEBUG);
        return;
    }
    
    // Проверяем старший бит 15-го байта (113-й бит ключа)
    // В targetKey 15-й байт = 0x7F (0111 1111), в нашем ключе он может быть другим
    // Но старший бит должен совпадать (0 в данном случае)
    if ((targetKey[14] & 0x80) != (m_ourEdPub[14] & 0x80)) {
        AddLog(L"[PATH_LOOKUP] Bit 113 mismatch", LOG_DEBUG);
        return;
    }
    
    AddLog(L"[PATH_LOOKUP] For us! Responding with PATH_NOTIFY...", LOG_SUCCESS);
    
    // Читаем обратный путь (varints ending with 0)
    vector<BYTE> backPath;
    while (remaining > 0) {
        unsigned long long port = 0;
        int shift = 0;
        bool ok = false;
        
        while (remaining > 0) {
            BYTE b = *p++;
            remaining--;
            port |= (unsigned long long)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) {
                ok = true;
                break;
            }
        }
        
        if (!ok) break;
        
        WriteUvarint(backPath, port);
        if (port == 0) break;
    }
    
    // Формируем ответ PATH_NOTIFY
    // Получаем наши координаты от корня
    vector<BYTE> ourCoords = GetOurPathFromRoot();
    
    // Подписываем сообщение: seq + ourCoords
    BYTE seed[32];
    GetEdSeed(seed);
    
    long long timestamp = GetTickCount() / 1000;
    vector<BYTE> toSign;
    WriteUvarint(toSign, timestamp);
    toSign.insert(toSign.end(), ourCoords.begin(), ourCoords.end());
    
    BYTE signature[64];
    if (!SignEd25519(seed, &toSign[0], toSign.size(), signature)) {
        AddLog(L"[PATH_LOOKUP] Signing failed", LOG_ERROR);
        return;
    }
    
    // Формируем PATH_NOTIFY пакет
    vector<BYTE> notify;
    notify.push_back(WIRE_PATH_NOTIFY);
    
    // Обратный путь
    notify.insert(notify.end(), backPath.begin(), backPath.end());
    
    // 64 (varint)
    WriteUvarint(notify, 64);
    
    // Наш публичный ключ
    notify.insert(notify.end(), m_ourEdPub, m_ourEdPub + 32);
    
    // Ключ удаленной ноды (кто запрашивал)
    notify.insert(notify.end(), remoteNodeKey, remoteNodeKey + 32);
    
    // Seq (timestamp)
    WriteUvarint(notify, timestamp);
    
    // Наши координаты
    notify.insert(notify.end(), ourCoords.begin(), ourCoords.end());
    
    // Подпись
    notify.insert(notify.end(), signature, signature + 64);
    
    // Отправляем
    SendPacket(WIRE_PATH_NOTIFY, &notify[1], notify.size() - 1);
    
    AddLog(L"[PATH_LOOKUP] Sent PATH_NOTIFY response", LOG_SUCCESS);

    // Если отправитель запрашивал нас, значит наш BLOOM до него дошёл.
    // Проверяем — есть ли у нас pending session для этого узла.
    // Если да — он уже знает нас, повторяем PATH_LOOKUP к нему.
    {
        BYTE senderIPv6[16];
        YggCrypto::DeriveIPv6(senderIPv6, remoteNodeKey);

        bool hasPending = false;
        EnterCriticalSection(&m_pendingLock);
        for (size_t i = 0; i < m_pendingSessions.size(); i++) {
            const BYTE* tgt = m_pendingSessions[i].targetIPv6;
            if (memcmp(tgt, senderIPv6, 16) == 0 ||
                (senderIPv6[0] == 0x02 && memcmp(&tgt[1], &senderIPv6[1], 7) == 0)) {
                hasPending = true;
                break;
            }
        }
        LeaveCriticalSection(&m_pendingLock);

        if (hasPending) {
            // Сбрасываем throttle чтобы можно было послать повторно
            string prefix = GetKeyPrefix(remoteNodeKey);
            EnterCriticalSection(&m_routingLock);
            m_recentPathLookups.erase(prefix);
            LeaveCriticalSection(&m_routingLock);

            AddLog(L"[PATH_LOOKUP] Sender has pending session - retrying PATH_LOOKUP to them", LOG_INFO);
            SendPathLookup(remoteNodeKey);
        }
    }
}

// ============================================================================
// PATH_NOTIFY (0x07) - Обработка ответа с путем
// ============================================================================

void IronPeer::HandlePathNotify(const BYTE* packet, DWORD len) {
    if (!m_bConnected || len < 64) return;
    
    WCHAR debug[256];
    AddLog(L"[PATH_NOTIFY] Received", LOG_DEBUG);
    
    const BYTE* p = packet + 1;
    DWORD remaining = len - 1;

    // Формат pathNotify (Go):
    // path (varints, 0-term) — путь для роутинга пакета
    // watermark (varint)
    // source (32 байта)     — ключ ответившего узла (targetFullKey)
    // dest (32 байта)       — наш ключ (ourKeyCheck)
    // info.seq (varint)
    // info.path (varints, 0-term) — координаты источника (serverCoords)
    // info.sig (64 байта)

    // 1. Читаем path (varints до 0) — роутинговый путь, сохраняем как myGlobalCoords
    vector<BYTE> myPath;
    while (remaining > 0) {
        unsigned long long port = 0;
        int shift = 0;
        bool ok = false;
        while (remaining > 0) {
            BYTE b = *p++; remaining--;
            port |= (unsigned long long)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) { ok = true; break; }
        }
        if (!ok) break;
        WriteUvarint(myPath, port);
        if (port == 0) break;
    }
    m_myGlobalCoords = myPath;
    wsprintf(debug, L"[PATH_NOTIFY] My global coords saved, size=%d", myPath.size());
    AddLog(debug, LOG_SUCCESS);

    // 2. Пропускаем watermark (varint)
    while (remaining > 0) {
        BYTE b = *p++; remaining--;
        if (!(b & 0x80)) break;
    }

    // 3. Читаем source (32 байта) — это ключ ответившего узла
    if (remaining < 32) return;
    BYTE targetFullKey[32];
    memcpy(targetFullKey, p, 32); p += 32; remaining -= 32;

    // 4. Читаем dest (32 байта) — должно совпадать с нашим ключом
    if (remaining < 32) return;
    BYTE ourKeyCheck[32];
    memcpy(ourKeyCheck, p, 32); p += 32; remaining -= 32;

    if (m_ourEdPub && memcmp(ourKeyCheck, m_ourEdPub, 32) != 0) {
        AddLog(L"[PATH_NOTIFY] Key check failed, not for us", LOG_WARN);
        return;
    }

    // 5. Пропускаем info.seq (varint)
    while (remaining > 0) {
        BYTE b = *p++; remaining--;
        if (!(b & 0x80)) break;
    }

    // 6. Читаем info.path (varints до 0) — координаты источника
    vector<BYTE> serverCoords;
    while (remaining > 0) {
        unsigned long long port = 0;
        int shift = 0;
        bool ok = false;
        while (remaining > 0) {
            BYTE b = *p++; remaining--;
            port |= (unsigned long long)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) { ok = true; break; }
        }
        if (!ok) break;
        WriteUvarint(serverCoords, port);
        if (port == 0) break;
    }
    // info.sig (64 байта) — не используем, оставшиеся байты
    
    // Сохраняем в таблицу маршрутизации (используем путь из PATH_NOTIFY - serverCoords)
    string prefix = GetKeyPrefix(targetFullKey);
    NodeRoute route(targetFullKey, serverCoords, NULL, 0);
    
    EnterCriticalSection(&m_routingLock);
    m_routingTable[prefix] = route;
    LeaveCriticalSection(&m_routingLock);
    
    wsprintf(debug, L"[PATH_NOTIFY] Added route for %S, path len=%d", prefix.c_str(), serverCoords.size());
    AddLog(debug, LOG_SUCCESS);
    
    // Проверяем есть ли ожидающие сессии для этого IPv6
    // Используем полный ключ из PATH_NOTIFY для создания сессии
    WCHAR targetHexW[65];
    for (int i = 0; i < 32; i++) {
        wsprintf(targetHexW + i*2, L"%02x", targetFullKey[i]);
    }
    targetHexW[64] = 0;
    wsprintf(debug, L"[PATH_NOTIFY] Full target key: %s", targetHexW);
    AddLog(debug, LOG_DEBUG);
    
    // Ищем pending sessions по IPv6 (первые 14 байт + бит)
    // IPv6 содержит только 113 бит ключа
    // Используем полный ключ из PATH_NOTIFY для создания сессии
    CheckPendingSessionsWithFullKey(targetFullKey, serverCoords);
}

void IronPeer::HandleTraffic(const BYTE* packet, DWORD len) {
    if (!m_bConnected) return;
    
    WCHAR debug[256];
    wsprintf(debug, L"[TRAFFIC] Received %lu bytes", len);
    AddLog(debug, LOG_DEBUG);
    
    // Дамп первых 32 байт
    wsprintf(debug, L"[TRAFFIC] Dump: ");
    for (int i = 0; i < 32 && i < (int)len; i++) {
        wsprintf(debug + wcslen(debug), L"%02x", packet[i]);
    }
    AddLog(debug, LOG_DEBUG);
    
    if (len < 64) {
        wsprintf(debug, L"[TRAFFIC] Packet too short: %lu bytes", len);
        AddLog(debug, LOG_WARN);
        return;
    }
    
    // Парсим WIRE_TRAFFIC пакет
    // [path (varints 0-terminated)]
    // [0]  // switch
    // [src key 32]
    // [dst key 32]
    // [len varint]
    // [session packet]
    
    DWORD pos = 1;  // пропускаем тип пакета
    DWORD remaining = len - 1;
    
    // Пропускаем path (varints пока не встретим 0)
    while (remaining > 0 && pos < len) {
        BYTE b = packet[pos++];
        remaining--;
        if (b == 0) break;
        if (b & 0x80) {
            while (remaining > 0 && (packet[pos] & 0x80)) {
                pos++;
                remaining--;
            }
            if (remaining > 0) {
                pos++;
                remaining--;
            }
        }
    }
    
    // Пропускаем switch port (varints пока не встретим 0)
    while (remaining > 0 && pos < len) {
        BYTE b = packet[pos++];
        remaining--;
        if (b == 0) break;
        if (b & 0x80) {
            while (remaining > 0 && (packet[pos] & 0x80)) {
                pos++;
                remaining--;
            }
            if (remaining > 0) {
                pos++;
                remaining--;
            }
        }
    }
    
    if (remaining < 64) {
        AddLog(L"[TRAFFIC] Packet too short for keys", LOG_ERROR);
        return;
    }
    
    // Читаем src key (32 bytes)
    BYTE srcKey[32];
    memcpy(srcKey, packet + pos, 32);
    pos += 32;
    remaining -= 32;
    
    // Читаем dst key (32 bytes)
    BYTE dstKey[32];
    memcpy(dstKey, packet + pos, 32);
    pos += 32;
    remaining -= 32;
    
    // Проверяем, что пакет для нас
    if (m_ourEdPub && memcmp(dstKey, m_ourEdPub, 32) != 0) {
        // Debug: показываем ключи
        string dstHex = GetKeyPrefix(dstKey);
        string ourHex = GetKeyPrefix(m_ourEdPub);
        wsprintf(debug, L"[TRAFFIC] Not for us - dst: %S, our: %S", 
                 dstHex.c_str(), ourHex.c_str());
        AddLog(debug, LOG_DEBUG);
        return;
    }
    
    wsprintf(debug, L"[TRAFFIC] For us! pos=%lu, remaining=%lu", pos, remaining);
    AddLog(debug, LOG_DEBUG);
    
    // Пропускаем один varint (как в Java: CryptoUtils.readUvarint(dis))
    if (remaining < 1) return;
    while (remaining > 0) {
        BYTE b = packet[pos++];
        remaining--;
        if (!(b & 0x80)) break;
    }
    
    // Session packet - всё оставшееся (как в Java: dis.readAllBytes())
    const BYTE* sessionPacket = packet + pos;
    DWORD sessionLen = remaining;
    
    // Определяем тип сессии
    int sessionType = sessionPacket[0] & 0xFF;
    
    wsprintf(debug, L"[TRAFFIC] Session type: 0x%02x (%s)", sessionType,
             sessionType == 0x01 ? L"INIT" : (sessionType == 0x02 ? L"ACK" : (sessionType == 0x03 ? L"TRAFFIC" : L"UNKNOWN")));
    AddLog(debug, LOG_INFO);
    
    string srcHex = GetKeyPrefix(srcKey);
    
    EnterCriticalSection(&m_sessionsLock);
    
    // Ищем сессию
    IronSession* session = NULL;
    for (size_t i = 0; i < m_sessions.size(); i++) {
        if (memcmp(m_sessions[i]->GetRemoteKey(), srcKey, 32) == 0) {
            session = m_sessions[i];
            session->AddRef();
            break;
        }
    }
    
    LeaveCriticalSection(&m_sessionsLock);
    
    switch (sessionType) {
        case SESSION_INIT:
        case SESSION_ACK: {
            wsprintf(debug, L"[TRAFFIC] Session %s from %S", 
                     sessionType == SESSION_INIT ? L"INIT" : L"ACK", srcHex.c_str());
            AddLog(debug, LOG_INFO);
            
            if (!session) {
                // Создаем новую сессию
                session = new IronSession(srcKey, 0, 1);
                session->Initialize();

                EnterCriticalSection(&m_sessionsLock);
                m_sessions.push_back(session);
                LeaveCriticalSection(&m_sessionsLock);
            }

            // Обрабатываем INIT/ACK асинхронно — Ed25519 + шифрование занимает 2-4 сек на ARM,
            // блокируя receive-поток и не давая читать входящие пакеты (SYN-ACK и др.)
            {
                struct HandshakeArgs {
                    IronSession* session;
                    IronPeer* peer;
                    vector<BYTE> packetData;
                    int sessionType;
                    BYTE srcKey[32];
                };
                HandshakeArgs* hargs = new HandshakeArgs;
                hargs->session = session;
                session->AddRef(); // поток освободит через Release()
                hargs->peer = this;
                hargs->packetData.assign(sessionPacket, sessionPacket + sessionLen);
                hargs->sessionType = sessionType;
                memcpy(hargs->srcKey, srcKey, 32);

                struct Local {
                    static DWORD WINAPI HandshakeThreadProc(LPVOID lpParam) {
                        HandshakeArgs* a = (HandshakeArgs*)lpParam;
                        a->session->HandleSessionHandshake(
                            &a->packetData[0], a->packetData.size(),
                            a->sessionType, a->srcKey, a->peer);
                        a->session->Release();
                        delete a;
                        return 0;
                    }
                };
                HANDLE hT = CreateThread(NULL, 0, Local::HandshakeThreadProc, hargs, 0, NULL);
                if (hT) {
                    SetThreadPriority(hT, THREAD_PRIORITY_BELOW_NORMAL);
                    CloseHandle(hT);
                } else {
                    // Fallback — синхронно если поток не создался
                    session->HandleSessionHandshake(sessionPacket, sessionLen, sessionType, srcKey, this);
                    session->Release();
                    delete hargs;
                }
                session = NULL; // session уже owned by thread
            }
            break;
        }
        
        case SESSION_TRAFFIC: {
            if (session) {
                session->HandleSessionTraffic(sessionPacket, sessionLen, this);
                session->Release();
            } else {
                wsprintf(debug, L"[TRAFFIC] No session for %S, dropping", srcHex.c_str());
                AddLog(debug, LOG_WARN);
            }
            return;  // session уже released выше для TRAFFIC
        }
        
        default: {
            wsprintf(debug, L"[TRAFFIC] Unknown session type: 0x%02x", sessionType);
            AddLog(debug, LOG_WARN);
            break;
        }
    }
    
    if (session) {
        session->Release();
    }
}

// ============================================================================
// ПОТОКИ
// ============================================================================

DWORD WINAPI IronPeer::ReceiveThreadProc(LPVOID lpParam) {
    IronPeer* pThis = (IronPeer*)lpParam;
    BYTE buffer[8192];
    DWORD received;
    
    AddLog(L"[Thread] Receive thread started", LOG_DEBUG);
    
    while (pThis->m_bConnected) {
        if (!pThis->ReceivePacket(buffer, sizeof(buffer), received)) {
            if (pThis->m_bConnected) {
                AddLog(L"[Thread] Receive failed", LOG_ERROR);
                pThis->m_bConnected = false;
            }
            break;
        }
        
        if (received > 0) {
            pThis->HandleReceivedData(buffer, received);
        }
    }
    
    AddLog(L"[Thread] Receive thread ended", LOG_WARN);
    return 0;
}

DWORD WINAPI IronPeer::KeepaliveThreadProc(LPVOID lpParam) {
    IronPeer* pThis = (IronPeer*)lpParam;
    int failCount = 0;
    const int MAX_FAILS = 3;
    DWORD lastKeepalive = GetTickCount();
    DWORD lastSigReq = GetTickCount();

    AddLog(L"[Keepalive] Thread started", LOG_DEBUG);

    // Отправляем первый keepalive сразу
    if (pThis->m_bConnected) {
        pThis->SendKeepAlive();
    }

    while (pThis->m_bConnected) {
        Sleep(50);

        if (!pThis->m_bConnected) break;

        DWORD now = GetTickCount();

        // Периодический SIG_REQ каждые 60 секунд — сбрасывает routerTimeout на стороне пира
        if ((now - lastSigReq) >= 60000) {
            lastSigReq = now;
            if (pThis->m_bConnected) {
                AddLog(L"[Keepalive] Sending periodic SIG_REQ", LOG_DEBUG);
                pThis->SendSigReq();
            }
        }

        // Keepalive каждые 1500ms
        if ((now - lastKeepalive) < 1500) continue;
        lastKeepalive = now;

        if (!pThis->SendKeepAlive()) {
            failCount++;
            WCHAR debug[256];
            wsprintf(debug, L"[Keepalive] Failed (%d/%d)", failCount, MAX_FAILS);
            AddLog(debug, LOG_WARN);

            if (failCount >= MAX_FAILS) {
                AddLog(L"[Keepalive] Too many failures, closing connection", LOG_ERROR);
                pThis->m_bConnected = false;
                break;
            }
        } else {
            failCount = 0;
        }
    }
    
    AddLog(L"[Keepalive] Thread ended", LOG_DEBUG);

    // Уведомляем UI об обрыве — запустит автопереподключение
    if (g_hWnd) PostMessage(g_hWnd, WM_PEER_DISCONNECTED, 0, 0);

    return 0;
}

// ============================================================================
// АСИНХРОННАЯ ОТПРАВКА SESSION_INIT
// ============================================================================

DWORD WINAPI IronPeer::SessionInitThreadProc(LPVOID lpParam) {
    struct SessionInitArgs {
        IronSession* session;
        IronPeer* peer;
        vector<BYTE> path;
    };
    
    SessionInitArgs* args = (SessionInitArgs*)lpParam;
    if (!args) return 1;
    
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION_INIT_ASYNC] Starting for session...");
    AddLog(debug, LOG_INFO);
    
    bool sent = args->session->SendSessionInit(args->peer, args->path);
    
    wsprintf(debug, L"[PENDING_FULL] SESSION_INIT sent: %s", sent ? L"SUCCESS" : L"FAILED");
    AddLog(debug, sent ? LOG_SUCCESS : LOG_ERROR);
    
    delete args;
    return 0;
}

// ============================================================================
// УПРАВЛЕНИЕ СЕССИЯМИ
// ============================================================================

IronSession* IronPeer::CreateSession(const BYTE* remoteKey, DWORD port) {
    IronSession* session = new IronSession(remoteKey, port, 1);
    if (!session) return NULL;
    
    if (!session->Initialize()) {
        session->Release();
        return NULL;
    }
    
    EnterCriticalSection(&m_sessionsLock);
    m_sessions.push_back(session);
    LeaveCriticalSection(&m_sessionsLock);
    
    return session;
}

IronSession* IronPeer::GetOrCreateSession(const BYTE* remoteKey, DWORD port) {
    EnterCriticalSection(&m_sessionsLock);
    
    for (size_t i = 0; i < m_sessions.size(); i++) {
        if (memcmp(m_sessions[i]->GetRemoteKey(), remoteKey, 32) == 0) {
            IronSession* session = m_sessions[i];
            session->AddRef();
            LeaveCriticalSection(&m_sessionsLock);
            return session;
        }
    }
    
    LeaveCriticalSection(&m_sessionsLock);
    
    // Создаем новую сессию
    return CreateSession(remoteKey, port);
}

IronSession* IronPeer::GetSession(const BYTE* remoteKey) {
    EnterCriticalSection(&m_sessionsLock);
    
    for (size_t i = 0; i < m_sessions.size(); i++) {
        if (memcmp(m_sessions[i]->GetRemoteKey(), remoteKey, 32) == 0) {
            IronSession* session = m_sessions[i];
            session->AddRef();
            LeaveCriticalSection(&m_sessionsLock);
            return session;
        }
    }
    
    LeaveCriticalSection(&m_sessionsLock);
    return NULL;
}

IronSession* IronPeer::GetSessionByIPv6(const BYTE* ipv6) {
    EnterCriticalSection(&m_sessionsLock);
    
    IronSession* bestSession = NULL;
    
    // Идем с конца (свежие сессии в конце списка)
    for (int i = (int)m_sessions.size() - 1; i >= 0; i--) {
        const BYTE* sessionIPv6 = m_sessions[i]->GetRemoteIPv6();

        // Сравниваем с учетом subnet /64:
        // - точный /128 если оба 0x02
        // - subnet /64 (байты 1..7) если ищем 0x02 (нормализованный из 0x03) и сессия 0x02
        bool match = false;
        if (sessionIPv6[0] == 0x02 && ipv6[0] == 0x02) {
            if (memcmp(sessionIPv6, ipv6, 16) == 0) {
                match = true;
            } else if (memcmp(&sessionIPv6[1], &ipv6[1], 7) == 0) {
                // subnet /64 — узел владеет этой подсетью
                match = true;
            }
        }

        if (match) {
            IronSession* s = m_sessions[i];
            // Предпочитаем CLOSED/FIN_WAIT (свободные для нового TCP) над ESTABLISHED/SYN_SENT
            if (s->GetTcpState() == TCP_CLOSED || s->GetTcpState() == TCP_FIN_WAIT) {
                bestSession = s;
                break;
            } else if (!bestSession) {
                bestSession = s;
            }
        }
    }
    
    if (bestSession) {
        bestSession->AddRef();
        LeaveCriticalSection(&m_sessionsLock);
        return bestSession;
    }
    
    LeaveCriticalSection(&m_sessionsLock);
    // Note: removed verbose debug log
    return NULL;
}

void IronPeer::CloseSession(const BYTE* remoteKey) {
    EnterCriticalSection(&m_sessionsLock);
    
    for (vector<IronSession*>::iterator it = m_sessions.begin(); it != m_sessions.end(); ) {
        if (memcmp((*it)->GetRemoteKey(), remoteKey, KEY_SIZE) == 0) {
            (*it)->Close();
            (*it)->Release();
            it = m_sessions.erase(it);
        } else {
            ++it;
        }
    }
    
    LeaveCriticalSection(&m_sessionsLock);
}

bool IronPeer::SendSessionInit(IronSession* session, const vector<BYTE>& path) {
    if (!session) return false;
    return session->SendSessionInit(this, path);
}

bool IronPeer::SendSessionAck(IronSession* session, const vector<BYTE>& path) {
    if (!session) return false;
    return session->SendSessionAck(this, path);
}

bool IronPeer::SendSessionTraffic(IronSession* session, const vector<BYTE>& path, 
                                   const BYTE* data, DWORD len) {
    if (!session) return false;
    return session->SendTraffic(this, path, data, len);
}

// ============================================================================
// ОТПРАВКА PATH_LOOKUP (0x06)
// ============================================================================

bool IronPeer::SendPathLookup(const BYTE* targetKey) {
    if (!m_bConnected || !m_ourEdPub) return false;
    
    // Проверяем не отправляли ли мы недавно PATH_LOOKUP для этого ключа
    string prefix = GetKeyPrefix(targetKey);
    DWORD now = GetTickCount();
    
    EnterCriticalSection(&m_routingLock);
    map<string, DWORD>::iterator it = m_recentPathLookups.find(prefix);
    if (it != m_recentPathLookups.end()) {
        // Если прошло меньше 5 секунд - не отправляем повторно
        if ((now - it->second) < 5000) {
            LeaveCriticalSection(&m_routingLock);
            AddLog(L"[PATH_LOOKUP] Duplicate suppressed (recent)", LOG_DEBUG);
            return true; // Возвращаем true чтобы не было ошибки
        }
    }
    // Обновляем время последнего запроса
    m_recentPathLookups[prefix] = now;
    LeaveCriticalSection(&m_routingLock);
    
    // Получаем наши координаты от корня
    vector<BYTE> ourPath = GetOurPathFromRoot();
    
    // Формируем пакет PATH_LOOKUP
    vector<BYTE> packet;
    packet.push_back(WIRE_PATH_LOOKUP);
    
    // Наш публичный ключ (remoteNodeKey)
    packet.insert(packet.end(), m_ourEdPub, m_ourEdPub + 32);
    
    // Целевой ключ
    packet.insert(packet.end(), targetKey, targetKey + 32);
    
    // Путь (наши координаты)
    packet.insert(packet.end(), ourPath.begin(), ourPath.end());
    
    return SendPacket(WIRE_PATH_LOOKUP, &packet[1], packet.size() - 1);
}

// ============================================================================
// УПРАВЛЕНИЕ ТАБЛИЦЕЙ МАРШРУТИЗАЦИИ
// ============================================================================

NodeRoute* IronPeer::GetRoute(const string& prefix) {
    EnterCriticalSection(&m_routingLock);
    map<string, NodeRoute>::iterator it = m_routingTable.find(prefix);
    NodeRoute* result = NULL;
    if (it != m_routingTable.end()) {
        // Возвращаем копию - нужно выделить память
        result = new NodeRoute(it->second);
    }
    LeaveCriticalSection(&m_routingLock);
    return result;
}

void IronPeer::UpdateRoute(const string& prefix, const NodeRoute& route) {
    EnterCriticalSection(&m_routingLock);
    m_routingTable[prefix] = route;
    LeaveCriticalSection(&m_routingLock);
}

// ============================================================================
// АСИНХРОННАЯ РАБОТА С СЕССИЯМИ (ожидание PATH_NOTIFY)
// ============================================================================

void IronPeer::AddPendingSession(const BYTE* targetKey, const BYTE* targetIPv6, int targetPort) {
    EnterCriticalSection(&m_pendingLock);
    
    // Проверяем нет ли уже такой сессии по IPv6
    for (size_t i = 0; i < m_pendingSessions.size(); i++) {
        if (memcmp(m_pendingSessions[i].targetIPv6, targetIPv6, 16) == 0) {
            // Обновляем порт
            m_pendingSessions[i].targetPort = targetPort;
            m_pendingSessions[i].createdTime = GetTickCount();
            LeaveCriticalSection(&m_pendingLock);
            return;
        }
    }
    
    // Добавляем новую
    m_pendingSessions.push_back(PendingSession(targetKey, targetIPv6, targetPort));
    
    WCHAR debug[256];
    wsprintf(debug, L"[PENDING] Added session for IPv6 %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             targetIPv6[0], targetIPv6[1], targetIPv6[2], targetIPv6[3],
             targetIPv6[4], targetIPv6[5], targetIPv6[6], targetIPv6[7],
             targetIPv6[8], targetIPv6[9], targetIPv6[10], targetIPv6[11],
             targetIPv6[12], targetIPv6[13], targetIPv6[14], targetIPv6[15]);
    AddLog(debug, LOG_INFO);
    
    LeaveCriticalSection(&m_pendingLock);
}

// ============================================================================
// ПОИСК PENDING SESSIONS ПО ПОЛНОМУ КЛЮЧУ (для PATH_NOTIFY)
// ============================================================================

void IronPeer::CheckPendingSessionsWithFullKey(const BYTE* fullKey, const vector<BYTE>& path) {
    WCHAR debug[256];
    
    // Конвертируем полный ключ в IPv6 для сравнения
    BYTE derivedIPv6[16];
    YggCrypto::DeriveIPv6(derivedIPv6, fullKey);
    
    wsprintf(debug, L"[CHECK_PENDING_FULL] fullKey -> IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             derivedIPv6[0], derivedIPv6[1], derivedIPv6[2], derivedIPv6[3],
             derivedIPv6[4], derivedIPv6[5], derivedIPv6[6], derivedIPv6[7],
             derivedIPv6[8], derivedIPv6[9], derivedIPv6[10], derivedIPv6[11],
             derivedIPv6[12], derivedIPv6[13], derivedIPv6[14], derivedIPv6[15]);
    AddLog(debug, LOG_DEBUG);
    
    EnterCriticalSection(&m_pendingLock);
    
    wsprintf(debug, L"[CHECK_PENDING_FULL] Have %d pending sessions", m_pendingSessions.size());
    AddLog(debug, LOG_DEBUG);
    
    for (size_t i = 0; i < m_pendingSessions.size(); ) {
        // Сравниваем IPv6: оригинальный (который запрашивали) vs полученный из полного ключа
        // Случай 1: искали Node IP (200::/8, байт 0 == 0x02) — точное совпадение 16 байт
        // Случай 2: искали Subnet IP (300::/8, байт 0 == 0x03) — сравниваем байты 1..7 (/64 префикс)
        bool ipv6Match = false;
        const BYTE* tgt = m_pendingSessions[i].targetIPv6;
        if (derivedIPv6[0] == 0x02) {
            // Точный адрес узла /128 (искали 200:: узел)
            if (tgt[0] == 0x02 && memcmp(tgt, derivedIPv6, 16) == 0) {
                ipv6Match = true;
                AddLog(L"[CHECK_PENDING] Exact Node /128 match!", LOG_SUCCESS);
            }
            // Адрес из подсети узла — байты 1..7 совпадают (/64 префикс)
            // ParseIPv6 нормализует 0x03->0x02, поэтому tgt[0] всегда 0x02
            else if (memcmp(&tgt[1], &derivedIPv6[1], 7) == 0) {
                ipv6Match = true;
                AddLog(L"[CHECK_PENDING] Subnet /64 match! Node owns this IP.", LOG_SUCCESS);
            }
        }

        wsprintf(debug, L"[CHECK_PENDING_FULL] pending IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 tgt[0], tgt[1], tgt[2], tgt[3],
                 tgt[4], tgt[5], tgt[6], tgt[7],
                 tgt[8], tgt[9], tgt[10], tgt[11],
                 tgt[12], tgt[13], tgt[14], tgt[15]);
        AddLog(debug, LOG_DEBUG);

        wsprintf(debug, L"[CHECK_PENDING_FULL] ipv6Match=%d", ipv6Match);
        AddLog(debug, LOG_DEBUG);
        
        if (ipv6Match) {
            wsprintf(debug, L"[PENDING_FULL] Found matching session for port %d", m_pendingSessions[i].targetPort);
            AddLog(debug, LOG_SUCCESS);
            
            // Закрываем старые сессии к этому же адресу (чтобы не было путаницы)
            EnterCriticalSection(&m_sessionsLock);
            for (int j = m_sessions.size() - 1; j >= 0; j--) {
                if (memcmp(m_sessions[j]->GetRemoteKey(), fullKey, 16) == 0) {
                    // НЕ закрываем ESTABLISHED сессии
                    if (m_sessions[j]->GetTcpState() == TCP_ESTABLISHED && !m_sessions[j]->IsClosed()) {
                        AddLog(L"[PENDING_FULL] Keep existing ESTABLISHED session", LOG_DEBUG);
                        continue;
                    }
                    wsprintf(debug, L"[PENDING_FULL] Closing old session %d to same target", j);
                    AddLog(debug, LOG_DEBUG);
                    m_sessions[j]->Close();
                    m_sessions[j]->Release();
                    m_sessions.erase(m_sessions.begin() + j);
                }
            }
            LeaveCriticalSection(&m_sessionsLock);
            
            // Проверяем, нет ли уже ESTABLISHED сессии
            bool hasEstablished = false;
            for (size_t k = 0; k < m_sessions.size(); k++) {
                if (memcmp(m_sessions[k]->GetRemoteKey(), fullKey, 16) == 0 && 
                    m_sessions[k]->GetTcpState() == TCP_ESTABLISHED && !m_sessions[k]->IsClosed()) {
                    AddLog(L"[PENDING_FULL] Session already ESTABLISHED, skipping creation", LOG_INFO);
                    hasEstablished = true;
                    break;
                }
            }
            
            if (hasEstablished) {
                LeaveCriticalSection(&m_pendingLock);
                continue;
            }
            
            // Создаем сессию с ПОЛНЫМ ключом из PATH_NOTIFY
            IronSession* session = new IronSession(fullKey, m_pendingSessions[i].targetPort, 1);
            
            WCHAR debug2[256];
            wsprintf(debug2, L"[PENDING_FULL] Creating session with key[0..3]=%02x%02x%02x%02x, port=%d", 
                     fullKey[0], fullKey[1], fullKey[2], fullKey[3], m_pendingSessions[i].targetPort);
            AddLog(debug2, LOG_INFO);
            
            session->Initialize();
            
            EnterCriticalSection(&m_sessionsLock);
            m_sessions.push_back(session);
            LeaveCriticalSection(&m_sessionsLock);
            
            wsprintf(debug, L"[PENDING_FULL] Session created with full key, path len=%d", path.size());
            AddLog(debug, LOG_INFO);
            
            // Отправляем SESSION_INIT асинхронно (чтобы не блокировать receive thread!)
            LeaveCriticalSection(&m_pendingLock);
            
            // Создаем структуру для передачи в поток
            struct SessionInitArgs {
                IronSession* session;
                IronPeer* peer;
                vector<BYTE> path;
            };
            SessionInitArgs* args = new SessionInitArgs();
            args->session = session;
            args->peer = this;
            args->path = path;
            
            HANDLE hInitThread = CreateThread(NULL, 0, SessionInitThreadProc, args, 0, NULL);
            
            if (hInitThread) {
                SetThreadPriority(hInitThread, THREAD_PRIORITY_BELOW_NORMAL);
                CloseHandle(hInitThread);
                AddLog(L"[PENDING_FULL] SESSION_INIT started in background thread", LOG_INFO);
            } else {
                // Fallback - отправляем синхронно
                bool sent = session->SendSessionInit(this, path);
                wsprintf(debug, L"[PENDING_FULL] SESSION_INIT sent: %s", sent ? L"SUCCESS" : L"FAILED");
                AddLog(debug, sent ? LOG_SUCCESS : LOG_ERROR);
                delete args;
            }
            
            EnterCriticalSection(&m_pendingLock);
            
            // Удаляем из pending
            m_pendingSessions.erase(m_pendingSessions.begin() + i);
        } else {
            ++i;
        }
    }
    
    LeaveCriticalSection(&m_pendingLock);
}

void IronPeer::CheckPendingSessions(const string& prefix) {
    WCHAR debug[256];
    wsprintf(debug, L"[CHECK_PENDING] Looking for prefix: %S", prefix.c_str());
    AddLog(debug, LOG_DEBUG);
    
    EnterCriticalSection(&m_pendingLock);
    
    wsprintf(debug, L"[CHECK_PENDING] Have %d pending sessions", m_pendingSessions.size());
    AddLog(debug, LOG_DEBUG);
    
    for (size_t i = 0; i < m_pendingSessions.size(); ) {
        string sessionPrefix = GetKeyPrefix(m_pendingSessions[i].targetKey);
        
        wsprintf(debug, L"[CHECK_PENDING] Checking: %S vs %S", sessionPrefix.c_str(), prefix.c_str());
        AddLog(debug, LOG_DEBUG);
        
        // Сравниваем первые 14 байт + старший бит 15-го (113 бит как в IPv6)
        bool prefixMatch = (sessionPrefix.length() >= 30 && prefix.length() >= 30) &&
                           (memcmp(sessionPrefix.c_str(), prefix.c_str(), 28) == 0) &&
                           ((sessionPrefix[28] & 0x80) == (prefix[28] & 0x80));
        
        if (prefixMatch || sessionPrefix == prefix) {
            WCHAR debug[256];
            wsprintf(debug, L"[PENDING] Route found for %S, creating session", prefix.c_str());
            AddLog(debug, LOG_SUCCESS);
            
            // Закрываем старые сессии к этому адресу
            EnterCriticalSection(&m_sessionsLock);
            for (int j = m_sessions.size() - 1; j >= 0; j--) {
                if (memcmp(m_sessions[j]->GetRemoteKey(), m_pendingSessions[i].targetKey, 16) == 0) {
                    // НЕ закрываем ESTABLISHED сессии
                    if (m_sessions[j]->GetTcpState() == TCP_ESTABLISHED && !m_sessions[j]->IsClosed()) {
                        AddLog(L"[PENDING] Keep existing ESTABLISHED session", LOG_DEBUG);
                        continue;
                    }
                    wsprintf(debug, L"[PENDING] Closing old session %d to same target", j);
                    AddLog(debug, LOG_DEBUG);
                    m_sessions[j]->Close();
                    m_sessions[j]->Release();
                    m_sessions.erase(m_sessions.begin() + j);
                }
            }
            LeaveCriticalSection(&m_sessionsLock);
            
            // Создаем сессию
            IronSession* session = new IronSession(m_pendingSessions[i].targetKey, 
                                                    m_pendingSessions[i].targetPort, 1);
            session->Initialize();
            
            EnterCriticalSection(&m_sessionsLock);
            m_sessions.push_back(session);
            LeaveCriticalSection(&m_sessionsLock);
            
            // Получаем путь
            NodeRoute* route = GetRoute(prefix);
            vector<BYTE> path;
            if (route && route->path.size() > 0) {
                path = route->path;
                wsprintf(debug, L"[PENDING] Using path from route, len=%d", path.size());
                AddLog(debug, LOG_DEBUG);
                delete route;
            } else {
                path.push_back(0);
                AddLog(L"[PENDING] Using empty path", LOG_DEBUG);
            }
            
            // Отправляем SESSION_INIT
            LeaveCriticalSection(&m_pendingLock);
            bool sent = session->SendSessionInit(this, path);
            wsprintf(debug, L"[PENDING] SESSION_INIT sent: %s", sent ? L"SUCCESS" : L"FAILED");
            AddLog(debug, sent ? LOG_SUCCESS : LOG_ERROR);
            EnterCriticalSection(&m_pendingLock);
            
            // Удаляем из pending
            m_pendingSessions.erase(m_pendingSessions.begin() + i);
        } else {
            ++i;
        }
    }
    
    if (m_pendingSessions.empty()) {
        AddLog(L"[CHECK_PENDING] No matching sessions found", LOG_WARN);
    }
    
    LeaveCriticalSection(&m_pendingLock);
}

// ============================================================================
// ПРОВЕРКА НАЛИЧИЯ СЕССИИ
// ============================================================================

bool IronPeer::HasSession(IronSession* session) {
    if (!session) return false;
    
    EnterCriticalSection(&m_sessionsLock);
    for (size_t i = 0; i < m_sessions.size(); i++) {
        if (m_sessions[i] == session) {
            LeaveCriticalSection(&m_sessionsLock);
            return true;
        }
    }
    LeaveCriticalSection(&m_sessionsLock);
    return false;
}

// ============================================================================
// ПОЛУЧЕНИЕ PATH К КЛЮЧУ
// ============================================================================

bool IronPeer::GetPathToKey(const BYTE* key, vector<BYTE>& outPath) {
    string prefix = GetKeyPrefix(key);
    
    EnterCriticalSection(&m_routingLock);
    map<string, NodeRoute>::iterator it = m_routingTable.find(prefix);
    if (it != m_routingTable.end() && it->second.path.size() > 0) {
        outPath = it->second.path;
        LeaveCriticalSection(&m_routingLock);
        return true;
    }
    LeaveCriticalSection(&m_routingLock);
    
    // Пробуем найти по IPv6 (первые 16 байт)
    EnterCriticalSection(&m_routingLock);
    for (it = m_routingTable.begin(); it != m_routingTable.end(); ++it) {
        // Сравниваем первые 14 байт + старший бит 15-го
        if (memcmp(it->first.c_str(), prefix.c_str(), 28) == 0 &&
            ((it->first[28] & 0x80) == (prefix[28] & 0x80))) {
            outPath = it->second.path;
            LeaveCriticalSection(&m_routingLock);
            return true;
        }
    }
    LeaveCriticalSection(&m_routingLock);
    
    // Fallback - пустой path
    outPath.clear();
    outPath.push_back(0);
    return false;
}

bool IronPeer::GetPathToIPv6(const BYTE* ipv6, vector<BYTE>& outPath) {
    WCHAR debug[256];
    WCHAR ipv6Hex[40] = {0};
    for (int i = 0; i < 16; i++) wsprintf(ipv6Hex + i*2, L"%02x", ipv6[i]);
    wsprintf(debug, L"[GetPathToIPv6] Looking for path to %s", ipv6Hex);
    AddLog(debug, LOG_DEBUG);
    
    // Ищем маршрут по IPv6 - для каждого маршрута выводим IPv6 из fullKey
    // и сравниваем с искомым IPv6
    EnterCriticalSection(&m_routingLock);
    wsprintf(debug, L"[GetPathToIPv6] Routing table size: %d", m_routingTable.size());
    AddLog(debug, LOG_DEBUG);
    
    for (map<string, NodeRoute>::iterator it = m_routingTable.begin(); 
         it != m_routingTable.end(); ++it) {
        // Выводим IPv6 из fullKey (Ed25519 public key)
        BYTE routeIPv6[16];
        YggCrypto::DeriveIPv6(routeIPv6, it->second.fullKey);
        
        bool match = false;
        if (routeIPv6[0] == 0x02 && ipv6[0] == 0x02) {
            if (memcmp(routeIPv6, ipv6, 16) == 0)
                match = true;
            else if (memcmp(&routeIPv6[1], &ipv6[1], 7) == 0)
                match = true; // subnet /64
        }
        if (match) {
            outPath = it->second.path;
            LeaveCriticalSection(&m_routingLock);
            wsprintf(debug, L"[GetPathToIPv6] FOUND path, size=%d", outPath.size());
            AddLog(debug, LOG_SUCCESS);
            return true;
        }
    }
    LeaveCriticalSection(&m_routingLock);
    
    // Fallback - пустой path
    outPath.clear();
    outPath.push_back(0);
    AddLog(L"[GetPathToIPv6] NOT FOUND, returning [0]", LOG_WARN);
    return false;
}
