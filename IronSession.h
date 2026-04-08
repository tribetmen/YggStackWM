// IronSession.h - Зашифрованная сессия Ironwood с мультиплексированием (16 TCP потоков)
#pragma once

#include "YggTypes.h"

// Forward declaration
class IronPeer;
struct NodeRoute;

// ============================================================================
// ПУЛ ПРЕДГЕНЕРИРОВАННЫХ КЛЮЧЕЙ (для ускорения создания сессий)
// ============================================================================

struct PrecomputedKeyPair {
    BYTE pub[32];
    BYTE priv[32];
    bool used;
    
    PrecomputedKeyPair() : used(false) {
        memset(pub, 0, 32);
        memset(priv, 0, 32);
    }
};

#define PRECOMPUTED_KEY_POOL_SIZE   16
#define KEYPOOL_MIN_KEYS_AT_START   4
#define KEYPOOL_IDLE_TARGET         12

// ============================================================================
// КОНСТАНТЫ TCP СОСТОЯНИЙ
// ============================================================================

enum TcpState {
    TCP_CLOSED = 0,
    TCP_SYN_SENT = 1,
    TCP_ESTABLISHED = 2,
    TCP_FIN_WAIT = 3
};

// ============================================================================
// ВИРТУАЛЬНЫЙ TCP ПОТОК (мини-TCP внутри Ironwood туннеля)
// ============================================================================

#define MAX_VIRTUAL_STREAMS 16

struct VirtualStream {
    // TCP состояние
    TcpState tcpState;
    bool synSent;
    bool serverFinReceived;
    bool ourFinSent;
    
    // Последовательности
    DWORD localSeq;
    DWORD remoteSeq;
    DWORD remoteAck;
    DWORD nextExpectedSeq;
    
    // Sliding window (отправка)
    DWORD sendWindowSize;
    DWORD sendUnacked;
    HANDLE sendWindowEvent;
    
    // Порты
    int sourcePort;
    
    // Очередь входящих данных
    vector<BYTE> recvQueue;
    DWORD recvQueueOffset;
    HANDLE recvEvent;
    
    // Ожидающие данные (до ESTABLISHED)
    vector<BYTE> pendingData;
    
    // Буфер реассемблирования
    map<DWORD, vector<BYTE> > reassemblyBuffer;
    DWORD reassemblyBufferSize;
    vector<BYTE> earlyRecvData;
    DWORD oldestBufferedTime;
    int dupAckCount;
    
    // Delayed ACK
    int delayedAckCount;
    DWORD delayedAckTime;
    DWORD delayedAckSeq;
    
    // Флаги использования
    bool inUse;
    volatile LONG refCount;
    
    VirtualStream() : tcpState(TCP_CLOSED), synSent(false), serverFinReceived(false), ourFinSent(false),
                      localSeq(0), remoteSeq(0), remoteAck(0), nextExpectedSeq(0),
                      sendWindowSize(65535), sendUnacked(0), sourcePort(0),
                      recvQueueOffset(0), reassemblyBufferSize(0), oldestBufferedTime(0), dupAckCount(0),
                      delayedAckCount(0), delayedAckTime(0), delayedAckSeq(0), inUse(false), refCount(0) {
        recvEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        sendWindowEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    }
    
    ~VirtualStream() {
        if (recvEvent) CloseHandle(recvEvent);
        if (sendWindowEvent) CloseHandle(sendWindowEvent);
    }
    
    void Reset(int port = 0) {
        tcpState = TCP_CLOSED;
        synSent = serverFinReceived = ourFinSent = false;
        localSeq = GetTickCount();
        remoteSeq = remoteAck = nextExpectedSeq = 0;
        sendWindowSize = 65535;
        sendUnacked = 0;
        sourcePort = port;
        { vector<BYTE>().swap(recvQueue); }  // реальное освобождение памяти (не просто clear)
        recvQueueOffset = 0;
        { vector<BYTE>().swap(pendingData); }
        reassemblyBuffer.clear();
        reassemblyBufferSize = 0;
        { vector<BYTE>().swap(earlyRecvData); }
        oldestBufferedTime = 0;
        dupAckCount = 0;
        delayedAckCount = 0;
        delayedAckTime = 0;
        delayedAckSeq = 0;
        inUse = true;
        refCount = 1;
        ResetEvent(recvEvent);
        ResetEvent(sendWindowEvent);
    }
    
    void Release() {
        if (InterlockedDecrement((LONG*)&refCount) <= 0) {
            inUse = false;
        }
    }
    
    void AddRef() {
        InterlockedIncrement((LONG*)&refCount);
    }
    
    bool HasData() const { return recvQueue.size() > recvQueueOffset; }
};

// ============================================================================
// КЛАСС СЕССИИ IRONWOOD
// ============================================================================

class IronSession {
private:
    // Ключи удаленной стороны (Ed25519 и X25519)
    BYTE m_remoteKey[KEY_SIZE];
    BYTE m_remoteXPub[KEY_SIZE];
    
    // Текущие публичные ключи удаленной стороны (из handshake)
    BYTE m_remoteCurrentPub[KEY_SIZE];
    BYTE m_remoteNextPub[KEY_SIZE];
    
    // Наши Curve25519 ключи
    BYTE m_recvPriv[KEY_SIZE];
    BYTE m_recvPub[KEY_SIZE];
    BYTE m_sendPriv[KEY_SIZE];
    BYTE m_sendPub[KEY_SIZE];
    BYTE m_nextPriv[KEY_SIZE];
    BYTE m_nextPub[KEY_SIZE];
    
    // Shared secrets (X25519)
    BYTE m_recvShared[KEY_SIZE];
    BYTE m_sendShared[KEY_SIZE];
    BYTE m_nextSendShared[KEY_SIZE];
    BYTE m_nextRecvShared[KEY_SIZE];
    
    // Счетчики ключей (64-bit для совместимости с Java)
    unsigned long long m_remoteKeySeq;
    unsigned long long m_localKeySeq;
    
    // Nonce для шифрования
    DWORD m_sendNonce;
    DWORD m_recvNonce;
    DWORD m_nextSendNonce;
    DWORD m_nextRecvNonce;
    
    // Состояние сессии
    bool m_bReady;
    bool m_bClosed;
    DWORD m_lastRotation;
    DWORD m_lastActivity;
    DWORD m_lastInitSent;
    int m_decryptionErrors;
    
    // Целевой порт (для всех потоков в сессии)
    int m_targetPort;
    
    // Синхронизация
    CRITICAL_SECTION m_lock;
    volatile LONG m_sessionRefCount;
    
    // IPv6 удаленной стороны (derived from key, always 200::)
    BYTE m_remoteIPv6[16];
    // Оригинальный запрошенный IPv6 из браузера (может быть 300::)
    BYTE m_requestedIPv6[16];
    
    // Мультиплексированные потоки
    VirtualStream m_streams[MAX_VIRTUAL_STREAMS];

    // Буфер для входящих UDP DNS ответов (srcPort=53)
    // Защищён m_lock; сигнализируется через m_udpDnsEvent
    vector<BYTE> m_udpDnsResponse;
    HANDLE m_udpDnsEvent;
    volatile bool m_udpDnsPortUnreachable; // true = получили ICMPv6 Port Unreachable на UDP/53

    // Callback для получения данных (legacy compatibility)
    typedef void (*DataCallback)(void* context, const BYTE* data, DWORD len);
    DataCallback m_dataCallback;
    void* m_callbackContext;
    
public:
    IronSession(const BYTE* remoteKey, int targetPort, unsigned long long initialKeySeq);
    virtual ~IronSession();
    
    // Управление ссылками сессии
    void AddRef() { InterlockedIncrement((LONG*)&m_sessionRefCount); }
    void Release() { if (InterlockedDecrement((LONG*)&m_sessionRefCount) == 0) delete this; }
    
    // Инициализация
    bool Initialize();
    
    // Закрытие сессии
    void Close();
    void Cleanup();
    
    // Генерация и ротация ключей
    void GenerateInitialKeys();
    void RotateKeys();
    void FixShared(DWORD recvNonceVal, DWORD sendNonceVal);
    
    // Отправка пакетов сессии
    bool SendSessionInit(IronPeer* peer, const vector<BYTE>& path);
    void SendSessionInitAsync(IronPeer* peer, const vector<BYTE>& path);
    bool SendSessionAck(IronPeer* peer, const vector<BYTE>& path);
    bool SendTraffic(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    
    // Обработка входящих пакетов
    bool HandleSessionHandshake(const BYTE* packet, DWORD len, int sessionType, 
                                const BYTE* srcKey, IronPeer* peer);
    bool HandleSessionTraffic(const BYTE* packet, DWORD len, IronPeer* peer);
    
    // === УПРАВЛЕНИЕ ВИРТУАЛЬНЫМИ ПОТОКАМИ ===
    int AcquireStream();                    // Захватить свободный поток (-1 если нет)
    void ReleaseStream(int streamId);       // Освободить поток
    VirtualStream* GetStream(int streamId); // Получить указатель на поток
    
    // === TCP ОПЕРАЦИИ (с streamId) ===
    void SendSYN(int streamId, IronPeer* peer, const vector<BYTE>& path);
    void SendACK(int streamId, IronPeer* peer, const vector<BYTE>& path, DWORD ackNum);
    void SendDupACK(int streamId, IronPeer* peer, const vector<BYTE>& path, DWORD ackNum);
    void SendFIN(int streamId, IronPeer* peer, const vector<BYTE>& path);
    void SendData(int streamId, IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    void QueueOrSendData(int streamId, IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    void ProcessIncomingTCP(IronPeer* peer, const vector<BYTE>& path, const BYTE* ipv6Packet, DWORD len);
    
    // === TCP ОПЕРАЦИИ (backward compatibility - uses stream 0) ===
    void SendSYN(IronPeer* peer, const vector<BYTE>& path);
    void SendACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum);
    void SendDupACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum);
    void SendFIN(IronPeer* peer, const vector<BYTE>& path);
    void SendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    void QueueOrSendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    
    // === ЧТЕНИЕ ДАННЫХ (с streamId) ===
    bool ReadData(int streamId, BYTE* buffer, DWORD maxLen, DWORD& outLen, DWORD timeoutMs);
    bool HasData(int streamId) const;
    void CheckReassemblyTimeout(int streamId, IronPeer* peer = NULL, vector<BYTE>* path = NULL);
    
    // === ЧТЕНИЕ ДАННЫХ (backward compatibility - uses stream 0) ===
    bool ReadData(BYTE* buffer, DWORD maxLen, DWORD& outLen, DWORD timeoutMs);
    bool HasData() const { return HasData(0); }
    void SetDataCallback(DataCallback callback, void* context);

    // === UDP DNS (без TCP state machine) ===
    // Отправить UDP DNS запрос на порт 53
    // srcIPv6: наш IPv6 адрес (16 байт)
    // dstIPv6: адрес DNS-сервера (16 байт) — может отличаться от m_remoteIPv6 (у того заполнена host-часть)
    bool SendUdpDns(IronPeer* peer, const vector<BYTE>& path,
                    const BYTE* srcIPv6, const BYTE* dstIPv6,
                    WORD srcPort, const BYTE* dnsQuery, DWORD queryLen);
    // Ждать UDP DNS ответа (srcPort=53) с таймаутом. Возвращает длину ответа или 0.
    DWORD ReadUdpDns(BYTE* buffer, DWORD maxLen, DWORD timeoutMs);
    bool IsUdpDnsPortUnreachable() const { return m_udpDnsPortUnreachable; }
    
    // Геттеры
    bool IsReady() const { return m_bReady; }
    bool IsClosed() const { return m_bClosed; }
    bool IsPendingClose() const { return false; }  // Legacy compatibility
    bool TryAcquireUse() { return true; }  // Legacy compatibility - always succeeds with multiplexing
    void ReleaseUse() {}  // Legacy compatibility
    bool IsInUse() const { return false; }  // Legacy compatibility
    TcpState GetTcpState(int streamId) const { return (streamId >= 0 && streamId < MAX_VIRTUAL_STREAMS) ? m_streams[streamId].tcpState : TCP_CLOSED; }
    TcpState GetTcpState() const;  // Legacy compatibility - returns first active stream state
    bool IsServerFinReceived(int streamId) const { return (streamId >= 0 && streamId < MAX_VIRTUAL_STREAMS) ? m_streams[streamId].serverFinReceived : false; }
    bool IsOurFinSent(int streamId) const { return (streamId >= 0 && streamId < MAX_VIRTUAL_STREAMS) ? m_streams[streamId].ourFinSent : false; }
    unsigned long long GetLocalKeySeq() const { return m_localKeySeq; }
    unsigned long long GetRemoteKeySeq() const { return m_remoteKeySeq; }
    const BYTE* GetRemoteKey() const { return m_remoteKey; }
    const BYTE* GetRemoteIPv6() const { return m_remoteIPv6; }
    const BYTE* GetSendPub() const { return m_sendPub; }
    const BYTE* GetNextPub() const { return m_nextPub; }
    const BYTE* GetRecvPriv() const { return m_recvPriv; }
    const BYTE* GetSendPriv() const { return m_sendPriv; }
    const BYTE* GetRemoteCurrentPub() const { return m_remoteCurrentPub; }
    const BYTE* GetRemoteNextPub() const { return m_remoteNextPub; }
    int GetTargetPort() const { return m_targetPort; }
    
    // Сеттеры для handshake
    void SetRemoteCurrentPub(const BYTE* pub) { memcpy(m_remoteCurrentPub, pub, KEY_SIZE); }
    void SetRemoteNextPub(const BYTE* pub) { memcpy(m_remoteNextPub, pub, KEY_SIZE); }
    void SetRemoteKeySeq(unsigned long long seq) { m_remoteKeySeq = seq; }
    void SetReady(bool ready) { m_bReady = ready; }
    void UpdateActivity() { m_decryptionErrors = 0; }
    void SetRemoteIPv6(const BYTE* ipv6) { memcpy(m_remoteIPv6, ipv6, 16); memcpy(m_requestedIPv6, ipv6, 16); }
    void SetRequestedIPv6(const BYTE* ipv6) { memcpy(m_requestedIPv6, ipv6, 16); }
    const BYTE* GetRequestedIPv6() const { return m_requestedIPv6; }
    void ResetTcpState(int streamId = -1);  // -1 = all streams, >=0 = specific stream
    void ResetTcpOnly(int streamId = 0);    // Reset specific stream (default 0 for legacy compat)
    bool TryClaimSynInitiator();
    void TouchActivity() { m_lastActivity = GetTickCount(); }
    DWORD GetLastActivity() const { return m_lastActivity; }
    DWORD GetLastInitSent() const { return m_lastInitSent; }
    void TouchLastInitSent() { m_lastInitSent = GetTickCount(); }
    bool IsTimedOut(DWORD timeoutMs) const {
        return (GetTickCount() - m_lastActivity) > timeoutMs;
    }
    
    void Lock()   { EnterCriticalSection(&m_lock); }
    void Unlock() { LeaveCriticalSection(&m_lock); }
    int GetActiveStreamCount() const;  // Количество активных потоков
    
    // Пул предгенерированных ключей (статический)
    static void InitKeyPool();
    static void PrecomputeKeysInBackground();
    static bool GetPrecomputedKeyPair(BYTE* outPub, BYTE* outPriv);
    static int GetKeyPoolAvailableCount();
    static void ShutdownKeyPool();
    static DWORD WINAPI KeyPoolBackgroundThreadProc(LPVOID lpParam);
    
    friend class IronPeer;
    
private:
    // Вспомогательные методы
    BYTE* CreateAndSendPacket(int streamId, IronPeer* peer, const vector<BYTE>& path,
                              bool syn, bool ack, bool psh, bool fin,
                              DWORD seqNum, DWORD ackNum, const BYTE* data, DWORD dataLen,
                              DWORD& outPacketLen);
    void PerformKeyRotation(const BYTE* theirNextPub, DWORD nonce);
    void ProcessReassemblyBuffer(int streamId, IronPeer* peer, const vector<BYTE>& path);
    bool IsSeqGreater(DWORD seq1, DWORD seq2);
    int FindStreamByPort(int port) const;
    
    // Внутренние методы TCP
    void SendSYNPacket(int streamId, IronPeer* peer, const vector<BYTE>& path);
    void SendSYNPacket(IronPeer* peer, const vector<BYTE>& path);
    void DeliverToApplication(int streamId, const BYTE* data, DWORD len);
    void NotifyDataReceived(int streamId);
    void NotifyDataReceived();
    
    // Шифрование/дешифрование
    bool EncryptPacket(const BYTE* plaintext, DWORD plainLen, BYTE* ciphertext, DWORD& cipherLen,
                       const BYTE* remotePub, const BYTE* privKey, DWORD nonce);
    bool DecryptPacket(const BYTE* ciphertext, DWORD cipherLen, BYTE* plaintext, DWORD& plainLen,
                       const BYTE* remotePub, const BYTE* privKey, DWORD nonce);
    
    // Статические переменные пула ключей
    static PrecomputedKeyPair s_keyPool[PRECOMPUTED_KEY_POOL_SIZE];
    static CRITICAL_SECTION s_keyPoolLock;
    static HANDLE s_keyPoolThread;
    static volatile BOOL s_keyPoolRunning;
    static volatile int s_keyPoolAvailable;
};
