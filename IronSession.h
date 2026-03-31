// IronSession.h - Зашифрованная сессия Ironwood
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
    
    // TCP последовательности
    DWORD m_localSeq;
    DWORD m_remoteSeq;
    DWORD m_remoteAck;
    DWORD m_nextExpectedSeq;
    
    // TCP состояние
    TcpState m_tcpState;
    bool m_synSent;
    
    // Состояние сессии
    bool m_bReady;
    bool m_bClosed;
    volatile bool m_inUse;  // Захвачена HTTP-потоком (эксклюзивное использование)
    DWORD m_lastRotation;
    DWORD m_lastActivity;   // Время последней активности (для timeout)
    int m_decryptionErrors;
    
    // Порты
    int m_targetPort;
    int m_sourcePort;
    
    // Синхронизация
    CRITICAL_SECTION m_lock;
    int m_refCount;
    
    // IPv6 удаленной стороны (для поиска сессии)
    BYTE m_remoteIPv6[16];
    
    // Callback для получения данных приложением
    typedef void (*DataCallback)(void* context, const BYTE* data, DWORD len);
    DataCallback m_dataCallback;
    void* m_callbackContext;
    
    // Очередь входящих данных (если callback не установлен)
    CRITICAL_SECTION m_recvQueueLock;
    vector<BYTE> m_recvQueue;
    HANDLE m_recvEvent;
    
    // Ожидающие данные (до ESTABLISHED)
    vector<BYTE> m_pendingData;
    
    // Буфер реассемблирования
    map<DWORD, vector<BYTE> > m_reassemblyBuffer;
    DWORD m_reassemblyBufferSize;
    vector<BYTE> m_earlyRecvData;  // Данные полученные до SYN-ACK, буферизуются и отдаются после ESTABLISHED
    DWORD m_oldestBufferedTime;
    int m_dupAckCount;

public:
    IronSession(const BYTE* remoteKey, int targetPort, unsigned long long initialKeySeq);
    virtual ~IronSession();
    
    // Управление ссылками
    void AddRef() { m_refCount++; }
    void Release() { if (--m_refCount == 0) delete this; }
    
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
    bool SendSessionAck(IronPeer* peer, const vector<BYTE>& path);
    bool SendTraffic(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    
    // Обработка входящих пакетов
    bool HandleSessionHandshake(const BYTE* packet, DWORD len, int sessionType, 
                                const BYTE* srcKey, IronPeer* peer);
    bool HandleSessionTraffic(const BYTE* packet, DWORD len, IronPeer* peer);
    
    // TCP обработка
    void SendSYN(IronPeer* peer, const vector<BYTE>& path);
    void SendSYNPacket(IronPeer* peer, const vector<BYTE>& path);  // Отправка SYN без проверки состояния (после TryClaimSynInitiator)
    void SendACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum);
    void SendDupACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum);
    void SendFIN(IronPeer* peer, const vector<BYTE>& path);
    void SendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    void QueueOrSendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len);
    void ProcessIncomingTCP(IronPeer* peer, const vector<BYTE>& path, const BYTE* ipv6Packet, DWORD len);
    
    // Геттеры
    bool IsReady() const { return m_bReady; }
    bool IsClosed() const { return m_bClosed; }
    TcpState GetTcpState() const { return m_tcpState; }
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
    
    // Сеттеры для handshake
    void SetRemoteCurrentPub(const BYTE* pub) { memcpy(m_remoteCurrentPub, pub, KEY_SIZE); }
    void SetRemoteNextPub(const BYTE* pub) { memcpy(m_remoteNextPub, pub, KEY_SIZE); }
    void SetRemoteKeySeq(unsigned long long seq) { m_remoteKeySeq = seq; }
    void SetReady(bool ready) { m_bReady = ready; }
    void UpdateActivity() { m_decryptionErrors = 0; }
    void SetRemoteIPv6(const BYTE* ipv6) { memcpy(m_remoteIPv6, ipv6, 16); }
    void ResetTcpState();  // Сброс TCP для повторного использования Ironwood-сессии
    void TouchActivity() { m_lastActivity = GetTickCount(); }
    DWORD GetLastActivity() const { return m_lastActivity; }
    bool IsTimedOut(DWORD timeoutMs) const {
        return (GetTickCount() - m_lastActivity) > timeoutMs;
    }
    // Атомарная попытка захватить право инициировать SYN.
    // Возвращает true если этот поток стал инициатором (должен послать SYN),
    // false если другой поток уже начал подключение.
    bool TryClaimSynInitiator();
    // Эксклюзивный захват сессии HTTP-потоком. Возвращает true если захвачено.
    bool TryAcquireUse() {
        EnterCriticalSection(&m_lock);
        if (m_inUse) { LeaveCriticalSection(&m_lock); return false; }
        m_inUse = true;
        LeaveCriticalSection(&m_lock);
        return true;
    }
    void ReleaseUse() { m_inUse = false; }
    bool IsInUse() const { return m_inUse; }
    void Lock()   { EnterCriticalSection(&m_lock); }
    void Unlock() { LeaveCriticalSection(&m_lock); }
    
    // Callback для получения данных
    void SetDataCallback(DataCallback callback, void* context);
    bool ReadData(BYTE* buffer, DWORD maxLen, DWORD& outLen, DWORD timeoutMs);
    bool HasData() const { return !m_recvQueue.empty(); }
    void NotifyDataReceived();
    
    // Пул предгенерированных ключей (статический)
    static void InitKeyPool();                          // Инициализация пула
    static void PrecomputeKeysInBackground();           // Фоновое заполнение
    static bool GetPrecomputedKeyPair(BYTE* outPub, BYTE* outPriv);  // Взять ключи
    static int GetKeyPoolAvailableCount();              // Сколько ключей доступно
    static void ShutdownKeyPool();                      // Очистка
    
    // Потоковые процедуры для пула ключей
    static DWORD WINAPI KeyPoolBackgroundThreadProc(LPVOID lpParam);
    
    friend class IronPeer;
    
private:
    // Вспомогательные методы
    BYTE* CreateAndSendPacket(IronPeer* peer, const vector<BYTE>& path,
                              bool syn, bool ack, bool psh, bool fin,
                              DWORD seqNum, DWORD ackNum, const BYTE* data, DWORD dataLen,
                              DWORD& outPacketLen);
    void PerformKeyRotation(const BYTE* theirNextPub, DWORD nonce);
    void ProcessReassemblyBuffer(IronPeer* peer, const vector<BYTE>& path);
    void CheckReassemblyTimeout();
    bool IsSeqGreater(DWORD seq1, DWORD seq2);
    void DeliverToApplication(const BYTE* data, DWORD len);
    
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
