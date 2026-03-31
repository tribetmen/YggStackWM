// IronPeer.h - Подключение к удаленному пиру Yggdrasil
#pragma once

#include "YggTypes.h"
#include "IronSession.h"
#include <map>
#include <string>

// ============================================================================
// СТРУКТУРА МАРШРУТА УЗЛА (как NodeRoute в Java)
// ============================================================================

struct NodeRoute {
    BYTE fullKey[32];       // Полный ключ узла
    vector<BYTE> path;      // Путь (координаты) - varints ending with 0
    BYTE parentKey[32];     // Ключ родительского узла
    unsigned long long port;// Порт в дереве
    
    NodeRoute() : port(0) {
        memset(fullKey, 0, 32);
        memset(parentKey, 0, 32);
    }
    
    NodeRoute(const BYTE* key, const vector<BYTE>& p, const BYTE* parent, unsigned long long prt) 
        : path(p), port(prt) {
        memcpy(fullKey, key, 32);
        if (parent) memcpy(parentKey, parent, 32);
        else memset(parentKey, 0, 32);
    }
};

// ============================================================================
// ОЖИДАЮЩАЯ СЕССИЯ (для асинхронной отправки SESSION_INIT после PATH_NOTIFY)
// ============================================================================
struct PendingSession {
    BYTE targetKey[32];      // Partial key из IPv6
    BYTE targetIPv6[16];     // Оригинальный IPv6 (для точного сравнения)
    int targetPort;
    DWORD createdTime;
    
    PendingSession(const BYTE* key, const BYTE* ipv6, int port) : targetPort(port), createdTime(GetTickCount()) {
        memcpy(targetKey, key, 32);
        memcpy(targetIPv6, ipv6, 16);
    }
};

// ============================================================================
// КЛАСС ПИРА
// ============================================================================

class IronPeer {
private:
    // Сокет и ключи
    SOCKET m_socket;
    BYTE m_remoteKey[KEY_SIZE];
    BYTE m_remoteXPub[KEY_SIZE];
    unsigned long long m_remotePort;     // 64 бита
    unsigned long long m_ourPortInTree;  // 64 бита
    bool m_bConnected;
    bool m_bHandshakeComplete;  // Хендшейк пройден
    
    // Сессии
    vector<IronSession*> m_sessions;
    CRITICAL_SECTION m_sessionsLock;
    
    // Потоки
    HANDLE m_hReceiveThread;
    HANDLE m_hKeepaliveThread;
    
    // Состояние handshake
    volatile bool m_sigResReceived;
    BYTE m_psig[64];
    unsigned long long m_remoteSeq;      // 64 бита
    unsigned long long m_remoteNonce;    // 64 бита
    bool m_gotSigReq;

    // Таблица маршрутизации (как routingTable в Java) - ключ: hex первые 16 байт
    map<string, NodeRoute> m_routingTable;
    CRITICAL_SECTION m_routingLock;
    
    // Ожидающие сессии (ждут PATH_NOTIFY)
    vector<PendingSession> m_pendingSessions;
    CRITICAL_SECTION m_pendingLock;
    
    // Отслеживание недавних PATH_LOOKUP (дедупликация)
    map<string, DWORD> m_recentPathLookups;
    
    // Наши глобальные координаты (как myGlobalCoords в Java)
    vector<BYTE> m_myGlobalCoords;
    
    // Ссылка на ключи (для доступа к ourEdPub)
    BYTE* m_ourEdPub;
    BYTE* m_ourEdPriv;

    // Статические процедуры потоков
    static DWORD WINAPI ReceiveThreadProc(LPVOID lpParam);
    static DWORD WINAPI KeepaliveThreadProc(LPVOID lpParam);
    static DWORD WINAPI SessionInitThreadProc(LPVOID lpParam);  // Асинхронная отправка SESSION_INIT

    // Приватные методы
public:
    bool SendPacketRaw(const BYTE* data, DWORD len);
    string GetKeyPrefix(const BYTE* key);
private:
    bool ReadUvarint(unsigned long long& value);
    bool WriteUvarint(vector<BYTE>& out, unsigned long long value);
    
    // Утилиты для путей
    vector<BYTE> GetOurPathFromRoot();

    // Обработчики пакетов
    void HandleSigReq(const BYTE* packet, DWORD len);
    void HandleSigRes(const BYTE* packet, DWORD len);
    void HandleAnnounce(const BYTE* packet, DWORD len);
    void HandlePathLookup(const BYTE* packet, DWORD len);
    void HandlePathNotify(const BYTE* packet, DWORD len);
    void HandleTraffic(const BYTE* packet, DWORD len);
    
    // Подпись (вспомогательная)
    void GetEdSeed(BYTE* outSeed);
    bool SignEd25519(const BYTE* seed, const BYTE* data, DWORD dataLen, BYTE* signature);

public:
    // Конструктор / деструктор
    IronPeer(SOCKET sock, const BYTE* remoteKey);
    virtual ~IronPeer();
    
    // Установка ключей (должно быть вызвано после создания)
    void SetOurKeys(BYTE* edPub, BYTE* edPriv) { m_ourEdPub = edPub; m_ourEdPriv = edPriv; }
    
    // Управление соединением
    bool Start();
    void Stop();
    
    // Отправка пакетов
    bool SendPacket(BYTE type, const BYTE* data = NULL, DWORD dataLen = 0);
    bool SendKeepAlive();
    bool SendBloom(const BYTE* ourPubKey);
    bool SendPathLookup(const BYTE* targetKey);
    bool SendPathNotify(const BYTE* backPath, const BYTE* remoteNodeKey, const BYTE* realCoords);
    
    // Асинхронная работа с сессиями
    void AddPendingSession(const BYTE* targetKey, const BYTE* targetIPv6, int targetPort);
    void CheckPendingSessions(const string& prefix);
    void CheckPendingSessionsWithFullKey(const BYTE* fullKey, const vector<BYTE>& path);
    
    // Handshake
    bool SendSigReq();
    bool SendAnnounce();
    bool SendHandshakeBundle(const BYTE* ourPubKey, 
                            const BYTE* ourPrivKey,
                            unsigned long long remoteSeq, 
                            unsigned long long remoteNonce);
    
    // Получение пакетов
    bool ReceivePacket(BYTE* buffer, DWORD bufferSize, DWORD& bytesReceived);
    void HandleReceivedData(const BYTE* data, DWORD len);
    
    // Управление сессиями
    IronSession* CreateSession(const BYTE* remoteKey, DWORD port);
    IronSession* GetOrCreateSession(const BYTE* remoteKey, DWORD port);
    IronSession* GetSession(const BYTE* remoteKey);  // Получить существующую сессию
    IronSession* GetSessionByIPv6(const BYTE* ipv6); // Получить сессию по IPv6 (сравнение первых 16 байт)
    void CloseSession(const BYTE* remoteKey);
    bool HasSession(IronSession* session);           // Проверить наличие сессии
    bool GetPathToKey(const BYTE* key, vector<BYTE>& outPath); // Получить path к ключу
    bool GetPathToIPv6(const BYTE* ipv6, vector<BYTE>& outPath); // Получить path к IPv6 (поиск по первым 16 байтам ключа)
    
    // Отправка сессионных пакетов
    bool SendSessionInit(IronSession* session, const vector<BYTE>& path);
    bool SendSessionAck(IronSession* session, const vector<BYTE>& path);
    bool SendSessionTraffic(IronSession* session, const vector<BYTE>& path, const BYTE* data, DWORD len);
    
    // Состояние handshake
    bool IsSigResReceived() const { return m_sigResReceived; }
    void SetSigResReceived(bool received) { m_sigResReceived = received; }
    void SetRemoteSigReq(unsigned long long seq, unsigned long long nonce);
    bool GotSigReq() { return m_gotSigReq; }
    
    // Порты
    unsigned long long GetOurPortInTree() const { return m_ourPortInTree; }
    
    // Состояние соединения
    bool IsConnected() const { return m_bConnected; }
    bool IsHandshakeComplete() const { return m_bHandshakeComplete; }
    
    // Ручная установка глобальных координат (для отладки или если знаешь свой путь)
    void SetGlobalCoords(const vector<BYTE>& coords) { m_myGlobalCoords = coords; }
    vector<BYTE> GetGlobalCoords() const { return m_myGlobalCoords; }
    
    // Доступ к таблице маршрутизации (для YggdrasilCore)
    NodeRoute* GetRoute(const string& prefix);
    void UpdateRoute(const string& prefix, const NodeRoute& route);
};
