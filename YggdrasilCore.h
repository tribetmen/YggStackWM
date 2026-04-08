// YggdrasilCore.h - Главный контроллер Yggstack
#pragma once

#include "YggTypes.h"
#include "YggCrypto.h"
#include "IronPeer.h"
#include <string>

// ============================================================================
// ГЛАВНЫЙ КЛАСС YGGDRASIL
// ============================================================================

class CYggdrasilCore {
private:
    YggKeys m_keys;
    BYTE m_xPrivKey[32];  // X25519 private key, вычислен один раз из Ed25519 private key
    vector<IronPeer*> m_peers;
    CRITICAL_SECTION m_peersLock;
    
    static CYggdrasilCore* s_pInstance;
    
    // Приватные конструктор/деструктор (Singleton)
    CYggdrasilCore();
    ~CYggdrasilCore();

public:
    // Получение экземпляра Singleton
    static CYggdrasilCore* GetInstance();
    static void DestroyInstance();
    
    // Инициализация и завершение
    bool Initialize();
    void Shutdown();
    
    // Управление ключами
    bool LoadOrGenerateKeys();
    bool SaveKeysToRegistry();
    
    // Подключение к пирам
    IronPeer* ConnectToPeer(LPCWSTR peerAddress, int port);
    void DisconnectAll();
    
    // Отправка PATH_LOOKUP к целевому IPv6
    bool SendPathLookupToIPv6(LPCWSTR ipv6Address);
    std::wstring SendPathLookupToIPv6WithKey(LPCWSTR ipv6Address, BYTE* outKey);
    
    // Создание сессии к IPv6
    bool CreateSessionToIPv6(LPCWSTR ipv6Address, int targetPort = 1);
    
    // Получение первого пира
    IronPeer* GetFirstPeer();
    
    // Асинхронная работа с сессиями
    void AddPendingSession(LPCWSTR ipv6Address, int targetPort);
    
    // Получение сессии по IPv6 (для HTTP прокси)
    IronSession* GetSessionForIPv6(LPCWSTR ipv6Address);
    
    // Получение peer для сессии
    IronPeer* GetPeerForSession(IronSession* session);
    
    // Получение path к IPv6
    bool GetPathToIPv6(LPCWSTR ipv6Address, vector<BYTE>& outPath);

    // Принудительное пересоздание Ironwood-сессии (когда старая в FIN_WAIT)
    bool ForceRecreateSessionToIPv6(LPCWSTR ipv6Address, int port);
    
    // Разбор IPv6-строки в 16 байт (публичная обёртка над статическим ParseIPv6String)
    static bool ParseIPv6(LPCWSTR ipv6Str, BYTE* outBytes);

    // Геттеры
    const YggKeys& GetKeys() const { return m_keys; }
    const BYTE* GetIPv6() const { return m_keys.ipv6; }
    // Возвращает X25519 private key (вычислен один раз при LoadOrGenerateKeys)
    const BYTE* GetXPrivKey() const { return m_xPrivKey; }
    WCHAR* GetIPv6String(WCHAR* buffer, int maxLen);
};
