// YggdrasilCore.cpp - Реализация главного контроллера
#include "stdafx.h"
#include "YggdrasilCore.h"
#include "IronSession.h"
#include "ygg_handshake.h"
#include "ygg_constants.h"
#include <string>

#pragma comment(lib, "ws2.lib")

extern void AddLog(LPCWSTR text, BYTE type);

// TweetNaCl
extern "C" {
#include "tweetnacl32.h"
}

// Статическая переменная Singleton
CYggdrasilCore* CYggdrasilCore::s_pInstance = NULL;

// ============================================================================
// SINGLETON
// ============================================================================

CYggdrasilCore::CYggdrasilCore() {
    memset(&m_keys, 0, sizeof(m_keys));
    InitializeCriticalSection(&m_peersLock);
}

CYggdrasilCore::~CYggdrasilCore() {
    Shutdown();
    DeleteCriticalSection(&m_peersLock);
}

CYggdrasilCore* CYggdrasilCore::GetInstance() {
    if (!s_pInstance) {
        s_pInstance = new CYggdrasilCore();
    }
    return s_pInstance;
}

void CYggdrasilCore::DestroyInstance() {
    if (s_pInstance) {
        delete s_pInstance;
        s_pInstance = NULL;
    }
}

// ============================================================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================================================

bool CYggdrasilCore::Initialize() {
    // Инициализация криптографии
    if (!YggCrypto::Initialize()) {
        return false;
    }
    
    // Тесты криптографии отключены в продакшн-сборке
    // YggCrypto::RunCryptoTests();
    
    // Инициализация пула предгенерированных ключей
    IronSession::InitKeyPool();
    
    return true;
}

void CYggdrasilCore::Shutdown() {
    DisconnectAll();
    
    // Очистка пула ключей
    IronSession::ShutdownKeyPool();
}

// ============================================================================
// УПРАВЛЕНИЕ КЛЮЧАМИ
// ============================================================================

bool CYggdrasilCore::LoadOrGenerateKeys() {
    WCHAR debug[256];
    
    // Сначала пробуем загрузить из реестра
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Yggstack", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BYTE privKey[64] = {0};
        BYTE pubKey[32] = {0};
        DWORD privLen = sizeof(privKey);
        DWORD pubLen = sizeof(pubKey);
        DWORD type;
        
        bool hasPriv = (RegQueryValueEx(hKey, L"PrivateKey", NULL, &type, privKey, &privLen) == ERROR_SUCCESS);
        bool hasPub = (RegQueryValueEx(hKey, L"PublicKey", NULL, &type, pubKey, &pubLen) == ERROR_SUCCESS);
        
        RegCloseKey(hKey);
        
        if (hasPriv && hasPub && privLen == 64 && pubLen == 32) {
            memcpy(m_keys.privateKey, privKey, 64);
            memcpy(m_keys.publicKey, pubKey, 32);
            
            YggCrypto::DeriveIPv6(m_keys.ipv6, m_keys.publicKey);
            
            // Выводим полный ключ и IPv6 для отладки
            WCHAR keyHex[65] = {0}, ipv6Str[40];
            for (int i = 0; i < 32; i++) {
                WCHAR b[4];
                wsprintf(b, L"%02x", m_keys.publicKey[i]);
                wcscat(keyHex, b);
            }
            YggCrypto::FormatIPv6(m_keys.ipv6, ipv6Str, 40);
            
            wsprintf(debug, L"[KEYS] Loaded from registry");
            AddLog(debug, LOG_SUCCESS);
            wsprintf(debug, L"[KEYS] Public Key: %s", keyHex);
            AddLog(debug, LOG_INFO);
            wsprintf(debug, L"[KEYS] IPv6: %s", ipv6Str);
            AddLog(debug, LOG_INFO);
            
            // DEBUG: Конвертируем Ed25519 pub -> X25519 pub и выводим
            BYTE x25519Pub[32];
            extern int crypto_sign_ed25519_pk_to_curve25519(unsigned char*, const unsigned char*);
            if (crypto_sign_ed25519_pk_to_curve25519(x25519Pub, m_keys.publicKey) == 0) {
                WCHAR x25519Hex[65] = {0};
                for (int i = 0; i < 32; i++) {
                    WCHAR b[4];
                    wsprintf(b, L"%02x", x25519Pub[i]);
                    wcscat(x25519Hex, b);
                }
                wsprintf(debug, L"[KEYS] X25519 Pub: %s", x25519Hex);
                AddLog(debug, LOG_INFO);
            }
            
            return true;
        }
    }
    
    // Если не удалось загрузить — генерируем новые
    AddLog(L"[KEYS] Generating new key pair...", LOG_INFO);
    
    if (!YggCrypto::GenerateKeyPair(m_keys.publicKey, m_keys.privateKey)) {
        AddLog(L"[KEYS] Generation failed!", LOG_ERROR);
        return false;
    }
    
    
    
    // Получаем IPv6 из публичного ключа
    YggCrypto::DeriveIPv6(m_keys.ipv6, m_keys.publicKey);
    
    // Выводим полный ключ и IPv6 для отладки
    WCHAR keyHex[65] = {0}, ipv6Str[40];
    for (int i = 0; i < 32; i++) {
        WCHAR b[4];
        wsprintf(b, L"%02x", m_keys.publicKey[i]);
        wcscat(keyHex, b);
    }
    YggCrypto::FormatIPv6(m_keys.ipv6, ipv6Str, 40);
    
    wsprintf(debug, L"[KEYS] Public Key: %s", keyHex);
    AddLog(debug, LOG_INFO);
    wsprintf(debug, L"[KEYS] IPv6: %s", ipv6Str);
    AddLog(debug, LOG_INFO);
    
    // Сохраняем в реестр
    if (SaveKeysToRegistry()) {
        AddLog(L"[KEYS] New keys saved to registry", LOG_SUCCESS);
    }
    
    return true;
}

bool CYggdrasilCore::SaveKeysToRegistry() {
    HKEY hKey;
    
    if (RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\Yggstack", 0, NULL, 0,
                       KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, L"PrivateKey", 0, REG_BINARY, 
                      (LPBYTE)m_keys.privateKey, 64);
        RegSetValueEx(hKey, L"PublicKey", 0, REG_BINARY,
                      (LPBYTE)m_keys.publicKey, 32);
        
        RegCloseKey(hKey);
        return true;
    }
    
    return false;
}

WCHAR* CYggdrasilCore::GetIPv6String(WCHAR* buffer, int maxLen) {
    YggCrypto::FormatIPv6(m_keys.ipv6, buffer, maxLen);
    return buffer;
}

// ============================================================================
// УПРАВЛЕНИЕ ПИРАМИ
// ============================================================================

IronPeer* CYggdrasilCore::ConnectToPeer(LPCWSTR peerAddress, int port) {
    char host[256];
    WCHAR debugMsg[256];
    
    WideCharToMultiByte(CP_ACP, 0, peerAddress, -1, host, sizeof(host), NULL, NULL);
    
    // Убираем протокол из адреса
    char* addrStart = strstr(host, "://");
    if (addrStart) {
        addrStart += 3;
    } else {
        addrStart = host;
    }
    
    // Отделяем порт если есть в адресе
    char* portStr = strchr(addrStart, ':');
    if (portStr) {
        *portStr = '\0';
        port = atoi(portStr + 1);
    }
    
    wsprintf(debugMsg, L"Connecting to %S:%d", addrStart, port);
    AddLog(debugMsg, LOG_INFO);
    
    // Создаем сокет
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        AddLog(L"Failed to create socket", LOG_ERROR);
        return NULL;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    
    // Пробуем интерпретировать как IP адрес
    addr.sin_addr.s_addr = inet_addr(addrStart);
    
    // Если не IP, пробуем DNS
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        AddLog(L"Address is not IP, trying DNS...", LOG_DEBUG);
        
        struct hostent* hostent = gethostbyname(addrStart);
        if (!hostent) {
            AddLog(L"DNS resolution failed", LOG_ERROR);
            closesocket(sock);
            return NULL;
        }
        memcpy(&addr.sin_addr, hostent->h_addr, hostent->h_length);
    }
    
    // Отключаем Nagle algorithm для минимальной задержки
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    
    // Устанавливаем неблокирующий режим
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    int result = select(sock + 1, NULL, &fdset, NULL, &tv);
    if (result != 1) {
        AddLog(L"Connection timeout", LOG_ERROR);
        closesocket(sock);
        return NULL;
    }
    
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
    if (so_error != 0) {
        wsprintf(debugMsg, L"Connection error: %d", so_error);
        AddLog(debugMsg, LOG_ERROR);
        closesocket(sock);
        return NULL;
    }
    
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    
    AddLog(L"TCP Connected, starting handshake...", LOG_DEBUG);
    
    // META HANDSHAKE
    BYTE peerKey[KEY_SIZE] = {0};
    DWORD peerPort = 0;
    
    if (!PerformHandshake(sock, m_keys.publicKey, m_keys.privateKey, 
                         peerKey, &peerPort, NULL)) {
        AddLog(L"Handshake failed", LOG_ERROR);
        closesocket(sock);
        return NULL;
    }
    
    AddLog(L"Meta handshake successful", LOG_SUCCESS);
    
    // СОЗДАЕМ PEER
    AddLog(L"Creating peer...", LOG_DEBUG);
    
    IronPeer* newPeer = new IronPeer(sock, peerKey);
    if (!newPeer) {
        AddLog(L"new IronPeer failed!", LOG_ERROR);
        closesocket(sock);
        return NULL;
    }
    
    // Устанавливаем наши ключи для пира (нужно для PATH_LOOKUP/PATH_NOTIFY)
    newPeer->SetOurKeys(m_keys.publicKey, m_keys.privateKey);
    
    // Запускаем потоки (SIG_REQ будет обработан в потоке автоматически)
    if (!newPeer->Start()) {
        AddLog(L"Failed to start peer threads", LOG_ERROR);
        delete newPeer;
        return NULL;
    }
    
    // Добавляем в список
    EnterCriticalSection(&m_peersLock);
    m_peers.push_back(newPeer);
    LeaveCriticalSection(&m_peersLock);
    
    wsprintf(debugMsg, L"TCP connected to %s, starting handshake...", peerAddress);
    AddLog(debugMsg, LOG_DEBUG);
    
    return newPeer;
}

void CYggdrasilCore::DisconnectAll() {
    EnterCriticalSection(&m_peersLock);
    for(size_t i = 0; i < m_peers.size(); i++) {
        delete m_peers[i];
    }
    m_peers.clear();
    LeaveCriticalSection(&m_peersLock);
}

IronPeer* CYggdrasilCore::GetFirstPeer() {
    EnterCriticalSection(&m_peersLock);
    IronPeer* peer = m_peers.empty() ? NULL : m_peers[0];
    LeaveCriticalSection(&m_peersLock);
    return peer;
}

// ============================================================================
// PATH_LOOKUP
// ============================================================================

bool CYggdrasilCore::SendPathLookupToIPv6(LPCWSTR ipv6Address) {
    // Парсим IPv6 строку в байты
    BYTE ipv6[16] = {0};
    
    // Ручной парсинг hex IPv6 для надежности на WinCE
    // Формат: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
    const WCHAR* p = ipv6Address;
    int group = 0;
    
    while (group < 8 && *p) {
        unsigned long val = 0;
        int digits = 0;
        
        // Парсим hex цифры вручную (максимум 4)
        while (digits < 4 && *p && *p != L':') {
            WCHAR c = *p++;
            val <<= 4;
            if (c >= L'0' && c <= L'9') val |= (c - L'0');
            else if (c >= L'a' && c <= L'f') val |= (c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') val |= (c - L'A' + 10);
            digits++;
        }
        
        ipv6[group*2] = (val >> 8) & 0xFF;
        ipv6[group*2+1] = val & 0xFF;
        group++;
        
        // Пропускаем двоеточие или завершаем
        if (*p == L':') p++;
        else if (*p == 0) break;
    }
    
    if (group != 8) {
        AddLog(L"[PATH_LOOKUP] Invalid IPv6 format", LOG_ERROR);
        return false;
    }
    
    // Логируем распарсенный IPv6 для отладки
    WCHAR parsedIp[64];
    wsprintf(parsedIp, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7],
        ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
    AddLog(parsedIp, LOG_DEBUG);
    
    // Получаем partial key из IPv6
    BYTE targetKey[32];
    YggCrypto::DerivePartialKeyFromIPv6(targetKey, ipv6);
    
    WCHAR debug[256];
    WCHAR keyHex[33] = {0};
    for (int i = 0; i < 16; i++) {
        WCHAR b[4];
        wsprintf(b, L"%02x", targetKey[i]);
        wcscat(keyHex, b);
    }
    wsprintf(debug, L"[PATH_LOOKUP] Target key prefix: %s", keyHex);
    AddLog(debug, LOG_INFO);
    
    // Отправляем PATH_LOOKUP через первый пир (если есть)
    EnterCriticalSection(&m_peersLock);
    IronPeer* peer = m_peers.empty() ? NULL : m_peers[0];
    LeaveCriticalSection(&m_peersLock);
    
    if (!peer) {
        AddLog(L"[PATH_LOOKUP] No peer connected", LOG_ERROR);
        return false;
    }
    
    if (peer->SendPathLookup(targetKey)) {
        AddLog(L"[PATH_LOOKUP] Request sent", LOG_SUCCESS);
        return true;
    }
    
    return false;
}

std::wstring CYggdrasilCore::SendPathLookupToIPv6WithKey(LPCWSTR ipv6Address, BYTE* outKey) {
    // Парсим IPv6 строку в байты
    BYTE ipv6[16] = {0};
    
    // Ручной парсинг hex IPv6 для надежности на WinCE
    const WCHAR* p = ipv6Address;
    int group = 0;
    
    while (group < 8 && *p) {
        unsigned long val = 0;
        int digits = 0;
        
        while (digits < 4 && *p && *p != L':') {
            WCHAR c = *p++;
            val <<= 4;
            if (c >= L'0' && c <= L'9') val |= (c - L'0');
            else if (c >= L'a' && c <= L'f') val |= (c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') val |= (c - L'A' + 10);
            digits++;
        }
        
        ipv6[group*2] = (val >> 8) & 0xFF;
        ipv6[group*2+1] = val & 0xFF;
        group++;
        
        if (*p == L':') p++;
        else if (*p == 0) break;
    }
    
    if (group != 8) {
        return L"Invalid IPv6 format";
    }
    
    // Получаем partial key из IPv6
    BYTE targetKey[32];
    YggCrypto::DerivePartialKeyFromIPv6(targetKey, ipv6);
    
    if (outKey) {
        memcpy(outKey, targetKey, 32);
    }
    
    // Формируем hex строку
    WCHAR keyHex[65] = {0};
    for (int i = 0; i < 32; i++) {
        WCHAR b[4];
        wsprintf(b, L"%02x", targetKey[i]);
        wcscat(keyHex, b);
    }
    
    // Отправляем PATH_LOOKUP через первый пир (если есть)
    EnterCriticalSection(&m_peersLock);
    IronPeer* peer = m_peers.empty() ? NULL : m_peers[0];
    LeaveCriticalSection(&m_peersLock);
    
    if (!peer) {
        return std::wstring(L"No peer - Key: ") + keyHex;
    }
    
    peer->SendPathLookup(targetKey);
    
    return std::wstring(L"Sent - Key: ") + keyHex;
}

// ============================================================================
// СОЗДАНИЕ СЕССИИ
// ============================================================================

bool CYggdrasilCore::CreateSessionToIPv6(LPCWSTR ipv6Address, int targetPort) {
    // Парсим IPv6 строку в байты
    BYTE ipv6[16] = {0};
    
    // Ручной парсинг hex IPv6 для надежности на WinCE
    const WCHAR* p = ipv6Address;
    int group = 0;
    
    while (group < 8 && *p) {
        unsigned long val = 0;
        int digits = 0;
        
        while (digits < 4 && *p && *p != L':') {
            WCHAR c = *p++;
            val <<= 4;
            if (c >= L'0' && c <= L'9') val |= (c - L'0');
            else if (c >= L'a' && c <= L'f') val |= (c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') val |= (c - L'A' + 10);
            digits++;
        }
        
        ipv6[group*2] = (val >> 8) & 0xFF;
        ipv6[group*2+1] = val & 0xFF;
        group++;
        
        if (*p == L':') p++;
        else if (*p == 0) break;
    }
    
    if (group != 8) {
        AddLog(L"[SESSION] Invalid IPv6 format", LOG_ERROR);
        return false;
    }
    
    // Получаем partial key из IPv6
    BYTE targetKey[32];
    YggCrypto::DerivePartialKeyFromIPv6(targetKey, ipv6);
    
    // Получаем префикс для поиска в таблице маршрутизации
    char prefix[33];
    for (int i = 0; i < 16; i++) {
        sprintf(prefix + i*2, "%02x", targetKey[i]);
    }
    prefix[32] = 0;
    
    // Ищем пир и маршрут
    IronPeer* peer = NULL;
    vector<BYTE> path;
    
    EnterCriticalSection(&m_peersLock);
    if (!m_peers.empty()) {
        peer = m_peers[0];  // Берем первый пир
    }
    LeaveCriticalSection(&m_peersLock);
    
    if (!peer) {
        AddLog(L"[SESSION] No peer connected", LOG_ERROR);
        return false;
    }
    
    // Отправляем PATH_LOOKUP и ждем маршрут (максимум 10 секунд)
    NodeRoute* route = peer->GetRoute(prefix);
    if (!route || route->path.empty()) {
        peer->SendPathLookup(targetKey);
        AddLog(L"[SESSION] PATH_LOOKUP sent, waiting for route...", LOG_INFO);
        
        for (int i = 0; i < 40; i++) {
            Sleep(250);
            route = peer->GetRoute(prefix);
            if (route && !route->path.empty()) {
                break;
            }
        }
    }
    
    if (!route || route->path.empty()) {
        AddLog(L"[SESSION] No route to target after timeout", LOG_ERROR);
        return false;
    }
    
    WCHAR routeDebug[256];
    wsprintf(routeDebug, L"[SESSION] Route found, path len=%d", route->path.size());
    AddLog(routeDebug, LOG_SUCCESS);
    
    // Создаем сессию
    IronSession* session = peer->CreateSession(targetKey, targetPort);
    if (!session) {
        AddLog(L"[SESSION] Failed to create session", LOG_ERROR);
        delete route;
        return false;
    }
    
    // TODO: Установить путь и отправить SESSION_INIT
    // Пока заглушка - просто создаем сессию
    bool result = true;
    
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION] CreateSessionToIPv6 %s", result ? L"SUCCESS" : L"FAILED");
    AddLog(debug, result ? LOG_SUCCESS : LOG_ERROR);
    
    session->Release();
    delete route;
    
    return result;
}

// ============================================================================
// АСИНХРОННАЯ РАБОТА С СЕССИЯМИ
// ============================================================================

void CYggdrasilCore::AddPendingSession(LPCWSTR ipv6Address, int targetPort) {
    // Парсим IPv6 строку в байты
    BYTE ipv6[16] = {0};
    const WCHAR* p = ipv6Address;
    int group = 0;
    
    while (group < 8 && *p) {
        unsigned long val = 0;
        int digits = 0;
        
        while (digits < 4 && *p && *p != L':') {
            WCHAR c = *p++;
            val <<= 4;
            if (c >= L'0' && c <= L'9') val |= (c - L'0');
            else if (c >= L'a' && c <= L'f') val |= (c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') val |= (c - L'A' + 10);
            digits++;
        }
        
        ipv6[group*2] = (val >> 8) & 0xFF;
        ipv6[group*2+1] = val & 0xFF;
        group++;
        
        if (*p == L':') p++;
        else if (*p == 0) break;
    }
    
    if (group != 8) {
        AddLog(L"[PENDING] Invalid IPv6 format", LOG_ERROR);
        return;
    }
    
    // Получаем partial key из IPv6
    BYTE targetKey[32];
    YggCrypto::DerivePartialKeyFromIPv6(targetKey, ipv6);
    
    // Получаем префикс для логирования
    char prefix[33];
    for (int i = 0; i < 16; i++) {
        sprintf(prefix + i*2, "%02x", targetKey[i]);
    }
    prefix[32] = 0;
    
    // Находим пир
    IronPeer* peer = NULL;
    EnterCriticalSection(&m_peersLock);
    if (!m_peers.empty()) {
        peer = m_peers[0];
    }
    LeaveCriticalSection(&m_peersLock);
    
    if (!peer) {
        AddLog(L"[PENDING] No peer connected", LOG_ERROR);
        return;
    }
    
    // Добавляем в ожидающие
    peer->AddPendingSession(targetKey, targetPort);
    
    WCHAR debug[256];
    wsprintf(debug, L"[PENDING] Session added for %S", prefix);
    AddLog(debug, LOG_SUCCESS);
}

// Парсинг IPv6 строки в байты
static bool ParseIPv6String(LPCWSTR ipv6Str, BYTE* outBytes) {
    // Простой парсер для форматов типа 200:4caa:b3ab:d620:b940:1d43:dc54:4a94
    int values[8] = {0};
    int count = swscanf(ipv6Str, L"%x:%x:%x:%x:%x:%x:%x:%x", 
                        &values[0], &values[1], &values[2], &values[3],
                        &values[4], &values[5], &values[6], &values[7]);
    if (count != 8) return false;
    
    for (int i = 0; i < 8; i++) {
        outBytes[i * 2] = (values[i] >> 8) & 0xFF;
        outBytes[i * 2 + 1] = values[i] & 0xFF;
    }
    return true;
}

// Получение сессии по IPv6 (для HTTP прокси)
IronSession* CYggdrasilCore::GetSessionForIPv6(LPCWSTR ipv6Address) {
    // Парсим IPv6 строку
    BYTE ipv6Bytes[16];
    if (!ParseIPv6String(ipv6Address, ipv6Bytes)) {
        return NULL;
    }
    
    // Ищем пир
    EnterCriticalSection(&m_peersLock);
    if (m_peers.empty()) {
        LeaveCriticalSection(&m_peersLock);
        return NULL;
    }
    IronPeer* peer = m_peers[0];
    LeaveCriticalSection(&m_peersLock);
    
    // Ищем сессию по IPv6
    return peer->GetSessionByIPv6(ipv6Bytes);
}

IronPeer* CYggdrasilCore::GetPeerForSession(IronSession* session) {
    EnterCriticalSection(&m_peersLock);
    for (size_t i = 0; i < m_peers.size(); i++) {
        if (m_peers[i]->HasSession(session)) {
            LeaveCriticalSection(&m_peersLock);
            return m_peers[i];
        }
    }
    LeaveCriticalSection(&m_peersLock);
    return NULL;
}

bool CYggdrasilCore::GetPathToIPv6(LPCWSTR ipv6Address, vector<BYTE>& outPath) {
    // Парсим IPv6
    BYTE ipv6Bytes[16];
    if (!ParseIPv6String(ipv6Address, ipv6Bytes)) {
        return false;
    }

    // Получаем первый пир
    EnterCriticalSection(&m_peersLock);
    if (m_peers.empty()) {
        LeaveCriticalSection(&m_peersLock);
        return false;
    }
    IronPeer* peer = m_peers[0];
    LeaveCriticalSection(&m_peersLock);

    // Запрашиваем path (по IPv6)
    return peer->GetPathToIPv6(ipv6Bytes, outPath);
}

bool CYggdrasilCore::ForceRecreateSessionToIPv6(LPCWSTR ipv6Address, int port) {
    BYTE ipv6Bytes[16];
    if (!ParseIPv6String(ipv6Address, ipv6Bytes)) {
        AddLog(L"[RECREATE] Failed to parse IPv6", LOG_ERROR);
        return false;
    }

    EnterCriticalSection(&m_peersLock);
    if (m_peers.empty()) {
        LeaveCriticalSection(&m_peersLock);
        AddLog(L"[RECREATE] No peer available", LOG_ERROR);
        return false;
    }
    IronPeer* peer = m_peers[0];
    LeaveCriticalSection(&m_peersLock);

    // Получаем существующую сессию для извлечения полного ключа (32 байта)
    IronSession* oldSession = peer->GetSessionByIPv6(ipv6Bytes);
    if (!oldSession) {
        AddLog(L"[RECREATE] No existing session to recreate", LOG_WARN);
        return false;
    }
    BYTE remoteKey[32];
    memcpy(remoteKey, oldSession->GetRemoteKey(), 32);
    oldSession->Release();

    // Получаем путь из таблицы маршрутизации
    vector<BYTE> path;
    if (!peer->GetPathToIPv6(ipv6Bytes, path)) {
        AddLog(L"[RECREATE] No path in routing table", LOG_ERROR);
        return false;
    }

    // Атомарно закрываем старую сессию и создаём новую через CheckPendingSessionsWithFullKey.
    // Этот метод выполняет close+create под одним m_sessionsLock, исключая race condition,
    // при которой SESSION_ACK приходит в окно между CloseSession и CreateSession.
    // SESSION_INIT отправляется асинхронно в фоновом потоке (SessionInitThreadProc).
    AddLog(L"[RECREATE] Triggering atomic session recreate...", LOG_DEBUG);
    peer->CheckPendingSessionsWithFullKey(remoteKey, path);
    return true;
}
