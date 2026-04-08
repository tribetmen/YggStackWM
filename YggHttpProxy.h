// YggHttpProxy.h - HTTP/HTTPS Proxy for Yggdrasil (Windows Mobile Version)
#pragma once

#include <winsock2.h>
#include <vector>
#include "YggTypes.h"

#define HTTP_PROXY_PORT     8080
#define HTTP_MAX_CLIENTS    32   // Макс параллельных соединений (thread-per-connection)
#define PROXY_BUFFER_SIZE   4096
#define RELAY_TIMEOUT_MS    600000 // 600 seconds (10 min)

class CYggHttpProxy {
private:
    SOCKET m_listenSocket;
    WORD m_listenPort;
    HANDLE m_hServerThread;
    volatile BOOL m_bRunning;
    CYggdrasilCore* m_pCore;
    
    // Счётчик активных клиентских потоков
    volatile LONG m_activeClients;
    CRITICAL_SECTION m_clientsLock;

    static DWORD WINAPI ServerThreadProc(LPVOID lpParam);
    static DWORD WINAPI ClientThreadProc(LPVOID lpParam);  // Один поток на клиента

    bool AcceptClient();
    void HandleClient(SOCKET clientSocket);

    // Request parser supporting HTTP GET/POST and HTTPS CONNECT
    bool ParseRequest(const char* request, char* method, char* host, int* port, char* path, bool* isConnect);

    bool IsYggdrasilHost(const char* host);

    // Строит HTTP/1.1 запрос для сервера: переписывает первую строку и фильтрует hop-by-hop заголовки
    // Возвращает длину результата в outBuf (буфер должен быть PROXY_BUFFER_SIZE)
    int BuildServerRequest(const char* method, const char* path, const char* headersStart, int headersLen,
                           char* outBuf, int outBufSize, const char* realHost = NULL,
                           const char* httpVer = "HTTP/1.0");

    // Bi-directional non-blocking relay
    bool RelayData(SOCKET clientSocket, SOCKET targetSocket);
    void RelayThroughSession(SOCKET clientSocket, IronSession* session, int streamId, LPCWSTR ipv6, int port,
                             const char* initialData = NULL, int initialLen = 0, bool isConnect = false);

    // DNS-резолвер через Yggdrasil сессию к DNS-серверу
    // Возвращает true и заполняет outIPv6 (16 байт) если нашёл AAAA-запись в диапазоне 200::/7
    // Возвращает true и заполняет outIPv4 (строка) если нашёл только A-запись
    // Возвращает false если резолв не удался
    bool ResolveViaYggDns(const char* hostname, BYTE* outIPv6, char* outIPv4);

public:
    CYggHttpProxy();
    ~CYggHttpProxy();

    bool Start(WORD port = HTTP_PROXY_PORT);
    void Stop();
    bool IsRunning() const { return m_bRunning != FALSE; }
    void SetCore(CYggdrasilCore* pCore) { m_pCore = pCore; }
};

// ============================================================================
// DNS over Yggdrasil
// DNS-сервер внутри сети Yggdrasil (адрес в диапазоне 200::/7)
// Можно переопределить перед вызовом Start() через SetDnsServer()
// ============================================================================
#define YGG_DNS_SERVER_DEFAULT  L"308:25:40:bd::"
#define YGG_DNS_PORT            53

// Публичные Alfis DNS серверы (Revertron) для fallback
// 308:25:40:bd:: - Bratislava, SK
// 308:62:45:62:: - Amsterdam, NL
// 308:84:68:55:: - Frankfurt, DE
// 308:c8:48:45:: - Buffalo, US

// Global functions
bool StartHttpProxy(WORD port = HTTP_PROXY_PORT);
void StopHttpProxy();
bool IsHttpProxyRunning();

// Настройка DNS-сервера (вызывать до Start или в любой момент — thread-safe через CRITICAL_SECTION)
void SetYggDnsServer(LPCWSTR ipv6);