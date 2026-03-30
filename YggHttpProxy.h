// YggHttpProxy.h - HTTP/HTTPS Proxy for Yggdrasil (Windows Mobile Version)
#pragma once

#include <winsock2.h>
#include <vector>
#include "YggTypes.h"

#define HTTP_PROXY_PORT     8080
#define HTTP_MAX_CLIENTS    16
#define PROXY_BUFFER_SIZE   8192
#define RELAY_TIMEOUT_MS    60000 // 60 seconds of inactivity timeout

class CYggHttpProxy {
private:
    SOCKET m_listenSocket;
    WORD m_listenPort;
    HANDLE m_hServerThread;
    volatile BOOL m_bRunning;
    CYggdrasilCore* m_pCore;
    
    static DWORD WINAPI ServerThreadProc(LPVOID lpParam);
    static DWORD WINAPI ClientThreadProc(LPVOID lpParam);
    
    bool AcceptClient();
    void HandleClient(SOCKET clientSocket);
    
    // Request parser supporting HTTP GET/POST and HTTPS CONNECT
    bool ParseRequest(const char* request, char* method, char* host, int* port, char* path, bool* isConnect);
    
    bool IsYggdrasilHost(const char* host);
    
    // Bi-directional non-blocking relay
    bool RelayData(SOCKET clientSocket, SOCKET targetSocket);
    void RelayThroughSession(SOCKET clientSocket, IronSession* session, LPCWSTR ipv6, int port, 
                             const char* initialData = NULL, int initialLen = 0, bool isConnect = false);
    
public:
    CYggHttpProxy();
    ~CYggHttpProxy();
    
    bool Start(WORD port = HTTP_PROXY_PORT);
    void Stop();
    bool IsRunning() const { return m_bRunning != FALSE; }
    void SetCore(CYggdrasilCore* pCore) { m_pCore = pCore; }
};

// Global functions
bool StartHttpProxy(WORD port = HTTP_PROXY_PORT);
void StopHttpProxy();
bool IsHttpProxyRunning();