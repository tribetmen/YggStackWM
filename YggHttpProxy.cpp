// YggHttpProxy.cpp - HTTP/HTTPS Proxy for Yggdrasil
#include "stdafx.h"
#include "YggHttpProxy.h"
#include "YggdrasilCore.h"
#include "IronSession.h"
#include "ygg_constants.h"
#include "IronPeer.h"

#pragma comment(lib, "ws2.lib")

extern void AddLog(LPCWSTR text, BYTE type);
extern HWND g_hWnd;
extern BOOL g_httpProxyRunning;

static CYggHttpProxy* g_pHttpProxy = NULL;

CYggHttpProxy::CYggHttpProxy() {
    m_listenSocket = INVALID_SOCKET;
    m_listenPort = HTTP_PROXY_PORT;
    m_hServerThread = NULL;
    m_bRunning = FALSE;
    m_pCore = NULL;
}

CYggHttpProxy::~CYggHttpProxy() {
    Stop();
}

bool CYggHttpProxy::Start(WORD port) {
    if (m_bRunning) return true;
    
    m_listenPort = port;
    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) {
        AddLog(L"[HTTP] Socket create failed", LOG_ERROR);
        return false;
    }
    
    int reuse = 1;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    
    if (bind(m_listenSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        AddLog(L"[HTTP] Bind failed", LOG_ERROR);
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        return false;
    }
    
    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        AddLog(L"[HTTP] Listen failed", LOG_ERROR);
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        return false;
    }
    
    m_bRunning = TRUE;
    m_hServerThread = CreateThread(NULL, 0, ServerThreadProc, this, 0, NULL);
    
    WCHAR debug[256];
    wsprintf(debug, L"[HTTP] Proxy started on 127.0.0.1:%d", port);
    AddLog(debug, LOG_SUCCESS);
    
    return true;
}

void CYggHttpProxy::Stop() {
    if (!m_bRunning) return;
    m_bRunning = FALSE;
    
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    
    if (m_hServerThread) {
        WaitForSingleObject(m_hServerThread, 2000);
        CloseHandle(m_hServerThread);
        m_hServerThread = NULL;
    }
    AddLog(L"[HTTP] Proxy stopped", LOG_INFO);
}

DWORD WINAPI CYggHttpProxy::ServerThreadProc(LPVOID lpParam) {
    CYggHttpProxy* pProxy = (CYggHttpProxy*)lpParam;
    while (pProxy->m_bRunning) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(pProxy->m_listenSocket, &fdset);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int result = select(0, &fdset, NULL, NULL, &tv);
        if (result > 0 && FD_ISSET(pProxy->m_listenSocket, &fdset)) {
            pProxy->AcceptClient();
        }
    }
    return 0;
}

DWORD WINAPI CYggHttpProxy::ClientThreadProc(LPVOID lpParam) {
    SOCKET clientSocket = (SOCKET)(DWORD)lpParam;
    CYggHttpProxy* pProxy = g_pHttpProxy;
    if (pProxy) {
        pProxy->HandleClient(clientSocket);
    }
    closesocket(clientSocket);
    return 0;
}

bool CYggHttpProxy::AcceptClient() {
    struct sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);
    SOCKET clientSocket = accept(m_listenSocket, (struct sockaddr*)&clientAddr, &addrLen);
    if (clientSocket == INVALID_SOCKET) return false;
    
    int flag = 1;
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    
    HANDLE hThread = CreateThread(NULL, 0, ClientThreadProc, (LPVOID)clientSocket, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return true;
}

void CYggHttpProxy::HandleClient(SOCKET clientSocket) {
    char buffer[PROXY_BUFFER_SIZE];
    int totalReceived = 0;
    
    // Безопасное чтение заголовков, чтобы поток не завис навсегда
    while (totalReceived < sizeof(buffer) - 1) {
        fd_set fdread;
        FD_ZERO(&fdread);
        FD_SET(clientSocket, &fdread);
        struct timeval tv;
        tv.tv_sec = 5; // Ждем запрос максимум 5 секунд
        tv.tv_usec = 0;
        
        if (select(0, &fdread, NULL, NULL, &tv) <= 0) return;
        
        int received = recv(clientSocket, buffer + totalReceived, sizeof(buffer) - 1 - totalReceived, 0);
        if (received <= 0) return;
        
        totalReceived += received;
        buffer[totalReceived] = '\0';
        
        if (strstr(buffer, "\r\n\r\n") != NULL) break;
    }
    
    if (totalReceived <= 0) return;

    char firstLine[256];
    strncpy(firstLine, buffer, sizeof(firstLine) - 1);
    firstLine[sizeof(firstLine) - 1] = '\0';
    char* end = strstr(firstLine, "\r\n");
    if (end) *end = '\0';
    
    WCHAR debug[512];
    MultiByteToWideChar(CP_ACP, 0, firstLine, -1, debug, 512);
    AddLog(debug, LOG_INFO);
    
    char method[16], host[256], path[1024];
    int port = 80;
    bool isConnect = false;
    
    if (!ParseRequest(buffer, method, host, &port, path, &isConnect)) {
        const char* err = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(clientSocket, err, strlen(err), 0);
        return;
    }
    
    if (IsYggdrasilHost(host)) {
        if (!m_pCore) return;
        
        WCHAR ipv6Str[64];
        MultiByteToWideChar(CP_ACP, 0, host, -1, ipv6Str, 64);
        
        // Проверяем, есть ли уже сессия (для переиспользования)
        IronSession* existingSession = m_pCore->GetSessionForIPv6(ipv6Str);
        if (existingSession) {
            if (existingSession->IsReady()) {
                AddLog(L"[HTTP] Reusing existing session", LOG_DEBUG);
                RelayThroughSession(clientSocket, existingSession, ipv6Str, port, buffer, totalReceived, isConnect);
                existingSession->Release();
                return;
            }
            existingSession->Release(); // Не ready, отпускаем и идем дальше
        }
        
        if (!m_pCore->SendPathLookupToIPv6(ipv6Str)) {
            const char* err = "HTTP/1.1 502 Bad Gateway\r\n\r\nRoute not found";
            send(clientSocket, err, strlen(err), 0);
            return;
        }
        
        m_pCore->AddPendingSession(ipv6Str, port);
        
        IronSession* session = NULL;
        for (int i = 0; i < 150; i++) {
            session = m_pCore->GetSessionForIPv6(ipv6Str);
            if (session && session->IsReady()) {
                break; // Сессия криптографически готова, выходим из ожидания
            }
            if (session) {
                session->Release();
            }
            session = NULL;
            Sleep(100);
        }
        
        if (!session) {
            const char* err = "HTTP/1.1 504 Gateway Timeout\r\n\r\nSession timeout";
            send(clientSocket, err, strlen(err), 0);
            return;
        }
        
        RelayThroughSession(clientSocket, session, ipv6Str, port, buffer, totalReceived, isConnect);
        
        // Освобождаем ссылку на сессию (крипто-туннель остается жить в Core)
        session->Release();
        return;
        
    } else {
        SOCKET targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (targetSocket == INVALID_SOCKET) return;
        int flag = 1;
        setsockopt(targetSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
        struct hostent* hostent = gethostbyname(host);
        if (!hostent) { closesocket(targetSocket); return; }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)port);
        memcpy(&addr.sin_addr, hostent->h_addr, hostent->h_length);
        if (connect(targetSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) { closesocket(targetSocket); return; }
        
        if (isConnect) {
            const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(clientSocket, ok, strlen(ok), 0);
        } else {
            send(targetSocket, buffer, totalReceived, 0);
        }
        RelayData(clientSocket, targetSocket);
        closesocket(targetSocket);
    }
}

bool CYggHttpProxy::ParseRequest(const char* request, char* method, char* host, int* port, char* path, bool* isConnect) {
    char reqCopy[1024];
    strncpy(reqCopy, request, sizeof(reqCopy) - 1);
    reqCopy[sizeof(reqCopy) - 1] = '\0';
    
    char* firstLineEnd = strstr(reqCopy, "\r\n");
    if (firstLineEnd) *firstLineEnd = '\0';
    
    char* space1 = strchr(reqCopy, ' ');
    if (!space1) return false;
    
    *space1 = '\0';
    strcpy(method, reqCopy);
    *isConnect = (strcmp(method, "CONNECT") == 0);
    
    char* urlStr = space1 + 1;
    while (*urlStr == ' ') urlStr++;
    
    char* space2 = strchr(urlStr, ' ');
    if (space2) *space2 = '\0';
    
    if (*isConnect) {
        char* portDiv = strchr(urlStr, ':');
        if (portDiv) {
            *portDiv = '\0';
            strcpy(host, urlStr);
            *port = atoi(portDiv + 1);
        } else {
            strcpy(host, urlStr);
            *port = 443;
        }
        strcpy(path, "");
        return true;
    }
    
    if (strncmp(urlStr, "http://", 7) == 0) {
        urlStr += 7;
        char* pathDiv = strchr(urlStr, '/');
        if (pathDiv) {
            strcpy(path, pathDiv);
            *pathDiv = '\0';
        } else {
            strcpy(path, "/");
        }
        
        if (urlStr[0] == '[') {
            char* bracketEnd = strchr(urlStr, ']');
            if (!bracketEnd) return false;
            *bracketEnd = '\0';
            strcpy(host, urlStr + 1);
            if (*(bracketEnd + 1) == ':') {
                *port = atoi(bracketEnd + 2);
            } else {
                *port = 80;
            }
        } else {
            char* portDiv = strchr(urlStr, ':');
            if (portDiv) {
                *portDiv = '\0';
                strcpy(host, urlStr);
                *port = atoi(portDiv + 1);
            } else {
                strcpy(host, urlStr);
                *port = 80;
            }
        }
        return true;
    }
    return false;
}

bool CYggHttpProxy::IsYggdrasilHost(const char* host) {
    if (strlen(host) < 4) return false;
    if (strchr(host, ':') == NULL) return false;
    // Проверяем диапазон 0200::/7 (все Yggdrasil адреса: 200-3ff)
    // Первая цифра должна быть 2 или 3 (0200-03ff)
    if (host[0] == '2' || host[0] == '3') {
        // Проверяем что это hex-цифра вторая (0-9, a-f, A-F)
        char c = host[1];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            return true;
        }
    }
    return false;
}

bool CYggHttpProxy::RelayData(SOCKET clientSocket, SOCKET targetSocket) {
    char buffer[PROXY_BUFFER_SIZE];
    fd_set readfds;
    DWORD lastActivity = GetTickCount();
    
    while (m_bRunning) {
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(targetSocket, &readfds);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int result = select(0, &readfds, NULL, NULL, &tv);
        if (result < 0) break;
        
        if (result > 0) {
            if (FD_ISSET(clientSocket, &readfds)) {
                int bytes = recv(clientSocket, buffer, sizeof(buffer), 0);
                if (bytes <= 0) break;
                if (send(targetSocket, buffer, bytes, 0) <= 0) break;
                lastActivity = GetTickCount();
            }
            if (FD_ISSET(targetSocket, &readfds)) {
                int bytes = recv(targetSocket, buffer, sizeof(buffer), 0);
                if (bytes <= 0) break;
                if (send(clientSocket, buffer, bytes, 0) <= 0) break;
                lastActivity = GetTickCount();
            }
        }
        if (GetTickCount() - lastActivity > RELAY_TIMEOUT_MS) break;
    }
    return true;
}

void CYggHttpProxy::RelayThroughSession(SOCKET clientSocket, IronSession* session, LPCWSTR ipv6, int port,
                                        const char* initialData, int initialLen, bool isConnect) {
    IronPeer* peer = m_pCore ? m_pCore->GetPeerForSession(session) : NULL;
    if (!peer) return;
    
    vector<BYTE> path;
    if (!m_pCore->GetPathToIPv6(ipv6, path)) return;
    
    // Сбрасываем TCP только если сессия закрыта или в FIN_WAIT.
    // Если сессия ESTABLISHED - используем её для переиспользования соединения.
    TcpState currentState = session->GetTcpState();
    if (currentState == TCP_CLOSED || currentState == TCP_FIN_WAIT) {
        session->ResetTcpState();
    } else if (currentState == TCP_ESTABLISHED) {
        AddLog(L"[HTTP] Reusing existing ESTABLISHED session", LOG_DEBUG);
    }
    
    // Отправляем SYN только если соединение не установлено
    if (session->GetTcpState() != TCP_ESTABLISHED) {
        session->SendSYN(peer, path);
        int waitCount = 0;
        while (waitCount < 50 && session->GetTcpState() != TCP_ESTABLISHED) {
            Sleep(100);
            waitCount++;
        }
    }
    
    if (session->GetTcpState() != TCP_ESTABLISHED) {
        const char* err = "HTTP/1.1 504 Gateway Timeout\r\n\r\nVirtual TCP failed";
        send(clientSocket, err, strlen(err), 0);
        return;
    }
    
    u_long nonblock = 1;
    ioctlsocket(clientSocket, FIONBIO, &nonblock);
    
    if (isConnect) {
        const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(clientSocket, ok, strlen(ok), 0);
    } else if (initialData && initialLen > 0) {
        // Теперь эти 708 байт гарантированно отправятся, так как статус = TCP_ESTABLISHED
        session->QueueOrSendData(peer, path, (BYTE*)initialData, initialLen);
    }
    
    char buffer[PROXY_BUFFER_SIZE];
    fd_set fdset;
    DWORD lastActivity = GetTickCount();
    DWORD sessionStartTime = GetTickCount(); // Жесткий таймаут 30 сек на всю сессию
    
    while (m_bRunning) {
        // Жесткий таймаут 30 секунд - защита от зависших сессий
        if (GetTickCount() - sessionStartTime > 30000) {
            AddLog(L"[HTTP] Hard session timeout (30s), closing", LOG_WARN);
            break;
        }
        FD_ZERO(&fdset);
        FD_SET(clientSocket, &fdset);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        
        int result = select(0, &fdset, NULL, NULL, &tv);
        
        if (result > 0 && FD_ISSET(clientSocket, &fdset)) {
            int received = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (received > 0) {
                session->QueueOrSendData(peer, path, (BYTE*)buffer, received);
                lastActivity = GetTickCount();
            } else if (received == 0) {
                AddLog(L"[HTTP] Browser closed connection, sending FIN", LOG_INFO);
                session->SendFIN(peer, path);
                break;
            } else {
                if (WSAGetLastError() != WSAEWOULDBLOCK) {
                    session->SendFIN(peer, path);
                    break;
                }
            }
        }
        
        DWORD recvLen = 0;
        BYTE recvBuffer[PROXY_BUFFER_SIZE];
        if (session->ReadData(recvBuffer, sizeof(recvBuffer), recvLen, 0)) {
            if (recvLen > 0) {
                int sent = send(clientSocket, (char*)recvBuffer, recvLen, 0);
                if (sent <= 0 && WSAGetLastError() != WSAEWOULDBLOCK) break;
                lastActivity = GetTickCount();
            }
        } else {
            // Как только сервер прислал флаг FIN и мы отдали все данные браузеру, закрываем сокет.
            // Браузер моментально отобразит загруженную страницу без зависаний.
            if (session->GetTcpState() == TCP_FIN_WAIT || session->GetTcpState() == TCP_CLOSED) {
                AddLog(L"[HTTP] Remote server sent FIN. Page loaded. Closing tunnel.", LOG_SUCCESS);
                break;
            }
        }
        
        if (GetTickCount() - lastActivity > 30000) {
            AddLog(L"[HTTP] Relay timeout over session", LOG_WARN);
            break;
        }
    }
    AddLog(L"[HTTP] Yggdrasil session relay ended", LOG_INFO);
}

bool StartHttpProxy(WORD port) {
    if (!g_pHttpProxy) g_pHttpProxy = new CYggHttpProxy();
    extern CYggdrasilCore* g_pYggCore;
    if (g_pYggCore) g_pHttpProxy->SetCore(g_pYggCore);
    return g_pHttpProxy->Start(port);
}

void StopHttpProxy() {
    if (g_pHttpProxy) g_pHttpProxy->Stop();
}

bool IsHttpProxyRunning() {
    return g_pHttpProxy && g_pHttpProxy->IsRunning();
}