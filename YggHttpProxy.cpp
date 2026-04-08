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
    m_activeClients = 0;
    InitializeCriticalSection(&m_clientsLock);
}

CYggHttpProxy::~CYggHttpProxy() {
    Stop();
    DeleteCriticalSection(&m_clientsLock);
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
    m_activeClients = 0;

    m_hServerThread = CreateThread(NULL, 32 * 1024, ServerThreadProc, this, 0, NULL);

    WCHAR debug[256];
    wsprintf(debug, L"[HTTP] Proxy started on 127.0.0.1:%d (thread-per-connection, max %d)", port, HTTP_MAX_CLIENTS);
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

    // Ждём завершения всех клиентских потоков (макс 5 сек)
    for (int i = 0; i < 50 && m_activeClients > 0; i++) {
        Sleep(100);
    }

    if (m_hServerThread) {
        WaitForSingleObject(m_hServerThread, 2000);
        CloseHandle(m_hServerThread);
        m_hServerThread = NULL;
    }

    // Ждём завершения всех клиентских потоков (макс 5 сек)
    for (int i = 0; i < 50 && m_activeClients > 0; i++) {
        Sleep(100);
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

// Поток для обработки одного клиента (thread-per-connection)
DWORD WINAPI CYggHttpProxy::ClientThreadProc(LPVOID lpParam) {
    SOCKET clientSocket = (SOCKET)lpParam;
    CYggHttpProxy* pProxy = g_pHttpProxy;
    
    if (pProxy && clientSocket != INVALID_SOCKET) {
        pProxy->HandleClient(clientSocket);
        closesocket(clientSocket);
    }
    
    // Уменьшаем счётчик активных клиентов
    if (pProxy) {
        InterlockedDecrement((LONG*)&pProxy->m_activeClients);
    }
    return 0;
}

bool CYggHttpProxy::AcceptClient() {
    struct sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);
    SOCKET clientSocket = accept(m_listenSocket, (struct sockaddr*)&clientAddr, &addrLen);
    if (clientSocket == INVALID_SOCKET) return false;

    // Проверяем лимит параллельных соединений
    LONG currentClients = InterlockedIncrement((LONG*)&m_activeClients);
    {
        WCHAR dbgAcc[128];
        wsprintf(dbgAcc, L"[HTTP] Accept: activeClients=%d", currentClients);
        AddLog(dbgAcc, LOG_DEBUG);
    }
    if (currentClients > HTTP_MAX_CLIENTS) {
        InterlockedDecrement((LONG*)&m_activeClients);
        WCHAR dbgLim[128];
        wsprintf(dbgLim, L"[HTTP] Max clients (%d) reached, rejecting", HTTP_MAX_CLIENTS);
        AddLog(dbgLim, LOG_WARN);
        const char* busy = "HTTP/1.1 503 Service Unavailable\r\n\r\nToo many connections";
        send(clientSocket, busy, strlen(busy), 0);
        closesocket(clientSocket);
        return false;
    }

    int flag = 1;
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

    int bufSize = 256 * 1024;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(bufSize));
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, (char*)&bufSize, sizeof(bufSize));

    // Создаём поток для этого клиента
    HANDLE hThread = CreateThread(NULL, 128 * 1024, ClientThreadProc, (LPVOID)clientSocket, 0, NULL);
    if (!hThread) {
        InterlockedDecrement((LONG*)&m_activeClients);
        WCHAR errLog[128];
        wsprintf(errLog, L"[HTTP] CreateThread failed! err=%d activeClients=%d", GetLastError(), m_activeClients);
        AddLog(errLog, LOG_ERROR);
        const char* err = "HTTP/1.1 503 Service Unavailable\r\n\r\nServer error";
        send(clientSocket, err, strlen(err), 0);
        closesocket(clientSocket);
        return false;
    }
    
    CloseHandle(hThread); // Не ждём завершения, поток сам закроется
    return true;
}


// HandleClient вызывается из отдельного потока для каждого клиента
// (thread-per-connection architecture)
// Поддерживает HTTP keep-alive: после каждого запроса ждёт следующий (Opera Mobile требует этого)
void CYggHttpProxy::HandleClient(SOCKET clientSocket) {
    char buffer[PROXY_BUFFER_SIZE];

    // Keep-alive loop: один поток обслуживает несколько последовательных запросов Opera
    while (m_bRunning) {
    int totalReceived = 0;

    // Безопасное чтение заголовков. Первый запрос ждём 5 сек, keep-alive — 3 сек.
    while (totalReceived < (int)sizeof(buffer) - 1) {
        fd_set fdread;
        FD_ZERO(&fdread);
        FD_SET(clientSocket, &fdread);
        struct timeval tv;
        tv.tv_sec = (totalReceived == 0) ? 5 : 3;
        tv.tv_usec = 0;

        if (select(0, &fdread, NULL, NULL, &tv) <= 0) return; // таймаут или ошибка — закрываем

        int received = recv(clientSocket, buffer + totalReceived, sizeof(buffer) - 1 - totalReceived, 0);
        if (received <= 0) return; // Opera закрыла соединение

        totalReceived += received;
        buffer[totalReceived] = '\0';

        if (strstr(buffer, "\r\n\r\n") != NULL) break;
    }

    if (totalReceived <= 0) return;
    
    // Включаем TCP_NODELAY для клиентского сокета - отправляем данные браузеру сразу
    int flag = 1;
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

    char firstLine[256];
    strncpy(firstLine, buffer, sizeof(firstLine) - 1);
    firstLine[sizeof(firstLine) - 1] = '\0';
    char* end = strstr(firstLine, "\r\n");
    if (end) *end = '\0';
    
    WCHAR debug[512];
    MultiByteToWideChar(CP_ACP, 0, firstLine, -1, debug, 512);
    AddLog(debug, LOG_INFO);
    
    char method[16], host[256], path[512];
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
        
        // === УПРОЩЁННАЯ ЛОГИКА ===
        // 1. Получаем или создаём сессию для этого IPv6
        // 2. Ждём пока она будет готова (с таймаутом)
        // 3. Берём стрим и релеим
        
        IronSession* session = NULL;
        int waitCycles = 0;

        {
            WCHAR dbgClients[128];
            wsprintf(dbgClients, L"[HTTP] Active clients: %d/%d", m_activeClients, HTTP_MAX_CLIENTS);
            AddLog(dbgClients, LOG_DEBUG);
        }

        while (waitCycles < 100 && m_bRunning) {  // Макс 10 секунд ожидания
            IronSession* candidate = m_pCore->GetSessionForIPv6(ipv6Str);
            
            if (candidate) {
                // Сессия существует
                if (candidate->IsReady() && candidate->TryAcquireUse()) {
                    // Сессия готова и мы её захватили
                    session = candidate;
                    break;
                }

                // Сессия не готова или занята - проверяем состояние
                if (candidate->IsClosed()) {
                    // Сессия закрыта keepalive - создаём новую
                    candidate->Release();
                    AddLog(L"[HTTP] Session closed, creating new", LOG_INFO);
                    goto create_new_session;
                }

                if (!candidate->IsReady()) {
                    // Сессия не готова — ждём немного (не пересоздаём немедленно, это вызывало цикл)
                    candidate->Release();
                    Sleep(100);
                    waitCycles++;
                    continue;
                }

                if (candidate->IsTimedOut(60000) && !candidate->IsInUse()) {
                    // Сессия протухла и свободна - сбрасываем
                    candidate->ResetTcpState();
                    candidate->Release();
                    AddLog(L"[HTTP] Session timed out, reinitializing", LOG_INFO);
                    goto create_new_session;
                }

                candidate->Release();
            } else {
                // Сессии нет - создаём
                goto create_new_session;
            }
            
            Sleep(100);
            waitCycles++;
        }
        
        if (!session) {
            AddLog(L"[HTTP] Timeout waiting for session", LOG_WARN);
            const char* err = "HTTP/1.1 504 Gateway Timeout\r\n\r\nSession busy";
            send(clientSocket, err, strlen(err), 0);
            return;
        }
        
        // Сессия готова - берём стрим и релеим
        goto do_relay;
        
    create_new_session:
        // Отправляем PATH_LOOKUP для создания новой сессии
        if (!m_pCore->SendPathLookupToIPv6(ipv6Str)) {
            const char* err = "HTTP/1.1 502 Bad Gateway\r\n\r\nRoute not found";
            send(clientSocket, err, strlen(err), 0);
            return;
        }
        m_pCore->AddPendingSession(ipv6Str, port);
        
        // Ждём создания сессии
        waitCycles = 0;
        while (waitCycles < 100 && m_bRunning) {
            IronSession* candidate = m_pCore->GetSessionForIPv6(ipv6Str);
            if (candidate && candidate->IsReady() && candidate->TryAcquireUse()) {
                session = candidate;
                break;
            }
            if (candidate) candidate->Release();
            Sleep(100);
            waitCycles++;
        }
        
        if (!session) {
            AddLog(L"[HTTP] Timeout creating session", LOG_WARN);
            const char* err = "HTTP/1.1 504 Gateway Timeout\r\n\r\nSession creation timeout";
            send(clientSocket, err, strlen(err), 0);
            return;
        }
        
    do_relay:
        // Получили сессию - берём стрим и релеим
        int streamId = session->AcquireStream();
        if (streamId == -1) {
            session->Release();
            WCHAR nofs[256];
            wsprintf(nofs, L"[HTTP] No free streams for %hs:%d (active=%d)", host, port, session->GetActiveStreamCount());
            AddLog(nofs, LOG_WARN);
            const char* err = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n";
            send(clientSocket, err, strlen(err), 0);
            return;
        }
        {
            WCHAR relay[512];
            wsprintf(relay, L"[HTTP] >> %hs %hs:%d%hs streamId=%d", method, host, port, path, streamId);
            AddLog(relay, LOG_INFO);
        }

        // Сохраняем оригинальный запрошенный IPv6 (сохраняем первый байт до нормализации)
        // GetSessionForIPv6 нормализует 300::->200::, поэтому m_remoteIPv6 всегда 200::.
        // Берём нормализованный адрес из сессии и восстанавливаем оригинальный первый байт из host.
        {
            BYTE reqIPv6[16];
            memcpy(reqIPv6, session->GetRemoteIPv6(), 16);
            // Первый байт берём из оригинального host строки (например "320:" -> 0x03, "200:" -> 0x02)
            // host[0] и host[1] дают старший байт первой группы
            unsigned int firstGroup = 0;
            const char* h = host;
            if (*h == '[') h++;
            while (*h && *h != ':' && *h != ']') {
                char c = *h++;
                firstGroup <<= 4;
                if (c >= '0' && c <= '9') firstGroup |= c - '0';
                else if (c >= 'a' && c <= 'f') firstGroup |= c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') firstGroup |= c - 'A' + 10;
            }
            reqIPv6[0] = (BYTE)(firstGroup >> 8);
            reqIPv6[1] = (BYTE)(firstGroup & 0xFF);
            // Обнуляем interface ID только для подсетей 300::/8 (first byte = 0x03)
            // Для узлов 200::/8 (first byte = 0x02) используем exact match без обнуления
            if (reqIPv6[0] == 0x03) {
                memset(reqIPv6 + 8, 0, 8);
            }
            session->SetRequestedIPv6(reqIPv6);
        }

        // Релеим
        RelayThroughSession(clientSocket, session, streamId, ipv6Str, port, buffer, totalReceived, isConnect);

        // Cleanup — гарантированно освобождаем стрим в любом случае (даже при ранних return в Relay)
        session->ReleaseStream(streamId);
        session->Release();
        return;
        
    } else {
        // Сначала пробуем резолвить через Yggdrasil DNS.
        // Если DNS вернул AAAA в диапазоне 200::/7 — роутим через Yggdrasil как обычный Ygg-хост.
        // Если вернул A-запись (обычный IP) — используем её вместо gethostbyname.
        // Если DNS недоступен — fallback на системный gethostbyname.
        // Пробуем DNS только если есть живой peer (иначе ждать 10 сек бессмысленно).
        IronPeer* firstPeer = m_pCore ? m_pCore->GetFirstPeer() : NULL;
        if (m_pCore && firstPeer && firstPeer->IsConnected()) {
            BYTE resolvedIPv6[16];
            char resolvedIPv4[16];
            memset(resolvedIPv6, 0, 16);
            resolvedIPv4[0] = '\0';

            bool dnsOk = ResolveViaYggDns(host, resolvedIPv6, resolvedIPv4);

            if (dnsOk && (resolvedIPv6[0] & 0xFE) == 0x02) {
                // AAAA-запись — Yggdrasil-адрес, роутим через сессию
                WCHAR ipv6Str[64];
                wsprintf(ipv6Str, L"%x:%x:%x:%x:%x:%x:%x:%x",
                    (resolvedIPv6[0]<<8)|resolvedIPv6[1],
                    (resolvedIPv6[2]<<8)|resolvedIPv6[3],
                    (resolvedIPv6[4]<<8)|resolvedIPv6[5],
                    (resolvedIPv6[6]<<8)|resolvedIPv6[7],
                    (resolvedIPv6[8]<<8)|resolvedIPv6[9],
                    (resolvedIPv6[10]<<8)|resolvedIPv6[11],
                    (resolvedIPv6[12]<<8)|resolvedIPv6[13],
                    (resolvedIPv6[14]<<8)|resolvedIPv6[15]);

                WCHAR dbgRedir[512];
                wsprintf(dbgRedir, L"[DNS] Redirecting %hs -> Ygg %s", host, ipv6Str);
                AddLog(dbgRedir, LOG_INFO);

                // Полностью дублируем Yggdrasil-ветку HandleClient для этого адреса
                IronSession* session2 = NULL;
                int waitCycles2 = 0;
                while (waitCycles2 < 100 && m_bRunning) {
                    IronSession* cand = m_pCore->GetSessionForIPv6(ipv6Str);
                    if (cand) {
                        if (cand->IsReady() && cand->TryAcquireUse()) { session2 = cand; break; }
                        if (cand->IsClosed()) { cand->Release(); break; }
                        cand->Release();
                    } else { break; }
                    Sleep(100); waitCycles2++;
                }
                if (!session2) {
                    if (!m_pCore->SendPathLookupToIPv6(ipv6Str)) {
                        const char* err = "HTTP/1.1 502 Bad Gateway\r\n\r\nRoute not found";
                        send(clientSocket, err, strlen(err), 0); return;
                    }
                    m_pCore->AddPendingSession(ipv6Str, port);
                    waitCycles2 = 0;
                    while (waitCycles2 < 100 && m_bRunning) {
                        IronSession* cand = m_pCore->GetSessionForIPv6(ipv6Str);
                        if (cand && cand->IsReady() && cand->TryAcquireUse()) { session2 = cand; break; }
                        if (cand) cand->Release();
                        Sleep(100); waitCycles2++;
                    }
                }
                if (!session2) {
                    const char* err = "HTTP/1.1 504 Gateway Timeout\r\n\r\nSession timeout";
                    send(clientSocket, err, strlen(err), 0); return;
                }
                int streamId2 = session2->AcquireStream();
                if (streamId2 == -1) {
                    session2->Release();
                    const char* err = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
                    send(clientSocket, err, strlen(err), 0); return;
                }
                RelayThroughSession(clientSocket, session2, streamId2, ipv6Str, port, buffer, totalReceived, isConnect);
                session2->ReleaseStream(streamId2);
                session2->Release();
                return;

            } else if (dnsOk && resolvedIPv4[0] != '\0') {
                // A-запись — обычный IP, подключаемся напрямую минуя gethostbyname
                SOCKET targetSocket2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (targetSocket2 == INVALID_SOCKET) return;
                int flag2 = 1;
                setsockopt(targetSocket2, IPPROTO_TCP, TCP_NODELAY, (char*)&flag2, sizeof(flag2));
                struct sockaddr_in addr2;
                memset(&addr2, 0, sizeof(addr2));
                addr2.sin_family = AF_INET;
                addr2.sin_port = htons((u_short)port);
                addr2.sin_addr.s_addr = inet_addr(resolvedIPv4);
                if (addr2.sin_addr.s_addr == INADDR_NONE || connect(targetSocket2, (struct sockaddr*)&addr2, sizeof(addr2)) != 0) {
                    closesocket(targetSocket2);
                    const char* err = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    send(clientSocket, err, (int)strlen(err), 0); return;
                }
                if (isConnect) {
                    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
                    send(clientSocket, ok, (int)strlen(ok), 0);
                } else {
                    const char* crlf2 = strstr(buffer, "\r\n");
                    if (crlf2) {
                        char newReq2[PROXY_BUFFER_SIZE];
                        const char* rest2 = crlf2 + 2;
                        int restLen2 = totalReceived - (int)(rest2 - buffer);
                        int newLen2 = BuildServerRequest(method, path, rest2, restLen2, newReq2, PROXY_BUFFER_SIZE, host);
                        send(targetSocket2, newReq2, newLen2, 0);
                    } else {
                        send(targetSocket2, buffer, totalReceived, 0);
                    }
                }
                RelayData(clientSocket, targetSocket2);
                closesocket(targetSocket2);
                return;
            }
            // DNS недоступен или вернул NXDOMAIN — fallback на системный резолвер ниже
        }

        SOCKET targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (targetSocket == INVALID_SOCKET) return;
        int flag = 1;
        setsockopt(targetSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
        struct hostent* hostent = gethostbyname(host);
        if (!hostent) {
            closesocket(targetSocket);
            const char* err = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(clientSocket, err, (int)strlen(err), 0);
            return;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)port);
        memcpy(&addr.sin_addr, hostent->h_addr, hostent->h_length);
        if (connect(targetSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            closesocket(targetSocket);
            const char* err = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(clientSocket, err, (int)strlen(err), 0);
            return;
        }
        if (isConnect) {
            const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(clientSocket, ok, (int)strlen(ok), 0);
        } else {
            const char* crlf = strstr(buffer, "\r\n");
            if (crlf) {
                char newRequest[PROXY_BUFFER_SIZE];
                const char* rest = crlf + 2;
                int restLen = totalReceived - (int)(rest - buffer);
                int newLen = BuildServerRequest(method, path, rest, restLen, newRequest, PROXY_BUFFER_SIZE, host);
                send(targetSocket, newRequest, newLen, 0);
            } else {
                send(targetSocket, buffer, totalReceived, 0);
            }
        }
        RelayData(clientSocket, targetSocket);
        closesocket(targetSocket);
        return;
    }

    } // end keep-alive loop
}

// Строит HTTP/1.1 запрос для сервера:
//   - Первая строка: "METHOD /path HTTP/1.1\r\n"
//   - Host: заменяется на realHost (реальный 200:: адрес узла, а не 300:: из браузера)
//   - Заголовки из headersStart копируются построчно, пропуская hop-by-hop
//   - Добавляет "Connection: close\r\n" чтобы сервер не ждал следующего запроса
// Возвращает итоговую длину.
int CYggHttpProxy::BuildServerRequest(const char* method, const char* path,
                                      const char* headersStart, int headersLen,
                                      char* outBuf, int outBufSize,
                                      const char* realHost,
                                      const char* httpVer) {
    int len = 0;
    // HTTP/1.0 по умолчанию — сервер не шлёт chunked, Opera парсит ответ без проблем.
    // HTTP/1.1 используется только для Range-retry (докачка), чтобы сервер принял Range:.
    len += _snprintf(outBuf + len, outBufSize - len - 1, "%s %s %s\r\n", method, path, httpVer);
    if (realHost && realHost[0]) {
        // IPv6-адреса (Yggdrasil) оборачиваем в [], доменные имена — как есть
        bool isIPv6 = (strchr(realHost, ':') != NULL);
        if (isIPv6) {
            len += _snprintf(outBuf + len, outBufSize - len - 1, "Host: [%s]\r\n", realHost);
        } else {
            len += _snprintf(outBuf + len, outBufSize - len - 1, "Host: %s\r\n", realHost);
        }
    }

    const char* p = headersStart;
    const char* end = headersStart + headersLen;
    while (p < end) {
        const char* lineEnd = p;
        while (lineEnd < end && *lineEnd != '\r' && *lineEnd != '\n') lineEnd++;
        int lineLen = (int)(lineEnd - p);
        if (lineLen == 0) break;

        bool skip = false;
        if (lineLen >= 16 && _strnicmp(p, "Proxy-Connection", 16) == 0) skip = true;
        if (lineLen >= 19 && _strnicmp(p, "Proxy-Authorization", 19) == 0) skip = true;
        if (lineLen >= 10 && _strnicmp(p, "Keep-Alive", 10) == 0) skip = true;
        if (lineLen >= 10 && _strnicmp(p, "Connection", 10) == 0) skip = true;
        if (lineLen >= 4  && _strnicmp(p, "Host", 4) == 0) skip = true;
        // Отключаем сжатие: нельзя добивать нулями сжатые данные при zero-padding
        if (lineLen >= 15 && _strnicmp(p, "Accept-Encoding", 15) == 0) skip = true;
        // Отключаем chunked transfer encoding
        if (lineLen >= 2  && _strnicmp(p, "TE", 2) == 0) skip = true;

        if (!skip && len + lineLen + 2 < outBufSize) {
            memcpy(outBuf + len, p, lineLen);
            len += lineLen;
            outBuf[len++] = '\r';
            outBuf[len++] = '\n';
        }
        p = lineEnd;
        if (p < end && *p == '\r') p++;
        if (p < end && *p == '\n') p++;
    }
    const char* connClose = "Connection: close\r\n\r\n";
    int ccLen = (int)strlen(connClose);
    if (len + ccLen < outBufSize) {
        memcpy(outBuf + len, connClose, ccLen);
        len += ccLen;
    }
    outBuf[len] = '\0';
    return len;
}

bool CYggHttpProxy::ParseRequest(const char* request, char* method, char* host, int* port, char* path, bool* isConnect) {
    char reqCopy[512];
    strncpy(reqCopy, request, sizeof(reqCopy) - 1);
    reqCopy[sizeof(reqCopy) - 1] = '\0';
    
    char* firstLineEnd = strstr(reqCopy, "\r\n");
    if (firstLineEnd) *firstLineEnd = '\0';
    
    char* space1 = strchr(reqCopy, ' ');
    if (!space1) return false;
    
    *space1 = '\0';
    strncpy(method, reqCopy, 15); method[15] = '\0';
    *isConnect = (strcmp(method, "CONNECT") == 0);
    
    char* urlStr = space1 + 1;
    while (*urlStr == ' ') urlStr++;
    
    char* space2 = strchr(urlStr, ' ');
    if (space2) *space2 = '\0';
    
    if (*isConnect) {
        char* portDiv = strchr(urlStr, ':');
        if (portDiv) {
            *portDiv = '\0';
            strncpy(host, urlStr, 255); host[255] = '\0';
            *port = atoi(portDiv + 1);
        } else {
            strncpy(host, urlStr, 255); host[255] = '\0';
            *port = 443;
        }
        path[0] = '\0';
        return true;
    }

    if (strncmp(urlStr, "http://", 7) == 0) {
        urlStr += 7;
        char* pathDiv = strchr(urlStr, '/');
        if (pathDiv) {
            strncpy(path, pathDiv, 511); path[511] = '\0';
            *pathDiv = '\0';
        } else {
            path[0] = '/'; path[1] = '\0';
        }

        if (urlStr[0] == '[') {
            char* bracketEnd = strchr(urlStr, ']');
            if (!bracketEnd) return false;
            *bracketEnd = '\0';
            strncpy(host, urlStr + 1, 255); host[255] = '\0';
            if (*(bracketEnd + 1) == ':') {
                *port = atoi(bracketEnd + 2);
            } else {
                *port = 80;
            }
        } else {
            char* portDiv = strchr(urlStr, ':');
            if (portDiv) {
                *portDiv = '\0';
                strncpy(host, urlStr, 255); host[255] = '\0';
                *port = atoi(portDiv + 1);
            } else {
                strncpy(host, urlStr, 255); host[255] = '\0';
                *port = 80;
            }
        }
        return true;
    }

    // Относительный путь: GET /path HTTP/1.1 + заголовок Host:
    // Ищем Host: в заголовках
    const char* hostHeader = strstr(request, "\r\nHost:");
    if (!hostHeader) hostHeader = strstr(request, "\r\nhost:");
    if (hostHeader) {
        hostHeader += 7; // пропускаем "\r\nHost:"
        while (*hostHeader == ' ') hostHeader++;
        char hostBuf[256];
        int hi = 0;
        while (*hostHeader && *hostHeader != '\r' && *hostHeader != '\n' && hi < 255)
            hostBuf[hi++] = *hostHeader++;
        hostBuf[hi] = '\0';
        // Разделяем host:port
        char* portDiv = strchr(hostBuf, ':');
        if (portDiv) {
            *portDiv = '\0';
            strncpy(host, hostBuf, 255); host[255] = '\0';
            *port = atoi(portDiv + 1);
        } else {
            strncpy(host, hostBuf, 255); host[255] = '\0';
            *port = 80;
        }
        // path — сам urlStr (уже обрезан до пробела)
        strncpy(path, urlStr, 511); path[511] = '\0';
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
    char buffer[PROXY_BUFFER_SIZE]; // 4KB
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

void CYggHttpProxy::RelayThroughSession(SOCKET clientSocket, IronSession* session, int streamId, LPCWSTR ipv6, int port,
                                        const char* initialData, int initialLen, bool isConnect) {
    IronPeer* peer = m_pCore ? m_pCore->GetPeerForSession(session) : NULL;
    if (!peer) return;

    vector<BYTE> path;
    if (!m_pCore->GetPathToIPv6(ipv6, path)) return;

    // Адрес для Host: — берём оригинальный адрес из браузера (320:: как есть)
    char realHostBuf[64];
    WideCharToMultiByte(CP_ACP, 0, ipv6, -1, realHostBuf, sizeof(realHostBuf) - 1, NULL, NULL);
    realHostBuf[sizeof(realHostBuf) - 1] = '\0';
    
    // Отслеживаем время выполнения запроса
    DWORD requestStartTime = GetTickCount();
    
    // Сессия захвачена эксклюзивно через TryAcquireUse — всегда TCP_CLOSED здесь.
    // Отправляем SYN и ждём ESTABLISHED.
    const int TCP_HANDSHAKE_TIMEOUT = 150;  // 15 секунд на TCP handshake (было 30)
    const int SYN_RETRY_INTERVAL = 10;       // Ретрансмит SYN каждую секунду (нужно при key rotation)
    
    TcpState initialTcpState = session->GetTcpState(streamId);
    if (initialTcpState == TCP_CLOSED || initialTcpState == TCP_FIN_WAIT) {
        session->SendSYN(streamId, peer, path);
        int waitCount = 0;
        int lastSynSent = 0;
        while (waitCount < TCP_HANDSHAKE_TIMEOUT && session->GetTcpState(streamId) != TCP_ESTABLISHED) {
            // Если peer отключился - выходим сразу
            if (!peer->IsConnected()) {
                AddLog(L"[HTTP] Peer disconnected during handshake", LOG_WARN);
                break;
            }
            Sleep(100);
            waitCount++;
            lastSynSent++;
            
            // Ретрансмит SYN если долго нет ответа (каждые 5 секунд, макс 2 раза)
            if (lastSynSent >= SYN_RETRY_INTERVAL && waitCount < TCP_HANDSHAKE_TIMEOUT - 10) {
                AddLog(L"[HTTP] Retransmitting SYN...", LOG_DEBUG);
                session->SendSYN(streamId, peer, path);
                lastSynSent = 0;
            }
            
            // Логируем каждые 5 секунд ожидания
            if (waitCount % 50 == 0) {
                WCHAR debug[256];
                wsprintf(debug, L"[HTTP] Waiting for ESTABLISHED... %dms (streamId=%d)", waitCount * 100, streamId);
                AddLog(debug, LOG_DEBUG);
            }
        }
    } else {
        AddLog(L"[HTTP] Session already ESTABLISHED", LOG_DEBUG);
    }
    
    if (session->GetTcpState(streamId) != TCP_ESTABLISHED) {
        // Сбрасываем состояние чтобы следующий поток мог начать новое подключение
        session->ResetTcpState(streamId);  // Сбрасываем только наш стрим
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
        // Переписываем первую строку: "GET http://host/path" -> "GET /path"
        const char* crlf = strstr(initialData, "\r\n");
        if (crlf) {
            char method2[16], host2[256], path2[512];
            int port2 = 80;
            bool isConn2 = false;
            char* newReq = new char[PROXY_BUFFER_SIZE];  // heap: не добавляем к стеку функции
            int newLen = 0;
            if (ParseRequest(initialData, method2, host2, &port2, path2, &isConn2) && !isConn2) {
                const char* rest = crlf + 2;
                int restLen = initialLen - (int)(rest - initialData);
                newLen = BuildServerRequest(method2, path2, rest, restLen, newReq, PROXY_BUFFER_SIZE, realHostBuf);
                session->QueueOrSendData(streamId, peer, path, (BYTE*)newReq, newLen);
            } else {
                session->QueueOrSendData(streamId, peer, path, (BYTE*)initialData, initialLen);
            }
            delete[] newReq;
        } else {
            session->QueueOrSendData(streamId, peer, path, (BYTE*)initialData, initialLen);
        }
    }

    char* buffer = new char[PROXY_BUFFER_SIZE]; // heap: чтение от браузера
    // recvBuffer на heap — читаем по 32KB за раз чтобы быстро дренировать m_recvQueue
    const DWORD RELAY_BUF_SIZE = 32 * 1024;
    BYTE* recvBuffer = new BYTE[RELAY_BUF_SIZE];

    fd_set fdset;
    DWORD lastActivity = GetTickCount();
    DWORD lastPathRefresh = GetTickCount();  // Path обновляем не чаще раза в 5 сек
    bool browserClosed = false;   // браузер закрыл свою сторону (half-close)
    DWORD browserClosedTime = 0;  // когда браузер закрыл соединение
    bool responseStarted = false; // получили хоть один байт ответа
    const DWORD REQUEST_TIMEOUT_MS = 120000;  // Общий таймаут на запрос: 120 сек

    // Range-retry трекинг (прозрачный для браузера)
    DWORD contentLength = 0;      // Content-Length из первого ответа (0 = неизвестен)
    DWORD bodyBytesSent = 0;      // байт тела отданных браузеру
    bool  headersDone   = false;  // нашли \r\n\r\n в потоке
    bool  rangeOk       = false;  // сервер поддерживает Range: bytes
    int   rangeRetryCount = 0;    // счётчик Range-retry (ограничиваем чтобы не зависать 120с)
    // Буфер для накопления заголовков первого ответа — heap, не стек
    const int HDR_BUF = 4096;
    char* hdrBuf = new char[HDR_BUF];
    int   hdrBufLen = 0;
    hdrBuf[0] = '\0';
    
    while (m_bRunning) {
        // Проверка общего таймаута (защита от half-open connections)
        if (GetTickCount() - requestStartTime > REQUEST_TIMEOUT_MS) {
            AddLog(L"[HTTP] Request timeout (120s), closing", LOG_WARN);
            break;
        }
        if (!peer->IsConnected()) {
            AddLog(L"[HTTP] Peer disconnected, closing relay", LOG_WARN);
            break;
        }

        if (!browserClosed) {
            FD_ZERO(&fdset);
            FD_SET(clientSocket, &fdset);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 10000;

            int result = select(0, &fdset, NULL, NULL, &tv);

            if (result > 0 && FD_ISSET(clientSocket, &fdset)) {
                int received = recv(clientSocket, buffer, PROXY_BUFFER_SIZE, 0);
                if (received > 0) {
                    // Обновляем path не чаще раза в 5 сек — избегаем lock contention при upload
                    DWORD now = GetTickCount();
                    if ((now - lastPathRefresh) > 5000) {
                        vector<BYTE> freshPath;
                        if (m_pCore->GetPathToIPv6(ipv6, freshPath)) path = freshPath;
                        lastPathRefresh = now;
                    }
                    session->QueueOrSendData(streamId, peer, path, (BYTE*)buffer, received);
                    lastActivity = GetTickCount();
                } else if (received == 0) {
                    // Браузер закрыл свою сторону (half-close).
                    // Отправляем FIN серверу и продолжаем читать ответ.
                    AddLog(L"[HTTP] Browser half-closed, sending FIN to server", LOG_INFO);
                    session->SendFIN(streamId, peer, path);
                    browserClosed = true;
                    browserClosedTime = GetTickCount();
                    lastActivity = GetTickCount();  // Сброс таймаута - даём время на получение данных
                } else {
                    if (WSAGetLastError() != WSAEWOULDBLOCK) {
                        session->SendFIN(streamId, peer, path);
                        break;
                    }
                }
            }
        }

        // Выходим когда сервер прислал FIN, все данные доставлены браузеру, и мы отправили наш FIN
        if (session->IsServerFinReceived(streamId) && !session->HasData(streamId)) {
            // Сервер закончил — отправляем FIN браузеру немедленно, не ждём его half-close
            // (для HEAD и мелких GET это экономит 100-300ms, освобождая слот Opera раньше)
            if (!browserClosed && !session->IsOurFinSent(streamId)) {
                session->SendFIN(streamId, peer, path);
                browserClosed = true;
                browserClosedTime = GetTickCount();
            }
            AddLog(L"[HTTP] Remote server sent FIN. Page loaded. Closing tunnel.", LOG_SUCCESS);
            break;
        }
        
        // Drain mode: после закрытия браузера даём 3 сек на получение FIN от сервера.
        // Больше ждать нет смысла — Opera ушла, слот нужно освободить.
        if (browserClosed && browserClosedTime > 0) {
            DWORD drainTime = GetTickCount() - browserClosedTime;
            if (drainTime > 3000) {
                AddLog(L"[HTTP] Drain timeout (3s), releasing stream", LOG_INFO);
                break;
            }
        }

        DWORD recvLen = 0;
        DWORD readTimeout;
        if (browserClosed) {
            readTimeout = 1000;   // Opera ушла — не висим на чтении
        } else if (!responseStarted) {
            readTimeout = 10000;  // До первого байта ждём 10 сек (создание сессии Ygg долгое)
        } else {
            readTimeout = 3000;   // Между чанками — 3 сек (700-1700ms RTT)
        }
        if (session->ReadData(streamId, recvBuffer, RELAY_BUF_SIZE, recvLen, readTimeout)) {
            if (recvLen > 0) {
                WCHAR debug[256];
                wsprintf(debug, L"[HTTP] ReadData returned %lu bytes for streamId=%d", recvLen, streamId);
                AddLog(debug, LOG_DEBUG);
                responseStarted = true;

                // Парсим заголовки первого ответа — нужны Content-Length и Accept-Ranges
                if (!headersDone) {
                    int hdrBufLenBefore = hdrBufLen;
                    int copy = (int)recvLen;
                    if (hdrBufLen + copy > HDR_BUF - 1) copy = HDR_BUF - 1 - hdrBufLen;
                    if (copy > 0) {
                        memcpy(hdrBuf + hdrBufLen, recvBuffer, copy);
                        hdrBufLen += copy;
                        hdrBuf[hdrBufLen] = '\0';
                    }
                    const char* hdrEnd = strstr(hdrBuf, "\r\n\r\n");
                    if (hdrEnd) {
                        headersDone = true;
                        // Content-Length
                        const char* cl = strstr(hdrBuf, "Content-Length: ");
                        if (!cl) cl = strstr(hdrBuf, "content-length: ");
                        if (cl) contentLength = (DWORD)atol(cl + 16);
                        // Accept-Ranges
                        if (strstr(hdrBuf, "Accept-Ranges: bytes") || strstr(hdrBuf, "accept-ranges: bytes"))
                            rangeOk = true;
                        // Лог первой строки ответа и Transfer-Encoding (диагностика chunked)
                        {
                            const char* eol = strstr(hdrBuf, "\r\n");
                            WCHAR wstatus[256];
                            char statusLine[128];
                            if (eol) {
                                int slen = (int)(eol - hdrBuf);
                                if (slen > 120) slen = 120;
                                memcpy(statusLine, hdrBuf, slen);
                                statusLine[slen] = '\0';
                            } else {
                                strcpy(statusLine, "(no EOL)");
                            }
                            bool isChunked = (strstr(hdrBuf, "Transfer-Encoding: chunked") != NULL ||
                                             strstr(hdrBuf, "transfer-encoding: chunked") != NULL);
                            wsprintf(wstatus, L"[HTTP] SrvResp: %hs%hs", statusLine,
                                     isChunked ? " [CHUNKED!]" : "");
                            AddLog(wstatus, LOG_DEBUG);
                        }
                        // Байт заголовков в текущем чанке = (полный размер заголовков) - (накоплено до чанка)
                        int hdrTotalLen = (int)(hdrEnd - hdrBuf) + 4;
                        int hdrBytesFromThisChunk = hdrTotalLen - hdrBufLenBefore;
                        if (hdrBytesFromThisChunk < 0) hdrBytesFromThisChunk = 0;
                        // Тело в текущем чанке = recvLen минус байты заголовков из этого чанка
                        int bodyInChunk = (int)recvLen - hdrBytesFromThisChunk;
                        if (bodyInChunk < 0) bodyInChunk = 0;
                        bodyBytesSent += (DWORD)bodyInChunk;
                        {
                            WCHAR hdbg[256];
                            wsprintf(hdbg, L"[HTTP] Hdrs: cl=%lu rangeOk=%d hdrLen=%d bodyInChunk=%d",
                                     contentLength, (int)rangeOk, hdrTotalLen, bodyInChunk);
                            AddLog(hdbg, LOG_DEBUG);
                        }
                    }
                } else {
                    bodyBytesSent += recvLen;
                }

                // Пересылаем данные браузеру как есть
                const char* sendStart = (const char*)recvBuffer;
                DWORD sendLen = recvLen;

                // Отправляем все данные браузеру с retry при WSAEWOULDBLOCK
                DWORD sendOffset = 0;
                bool sendOk = true;
                while (sendOffset < sendLen) {
                    // Браузер закрыл соединение — проглатываем данные, не тратим время на send
                    if (browserClosed) { sendOffset = sendLen; break; }
                    int sent = send(clientSocket, sendStart + sendOffset, sendLen - sendOffset, 0);
                    if (sent > 0) {
                        sendOffset += sent;
                        lastActivity = GetTickCount();
                    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
                        // Буфер браузера заполнен — ждём недолго (high latency сеть)
                        fd_set wfd;
                        FD_ZERO(&wfd);
                        FD_SET(clientSocket, &wfd);
                        struct timeval wtv;
                        wtv.tv_sec = 2;  // Макс 2 сек (было 10!)
                        wtv.tv_usec = 0;
                        if (select(0, NULL, &wfd, NULL, &wtv) <= 0) { sendOk = false; break; }
                    } else {
                        sendOk = false;
                        break;
                    }
                }
                if (!sendOk) break;
            }
        } else {
            TcpState tcpState = session->GetTcpState(streamId);
            if (tcpState == TCP_FIN_WAIT && session->IsServerFinReceived(streamId) && (browserClosed || session->IsOurFinSent(streamId))) {
                AddLog(L"[HTTP] Remote server sent FIN. Page loaded. Closing tunnel.", LOG_SUCCESS);
                break;
            }
            if (tcpState == TCP_CLOSED) {
                if (responseStarted && rangeOk && contentLength > 0 &&
                    bodyBytesSent > 0 && bodyBytesSent < contentLength &&
                    initialData && initialLen > 0) {
                    // Opera уже ушла — не тратим слот на докачку мёртвому клиенту
                    if (browserClosed) {
                        AddLog(L"[HTTP] RST mid-transfer, browser gone, aborting retry", LOG_INFO);
                        break;
                    }
                    // Лимит попыток: 3 RST подряд — сеть нестабильна, сдаёмся быстро
                    if (rangeRetryCount >= 3) {
                        AddLog(L"[HTTP] RST mid-transfer, max retries (3) reached, aborting", LOG_WARN);
                        break;
                    }
                    rangeRetryCount++;
                    WCHAR wdbg[256];
                    wsprintf(wdbg, L"[HTTP] RST mid-transfer, Range-retry #%d %lu/%lu bytes", rangeRetryCount, bodyBytesSent, contentLength);
                    AddLog(wdbg, LOG_WARN);

                    // 1. Переподключаемся через Ironwood
                    session->ResetTcpState(streamId);
                    vector<BYTE> newPath;
                    if (!m_pCore->GetPathToIPv6(ipv6, newPath)) break;
                    bool ready = false;
                    for (int ri = 0; ri < 150 && peer->IsConnected(); ri++) {
                        if (session->IsReady()) { ready = true; break; }
                        if (ri == 0) session->SendSessionInit(peer, newPath);
                        Sleep(100);
                    }
                    if (!ready) break;
                    session->SendSYN(streamId, peer, newPath);
                    int wi = 0;
                    while (wi < 150 && session->GetTcpState(streamId) != TCP_ESTABLISHED && peer->IsConnected())
                        { Sleep(100); wi++; }
                    if (session->GetTcpState(streamId) != TCP_ESTABLISHED) break;

                    // 2. Строим Range-запрос
                    const char* crlf = strstr(initialData, "\r\n");
                    if (!crlf) break;
                    char meth[16], hst[256], pth[512];
                    int prt = 80; bool isCn = false;
                    if (!ParseRequest(initialData, meth, hst, &prt, pth, &isCn) || isCn) break;
                    const char* rest = crlf + 2;
                    int restLen = initialLen - (int)(rest - initialData);
                    char* rangeReq = new char[PROXY_BUFFER_SIZE];
                    int rangeLen = BuildServerRequest(meth, pth, rest, restLen, rangeReq, PROXY_BUFFER_SIZE, realHostBuf);
                    // Вставляем Range: перед финальным \r\n
                    if (rangeLen >= 2) {
                        rangeLen -= 2;
                        rangeLen += _snprintf(rangeReq + rangeLen, PROXY_BUFFER_SIZE - rangeLen - 1,
                                              "Range: bytes=%lu-\r\n\r\n", bodyBytesSent);
                    }
                    session->QueueOrSendData(streamId, peer, newPath, (BYTE*)rangeReq, rangeLen);
                    delete[] rangeReq;
                    path = newPath;
                    lastActivity = GetTickCount();

                    // 3. Пропускаем заголовки 206-ответа, остаток буфера — начало тела.
                    {
                        char* skipBuf = new char[HDR_BUF];
                        int  skipLen = 0;
                        bool skipOk  = false;
                        DWORD deadline = GetTickCount() + 15000;
                        while (GetTickCount() < deadline && peer->IsConnected()) {
                            DWORD got = 0;
                            BYTE* dst = (BYTE*)skipBuf + skipLen;
                            DWORD want = HDR_BUF - 1 - skipLen;
                            if (want == 0) break;  // буфер переполнен — заголовки слишком большие
                            if (session->ReadData(streamId, dst, want, got, 2000) && got > 0) {
                                skipLen += (int)got;
                                skipBuf[skipLen] = '\0';
                                const char* sep = strstr(skipBuf, "\r\n\r\n");
                                if (sep) {
                                    // Нашли конец заголовков ответа на Range-запрос.
                                    // Проверяем статус: должно быть 206, иначе сервер не поддержал Range
                                    // и вернул 200 со всем файлом — склеивать нельзя, прерываемся.
                                    if (strncmp(skipBuf, "HTTP/", 5) == 0) {
                                        const char* sp = strchr(skipBuf, ' ');
                                        if (sp && atoi(sp + 1) != 206) {
                                            WCHAR wdbg2[128];
                                            wsprintf(wdbg2, L"[HTTP] Range-retry: server returned %d (not 206), aborting", atoi(sp + 1));
                                            AddLog(wdbg2, LOG_WARN);
                                            skipOk = false;
                                            break;
                                        }
                                    }
                                    // Всё что после \r\n\r\n — начало тела, отправляем браузеру.
                                    const char* bodyStart = sep + 4;
                                    int bodyLen = skipLen - (int)(bodyStart - skipBuf);
                                    if (bodyLen > 0) {
                                        DWORD boff = 0;
                                        while (boff < (DWORD)bodyLen) {
                                            int r = send(clientSocket, bodyStart + boff, bodyLen - boff, 0);
                                            if (r > 0) { boff += r; lastActivity = GetTickCount(); }
                                            else if (WSAGetLastError() == WSAEWOULDBLOCK) {
                                                fd_set wfd2; FD_ZERO(&wfd2); FD_SET(clientSocket, &wfd2);
                                                struct timeval wtv2; wtv2.tv_sec = 2; wtv2.tv_usec = 0;
                                                if (select(0, NULL, &wfd2, NULL, &wtv2) <= 0) break;
                                            } else break;
                                        }
                                        bodyBytesSent += (DWORD)bodyLen;
                                    }
                                    WCHAR sdbg[256];
                                    wsprintf(sdbg, L"[HTTP] Skip206: hdrLen=%d bodyLen=%d bodyBytesSent=%lu",
                                             (int)(bodyStart - skipBuf), bodyLen, bodyBytesSent);
                                    AddLog(sdbg, LOG_DEBUG);
                                    skipOk = true;
                                    break;
                                }
                            }
                        }
                        delete[] skipBuf;
                        if (!skipOk) break;
                    }

                    // 4. Продолжаем как обычно — headersDone=true, bodyBytesSent уже обновлён
                    hdrBufLen = 0;
                    headersDone = true;
                    continue;
                }
                if (responseStarted) {
                    // Zero-padding: даже если сервер не поддерживает Range (JS/CSS),
                    // добиваем нули чтобы Opera разблокировала очередь загрузки.
                    AddLog(L"[HTTP] RST mid-transfer, no retry possible (will zero-pad)", LOG_WARN);
                    break;
                }
                AddLog(L"[HTTP] RST received — retrying request", LOG_INFO);
                session->ResetTcpState(streamId);  // Сбрасываем только наш стрим
                vector<BYTE> newPath;
                if (!m_pCore->GetPathToIPv6(ipv6, newPath)) break;
                bool ready = false;
                for (int ri = 0; ri < 150 && peer->IsConnected(); ri++) {
                    if (session->IsReady()) { ready = true; break; }
                    // Шлём SESSION_INIT если ещё не готова
                    if (ri == 0) session->SendSessionInit(peer, newPath);
                    Sleep(100);
                }
                if (!ready) break;
                session->SendSYN(streamId, peer, newPath);
                int wi = 0;
                while (wi < 150 && session->GetTcpState(streamId) != TCP_ESTABLISHED && peer->IsConnected()) {
                    Sleep(100); wi++;
                }
                if (session->GetTcpState(streamId) != TCP_ESTABLISHED) break;
                // Повторяем запрос
                if (initialData && initialLen > 0) {
                    const char* crlf2 = strstr(initialData, "\r\n");
                    if (crlf2) {
                        char method3[16], host3[256], path3[512];
                        int port3 = 80; bool isConn3 = false;
                        char* retryReq = new char[PROXY_BUFFER_SIZE];
                        int retryLen = 0;
                        if (ParseRequest(initialData, method3, host3, &port3, path3, &isConn3) && !isConn3) {
                            const char* rest2 = crlf2 + 2;
                            int restLen2 = initialLen - (int)(rest2 - initialData);
                            retryLen = BuildServerRequest(method3, path3, rest2, restLen2, retryReq, PROXY_BUFFER_SIZE, realHostBuf);
                            session->QueueOrSendData(streamId, peer, newPath, (BYTE*)retryReq, retryLen);
                        } else {
                            session->QueueOrSendData(streamId, peer, newPath, (BYTE*)initialData, initialLen);
                        }
                        delete[] retryReq;
                    } else {
                        session->QueueOrSendData(streamId, peer, newPath, (BYTE*)initialData, initialLen);
                    }
                }
                path = newPath;
                lastActivity = GetTickCount();
            }
        }

        // Периодически проверяем reassembly timeout и сбрасываем delayed ACK
        session->CheckReassemblyTimeout(streamId, peer, const_cast<vector<BYTE>*>(&path));

        if (GetTickCount() - lastActivity > RELAY_TIMEOUT_MS) {
            AddLog(L"[HTTP] Relay inactivity timeout, closing", LOG_WARN);
            break;
        }
    }
    delete[] recvBuffer;

    // Zero-padding: Opera Mobile зависает если получила меньше байт чем Content-Length.
    // Добиваем остаток нулями — картинка будет серой снизу, но Opera разблокирует очередь
    // и сразу запросит следующий файл (JS, CSS, другие картинки).
    if (!browserClosed && contentLength > 0 && bodyBytesSent < contentLength) {
        DWORD padBytes = contentLength - bodyBytesSent;
        WCHAR padDbg[256];
        wsprintf(padDbg, L"[HTTP] Zero-padding %lu bytes to unblock Opera queue", padBytes);
        AddLog(padDbg, LOG_WARN);
        const int ZERO_BUF_SIZE = 4096;
        char* zeroBuf = new char[ZERO_BUF_SIZE];
        memset(zeroBuf, 0, ZERO_BUF_SIZE);
        while (bodyBytesSent < contentLength) {
            DWORD toSend = contentLength - bodyBytesSent;
            if (toSend > (DWORD)ZERO_BUF_SIZE) toSend = (DWORD)ZERO_BUF_SIZE;
            int sent = send(clientSocket, zeroBuf, (int)toSend, 0);
            if (sent > 0) {
                bodyBytesSent += sent;
            } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
                fd_set wfd; FD_ZERO(&wfd); FD_SET(clientSocket, &wfd);
                struct timeval wtv; wtv.tv_sec = 1; wtv.tv_usec = 0;
                if (select(0, NULL, &wfd, NULL, &wtv) <= 0) break;
            } else {
                break;
            }
        }
        delete[] zeroBuf;
    }

    delete[] hdrBuf;
    delete[] buffer;

    DWORD requestDuration = GetTickCount() - requestStartTime;
    WCHAR debug[256];
    wsprintf(debug, L"[HTTP] Request completed in %lums, streamId=%d", requestDuration, streamId);
    AddLog(debug, LOG_INFO);
    // Не закрываем clientSocket — keep-alive: HandleClient прочитает следующий запрос
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

// ============================================================================
// DNS over Yggdrasil
// ============================================================================

static WCHAR g_yggDnsServer[64] = YGG_DNS_SERVER_DEFAULT;
static CRITICAL_SECTION g_yggDnsLock;
static bool g_yggDnsLockInited = false;

// Список DNS-серверов управляется из UI (g_dnsServers/g_dnsCount в Yggstack.cpp)
extern WCHAR g_dnsServers[8][64];
extern int g_dnsCount;

// ============================================================================
// DNS-кэш: 16 записей, TTL 300 сек
// ============================================================================
#define DNS_CACHE_SIZE  16
#define DNS_CACHE_TTL   300000   // 300 сек в миллисекундах

struct DnsCacheEntry {
    char  hostname[64];
    BYTE  ipv6[16];      // 200::/7 — ненулевой если AAAA
    char  ipv4[16];      // a.b.c.d — ненулевой если только A
    DWORD timestamp;     // GetTickCount() при добавлении
    bool  valid;
    bool  nxdomain;      // true = хост не существует (не резолвим снова до истечения TTL)
};

static DnsCacheEntry g_dnsCache[DNS_CACHE_SIZE];
static bool g_dnsCacheInited = false;

static void DnsCacheInit() {
    if (!g_dnsCacheInited) {
        memset(g_dnsCache, 0, sizeof(g_dnsCache));
        g_dnsCacheInited = true;
    }
}

// Возвращает индекс записи или -1
static int DnsCacheLookup(const char* hostname, BYTE* outIPv6, char* outIPv4) {
    DnsCacheInit();
    DWORD now = GetTickCount();
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_dnsCache[i].valid) continue;
        if ((now - g_dnsCache[i].timestamp) > DNS_CACHE_TTL) {
            g_dnsCache[i].valid = false;
            continue;
        }
        if (_stricmp(g_dnsCache[i].hostname, hostname) == 0) {
            if (g_dnsCache[i].nxdomain) return -2; // NXDOMAIN кэширован
            memcpy(outIPv6, g_dnsCache[i].ipv6, 16);
            strncpy(outIPv4, g_dnsCache[i].ipv4, 15);
            outIPv4[15] = '\0';
            return i;
        }
    }
    return -1; // не найдено
}

static void DnsCacheStore(const char* hostname, const BYTE* ipv6, const char* ipv4, bool nxdomain) {
    DnsCacheInit();
    DWORD now = GetTickCount();
    // Ищем свободный или самый старый слот
    int oldest = 0;
    DWORD oldestTime = g_dnsCache[0].timestamp;
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_dnsCache[i].valid || (now - g_dnsCache[i].timestamp) > DNS_CACHE_TTL) {
            oldest = i;
            break;
        }
        if (g_dnsCache[i].timestamp < oldestTime) {
            oldest = i;
            oldestTime = g_dnsCache[i].timestamp;
        }
    }
    strncpy(g_dnsCache[oldest].hostname, hostname, 63);
    g_dnsCache[oldest].hostname[63] = '\0';
    if (ipv6) memcpy(g_dnsCache[oldest].ipv6, ipv6, 16);
    else memset(g_dnsCache[oldest].ipv6, 0, 16);
    if (ipv4) { strncpy(g_dnsCache[oldest].ipv4, ipv4, 15); g_dnsCache[oldest].ipv4[15] = '\0'; }
    else g_dnsCache[oldest].ipv4[0] = '\0';
    g_dnsCache[oldest].timestamp = now;
    g_dnsCache[oldest].valid = true;
    g_dnsCache[oldest].nxdomain = nxdomain;
}

void SetYggDnsServer(LPCWSTR ipv6) {
    if (!g_yggDnsLockInited) {
        InitializeCriticalSection(&g_yggDnsLock);
        g_yggDnsLockInited = true;
    }
    EnterCriticalSection(&g_yggDnsLock);
    wcsncpy(g_yggDnsServer, ipv6, 63);
    g_yggDnsServer[63] = L'\0';
    LeaveCriticalSection(&g_yggDnsLock);
}

// Строит минимальный DNS-запрос (A или AAAA) в буфер outBuf.
// Возвращает длину запроса (без TCP-преамбулы 2 байта длины).
// qtype: 1 = A, 28 = AAAA
static int BuildDnsQuery(const char* hostname, WORD txid, WORD qtype, BYTE* outBuf, int bufSize) {
    if (bufSize < 512) return 0;
    memset(outBuf, 0, bufSize);
    int p = 0;

    // Header
    outBuf[p++] = (BYTE)(txid >> 8);
    outBuf[p++] = (BYTE)(txid & 0xFF);
    outBuf[p++] = 0x01; outBuf[p++] = 0x00; // flags: RD=1
    outBuf[p++] = 0x00; outBuf[p++] = 0x01; // QDCOUNT=1
    outBuf[p++] = 0x00; outBuf[p++] = 0x00; // ANCOUNT=0
    outBuf[p++] = 0x00; outBuf[p++] = 0x00; // NSCOUNT=0
    outBuf[p++] = 0x00; outBuf[p++] = 0x00; // ARCOUNT=0

    // QNAME: кодируем каждый label
    const char* h = hostname;
    while (*h) {
        const char* dot = strchr(h, '.');
        int labelLen = dot ? (int)(dot - h) : (int)strlen(h);
        if (labelLen > 63 || p + labelLen + 2 > bufSize) return 0;
        outBuf[p++] = (BYTE)labelLen;
        memcpy(outBuf + p, h, labelLen);
        p += labelLen;
        if (!dot) break;
        h = dot + 1;
    }
    outBuf[p++] = 0x00; // завершающий нулевой label

    // QTYPE + QCLASS
    outBuf[p++] = (BYTE)(qtype >> 8);
    outBuf[p++] = (BYTE)(qtype & 0xFF);
    outBuf[p++] = 0x00; outBuf[p++] = 0x01; // IN

    return p;
}

// Парсит DNS-ответ: ищет первую AAAA-запись в диапазоне 200::/7, потом первую A-запись.
// outIPv6: 16 байт; outIPv4: строка "a.b.c.d"
// Возвращает: 2=нашли AAAA, 1=нашли только A, 0=ничего
static int ParseDnsResponse(const BYTE* buf, int len, BYTE* outIPv6, char* outIPv4, WORD expectedTxid) {
    if (len < 12) return 0;

    WORD txid   = (buf[0] << 8) | buf[1];
    WORD flags  = (buf[2] << 8) | buf[3];
    int ancount = (buf[6] << 8) | buf[7];

    if (!(flags & 0x8000)) return 0;        // QR=0, не ответ
    if (txid != expectedTxid) return 0;     // TXID не совпал
    if (flags & 0x0F) return 0;             // rcode != 0
    if (ancount == 0) return 0;

    // Пропускаем заголовок (12 байт) и секцию вопроса
    int p = 12;
    while (p < len) {
        BYTE labelLen = buf[p];
        if (labelLen == 0) { p++; break; }
        if ((labelLen & 0xC0) == 0xC0) { p += 2; break; }
        p += 1 + labelLen;
    }
    p += 4; // QTYPE + QCLASS

    int result = 0;
    for (int i = 0; i < ancount && p < len; i++) {
        // NAME: указатель (2 байта) или inline labels
        if ((buf[p] & 0xC0) == 0xC0) {
            p += 2;
        } else {
            while (p < len && buf[p] != 0) {
                if ((buf[p] & 0xC0) == 0xC0) { p += 2; break; }
                p += 1 + buf[p];
            }
            if (p < len && buf[p] == 0) p++;
        }
        if (p + 10 > len) break;

        WORD rtype = (buf[p] << 8) | buf[p+1];  p += 2;
        p += 6; // class (2) + ttl (4)
        WORD rdlen = (buf[p] << 8) | buf[p+1];  p += 2;

        if (p + rdlen > len) break;

        if (rtype == 28 && rdlen == 16 && (buf[p] & 0xFE) == 0x02) {
            // AAAA в диапазоне Yggdrasil 200::/7
            memcpy(outIPv6, buf + p, 16);
            return 2;
        } else if (rtype == 1 && rdlen == 4 && result == 0) {
            _snprintf(outIPv4, 16, "%d.%d.%d.%d", buf[p], buf[p+1], buf[p+2], buf[p+3]);
            outIPv4[15] = '\0';
            result = 1;
        }
        p += rdlen;
    }
    return result;
}

// Резолвит hostname через DNS-сервер внутри Yggdrasil (UDP/53 на subnet-адресе 03xx::/64).
// Возвращает: true + outIPv6 заполнен (Yggdrasil AAAA), или true + outIPv4 (A-запись), или false.
bool CYggHttpProxy::ResolveViaYggDns(const char* hostname, BYTE* outIPv6, char* outIPv4) {
    if (!m_pCore) return false;

    memset(outIPv6, 0, 16);
    outIPv4[0] = '\0';

    int cacheResult = DnsCacheLookup(hostname, outIPv6, outIPv4);
    if (cacheResult == -2) return false;
    if (cacheResult >= 0) return true;

    BYTE dnsReq[512];
    static WORD s_txid = 0x1337;
    static WORD s_srcPort = 40000;
    WORD txid = ++s_txid;
    int reqLen = BuildDnsQuery(hostname, txid, 28 /*AAAA*/, dnsReq, sizeof(dnsReq));
    if (reqLen <= 0) return false;

    // Список серверов из UI
    if (g_dnsCount == 0) return false;

    for (int si = 0; si < g_dnsCount && m_bRunning; si++) {
        const WCHAR* dnsIPv6 = g_dnsServers[si];

        // Получаем готовую сессию или устанавливаем новую
        IronSession* session = NULL;
        int waitCycles = 0;
        while (waitCycles < 50 && m_bRunning) {
            IronSession* c = m_pCore->GetSessionForIPv6(dnsIPv6);
            if (c) {
                if (c->IsReady()) { session = c; break; }
                if (c->IsClosed()) { c->Release(); break; }
                c->Release();
            } else { break; }
            Sleep(100); waitCycles++;
        }
        if (!session) {
            if (!m_pCore->SendPathLookupToIPv6(dnsIPv6)) continue;
            m_pCore->AddPendingSession(dnsIPv6, YGG_DNS_PORT);
            waitCycles = 0;
            while (waitCycles < 100 && m_bRunning) {
                IronSession* c = m_pCore->GetSessionForIPv6(dnsIPv6);
                if (c && c->IsReady()) { session = c; break; }
                if (c) c->Release();
                Sleep(100); waitCycles++;
            }
        }
        if (!session) {
            WCHAR w[128]; wsprintf(w, L"[DNS] No session to %s", dnsIPv6);
            AddLog(w, LOG_WARN); continue;
        }

        IronPeer* peer = m_pCore->GetPeerForSession(session);
        vector<BYTE> path;
        if (!peer || !m_pCore->GetPathToIPv6(dnsIPv6, path)) {
            session->Release(); continue;
        }

        // Dst: subnet-адрес (03xx:xxxx:xxxx:xxxx::) — DNS слушает на нём
        BYTE dstIPv6[16];
        memcpy(dstIPv6, session->GetRemoteIPv6(), 16);
        dstIPv6[0] = 0x03;
        memset(dstIPv6 + 8, 0, 8);

        WORD srcPort = s_srcPort++;
        if (s_srcPort > 49999) s_srcPort = 40000;

        // Небольшая пауза при первом обращении к только что открытой сессии
        if (si == 0) Sleep(500);

        if (!session->SendUdpDns(peer, path, m_pCore->GetIPv6(), dstIPv6, srcPort, dnsReq, (DWORD)reqLen)) {
            session->Release(); continue;
        }

        BYTE respBuf[512];
        DWORD respLen = session->ReadUdpDns(respBuf, sizeof(respBuf), 5000);
        bool portUnreachable = session->IsUdpDnsPortUnreachable();
        session->Release();

        if (portUnreachable) {
            WCHAR w[128]; wsprintf(w, L"[DNS] %s unreachable, trying next", dnsIPv6);
            AddLog(w, LOG_WARN); continue;
        }
        if (respLen == 0) {
            WCHAR w[128]; wsprintf(w, L"[DNS] Timeout on %s", dnsIPv6);
            AddLog(w, LOG_WARN); continue;
        }

        int parseResult = ParseDnsResponse(respBuf, (int)respLen, outIPv6, outIPv4, txid);
        if (parseResult == 2) {
            DnsCacheStore(hostname, outIPv6, NULL, false);
            WCHAR dbg[256]; wsprintf(dbg, L"[DNS] %hs -> AAAA (Ygg)", hostname);
            AddLog(dbg, LOG_INFO);
            return true;
        } else if (parseResult == 1) {
            DnsCacheStore(hostname, NULL, outIPv4, false);
            WCHAR dbg[256]; wsprintf(dbg, L"[DNS] %hs -> A %hs", hostname, outIPv4);
            AddLog(dbg, LOG_INFO);
            return true;
        } else {
            DnsCacheStore(hostname, NULL, NULL, true);
            return false;
        }
    }

    WCHAR dbg[256]; wsprintf(dbg, L"[DNS] All servers failed for %hs", hostname);
    AddLog(dbg, LOG_WARN);
    return false;
}