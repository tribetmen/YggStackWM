// YggNet.cpp - Сетевые операции и работа с Yggdrasil

#include "stdafx.h"
#include "YggNet.h"
#include "YggLog.h"
#include "YggdrasilCore.h"
#include "YggHttpProxy.h"
#include <winsock2.h>

#pragma comment(lib, "ws2.lib")

// Внешние переменные
extern HWND g_hWnd;
extern BOOL g_serviceRunning;
extern BOOL g_connecting;
extern BOOL g_showSpinner;
extern int g_spinnerAngle;
extern CYggdrasilCore* g_pYggCore;
extern IronPeer* g_pCurrentPeer;
extern HANDLE g_hConnectThread;
extern WCHAR g_currentIP[50];
extern WCHAR g_peersList[10][128];
extern int g_peerCount;
extern WCHAR g_privateKeyFull[128];
extern WCHAR g_privateKeyShort[64];

// Таймеры
#define ID_TIMER_SPINNER       1006
#define ID_TIMER_CONNECT       1005

// Структура для потока подключения
struct ConnectParams {
    HWND hWnd;
    WCHAR peerAddress[128];
    int port;
};

// Поток подключения
static DWORD WINAPI ConnectThreadProc(LPVOID lpParam) {
    ConnectParams* params = (ConnectParams*)lpParam;
    
    if (!g_pYggCore) {
        g_pYggCore = CYggdrasilCore::GetInstance();
    }
    
    IronPeer* peer = g_pYggCore->ConnectToPeer(params->peerAddress, params->port);
    
    if (peer) {
        g_pCurrentPeer = peer;
        PostMessage(params->hWnd, WM_USER + 100, 0, 0); // WM_CONNECT_COMPLETE
    } else {
        PostMessage(params->hWnd, WM_USER + 101, 0, 0); // WM_CONNECT_FAILED
    }
    
    delete params;
    return 0;
}

void OnStartService() {
    if (!g_pYggCore) {
        g_pYggCore = CYggdrasilCore::GetInstance();
    }
    
    if (!g_serviceRunning && !g_connecting) {
        extern int g_peerCount;
        if (g_peerCount == 0) {
            AddLog(L"No peers configured!", LOG_ERROR);
            return;
        }
        
        AddLog(L"Starting Yggdrasil service...", LOG_INFO);
        g_connecting = TRUE;
        g_showSpinner = TRUE;
        SetTimer(g_hWnd, ID_TIMER_SPINNER, 50, NULL);
        
        ConnectParams* params = new ConnectParams;
        params->hWnd = g_hWnd;
        wcscpy(params->peerAddress, g_peersList[0]);
        params->port = 7991;
        
        g_hConnectThread = CreateThread(NULL, 0, ConnectThreadProc, params, 0, NULL);
    } else if (g_serviceRunning) {
        g_serviceRunning = FALSE;
        DisconnectAll();
        g_pCurrentPeer = NULL;
        AddLog(L"Service stopped", LOG_WARN);
        InvalidateRect(g_hWnd, NULL, TRUE);
    }
}

void OnConnectComplete() {
    g_connecting = FALSE;
    g_showSpinner = FALSE;
    KillTimer(g_hWnd, ID_TIMER_SPINNER);
    g_serviceRunning = TRUE;
    
    AddLog(L"TCP connected, handshake in progress...", LOG_DEBUG);
    
    WCHAR ipStr[50];
    g_pYggCore->GetIPv6String(ipStr, 50);
    wcscpy(g_currentIP, ipStr);
    
    InvalidateRect(g_hWnd, NULL, TRUE);
}

void OnConnectFailed() {
    g_connecting = FALSE;
    g_showSpinner = FALSE;
    KillTimer(g_hWnd, ID_TIMER_SPINNER);
    
    AddLog(L"Connection failed", LOG_ERROR);
    
    if (g_hConnectThread) {
        CloseHandle(g_hConnectThread);
        g_hConnectThread = NULL;
    }
    
    InvalidateRect(g_hWnd, NULL, TRUE);
}

void DisconnectAll() {
    if (g_pYggCore) {
        g_pYggCore->DisconnectAll();
    }
}

BOOL InitWinsock() {
    WSADATA wsaData;
    WORD wVersion = MAKEWORD(1, 1);
    int result = WSAStartup(wVersion, &wsaData);
    if (result != 0) {
        wVersion = MAKEWORD(2, 0);
        result = WSAStartup(wVersion, &wsaData);
        if (result != 0) return FALSE;
    }
    return TRUE;
}

void LoadOrGenerateKeys() {
    if (!g_pYggCore) {
        g_pYggCore = CYggdrasilCore::GetInstance();
        g_pYggCore->Initialize();
    }
    
    if (g_pYggCore->LoadOrGenerateKeys()) {
        const YggKeys& keys = g_pYggCore->GetKeys();
        
        for(int i = 0; i < 64; i++) {
            wsprintf(g_privateKeyFull + i*2, L"%02x", keys.privateKey[i]);
        }
        g_privateKeyFull[128] = 0;
        
        wcsncpy(g_privateKeyShort, g_privateKeyFull, 20);
        wcscpy(g_privateKeyShort + 20, L"...");
        
        WCHAR ipStr[50];
        g_pYggCore->GetIPv6String(ipStr, 50);
        wcscpy(g_currentIP, ipStr);
        
        AddLog(L"Keys loaded", LOG_SUCCESS);
    }
}

void SaveConfig(void) {
    HKEY hKey;
    DWORD dwDisp;
    
    // Создаем/открываем ключ реестра
    if (RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\Yggdrasil", 0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisp) == ERROR_SUCCESS) {
        // Сохраняем приватный ключ
        RegSetValueEx(hKey, L"PrivateKey", 0, REG_SZ, (BYTE*)g_privateKeyFull, (wcslen(g_privateKeyFull) + 1) * sizeof(WCHAR));
        
        // Сохраняем количество пиров
        RegSetValueEx(hKey, L"PeerCount", 0, REG_DWORD, (BYTE*)&g_peerCount, sizeof(DWORD));
        
        // Сохраняем список пиров
        for (int i = 0; i < g_peerCount && i < 10; i++) {
            WCHAR peerName[32];
            wsprintf(peerName, L"Peer%d", i);
            RegSetValueEx(hKey, peerName, 0, REG_SZ, (BYTE*)g_peersList[i], (wcslen(g_peersList[i]) + 1) * sizeof(WCHAR));
        }
        
        RegCloseKey(hKey);
        AddLog(L"Config saved", LOG_SUCCESS);
    } else {
        AddLog(L"Failed to save config", LOG_ERROR);
    }
}

// ============================================================================
// HTTP ПРОКСИ
// ============================================================================

BOOL g_httpProxyRunning = FALSE;
HANDLE g_hHttpProxyThread = NULL;

static DWORD WINAPI HttpProxyThreadProc(LPVOID lpParam) {
    StartHttpProxy(HTTP_PROXY_PORT);
    
    while (g_httpProxyRunning && IsHttpProxyRunning()) {
        Sleep(100);
    }
    
    StopHttpProxy();
    return 0;
}

void StartHttpProxyAsync() {
    if (g_httpProxyRunning) return;
    
    // HTTP прокси работает даже без Yggdrasil (для обычного интернета)
    AddLog(L"[HTTP] Starting HTTP proxy...", LOG_INFO);
    
    g_httpProxyRunning = TRUE;
    g_hHttpProxyThread = CreateThread(NULL, 0, HttpProxyThreadProc, NULL, 0, NULL);
    
    if (!g_hHttpProxyThread) {
        g_httpProxyRunning = FALSE;
        AddLog(L"[HTTP] Failed to start thread", LOG_ERROR);
    } else {
        AddLog(L"[HTTP] Proxy started on 127.0.0.1:8080", LOG_SUCCESS);
        AddLog(L"[HTTP] Configure Opera: 127.0.0.1:8080", LOG_INFO);
    }
    
    InvalidateRect(g_hWnd, NULL, TRUE);
}

void StopHttpProxyLocal() {
    if (!g_httpProxyRunning) return;
    
    AddLog(L"[HTTP] Stopping...", LOG_INFO);
    
    g_httpProxyRunning = FALSE;
    StopHttpProxy();
    
    if (g_hHttpProxyThread) {
        WaitForSingleObject(g_hHttpProxyThread, 2000);
        CloseHandle(g_hHttpProxyThread);
        g_hHttpProxyThread = NULL;
    }
    
    AddLog(L"[HTTP] Stopped", LOG_INFO);
    InvalidateRect(g_hWnd, NULL, TRUE);
}

void OnToggleHttpProxy() {
    if (g_httpProxyRunning) {
        StopHttpProxyLocal();
    } else {
        StartHttpProxyAsync();
    }
}
