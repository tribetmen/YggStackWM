// Yggstack.cpp - Yggdrasil клиент для Windows Mobile 5/6
// Главный файл - координирует работу модулей

#include "stdafx.h"
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <aygshell.h>
#include <sipapi.h>
#include <winsock2.h>

// Ресурсы (иконка)
#include "resource.h"
#ifndef IDI_ICON1
#define IDI_ICON1 101
#endif

#include "scroll_arm4i.h"
#include "textselector.h"
#include "YggdrasilCore.h"
#include "ygg_constants.h"
#include "YggInput.h"
#include "YggLog.h"
#include "YggNet.h"
#include "YggDraw.h"

#pragma comment(lib, "ws2.lib")

#ifndef IDI_APPLICATION
#define IDI_APPLICATION  MAKEINTRESOURCE(32512)
#endif

// ID сообщений для потоков
#define WM_CONNECT_COMPLETE    (WM_USER + 100)
#define WM_CONNECT_FAILED      (WM_USER + 101)
#define WM_PEER_DISCONNECTED   (WM_USER + 102)

// Таймеры
#define ID_TIMER_SCROLL        1001
#define ID_TIMER_LONGPRESS     1002
#define ID_TIMER_BUTTON_PULSE  1004
#define ID_TIMER_SPINNER       1006
#define ID_TIMER_MULTITAP      1007
#define ID_TIMER_HIDE_SIP      1008

// Цвета
#define MY_COLOR_PRIMARY     RGB(41, 98, 255)
#define MY_COLOR_FOCUS       RGB(255, 0, 0)

// === ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ===
// Устройство
BOOL g_isButtonPhone = FALSE;
int g_focusIndex = 0;
int g_maxFocusIndex = 5;
BOOL g_hasHardwareKeyboard = FALSE;

// Окно
HWND g_hWndCommandBar = NULL;
HINSTANCE g_hInst = NULL;
HWND g_hWnd = NULL;
int g_screenHeight = 320;
int g_screenWidth = 240;
int g_totalHeight = 0;
int g_taskbarHeight = 26;
int g_topPanelHeight = 60;
int g_currentTab = 0;
int g_topPanelY = 0;

// Состояние сервиса
BOOL g_serviceRunning = FALSE;
BOOL g_connecting = FALSE;
BOOL g_buttonPulseState = FALSE;
int g_pulseCounter = 0;
BOOL g_bClosing = FALSE;
BOOL g_bManualMinimize = FALSE;

// Ввод
BOOL g_editingKey = FALSE;
BOOL g_addingPeer = FALSE;
BOOL g_showFullKey = FALSE;
int g_selectedPeer = -1;

// Тач-ввод (экспортируемые для input_touch.cpp)
BOOL g_dragging = FALSE;
int g_lastX = 0, g_lastY = 0;
BOOL g_longPressDetected = FALSE;
BOOL g_selectMode = FALSE;

// Мультитап
int g_lastTapKey = 0;
int g_tapIndex = 0;
WCHAR g_tempChar = 0;
DWORD g_tapTimer = 0;

// Лог
extern FILE* g_logFile;
TextSelection g_textSel;
BOOL g_logAutoScroll = TRUE;

// Буфер лога
LogEntry g_logBuffer[LOG_BUFFER_SIZE];
int g_logHead = 0;
int g_logTail = 0;
int g_logCount = 0;

// Данные
WCHAR g_privateKeyShort[64] = L"5dde162b...28dcdb3 (tap to view)";
WCHAR g_privateKeyFull[128] = L"";
WCHAR g_currentIP[50] = L"Not connected";
WCHAR g_peersList[10][128] = { L"tcp://ygg-msk-1.averyan.ru:8363" };
int g_peerCount = 1;
WCHAR g_newPeer[128] = L"";
WCHAR g_tempKey[256] = L"";
WCHAR g_connectPeerAddress[128] = L"";
// DNS-серверы Yggdrasil (первый — основной, остальные — fallback)
WCHAR g_dnsServers[8][64] = {
    L"308:25:40:bd::",   // Bratislava, SK
    L"308:62:45:62::",   // Amsterdam, NL
    L"308:84:68:55::",   // Frankfurt, DE
    L"308:c8:48:45::",   // Buffalo, US
};
int g_dnsCount = 4;
WCHAR g_newDns[64] = L"";
BOOL g_addingDns = FALSE;
// Алиас для совместимости с YggNet (основной сервер)
WCHAR g_yggDnsServerUI[64] = L"308:25:40:bd::";

// Ядро Yggdrasil
CYggdrasilCore* g_pYggCore = NULL;
IronPeer* g_pCurrentPeer = NULL;
HANDLE g_hConnectThread = NULL;

// Спиннер
int g_spinnerAngle = 0;
BOOL g_showSpinner = FALSE;

// Скролл
ScrollState g_scroll;

// === ПРОТОТИПЫ ===
void DetectDeviceType();
void ShowContextMenu(HWND hWnd, int x, int y);
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// === ФУНКЦИИ ===
void ShowKeyboard(BOOL bShow) {
    if (g_isButtonPhone) return;
    
    if (bShow) {
        SipShowIM(SIPF_ON);
        Sleep(200);
        
        HWND hSipWnd = FindWindow(L"SipWndClass", NULL);
        if (hSipWnd) {
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);
            RECT rc;
            GetWindowRect(hSipWnd, &rc);
            int height = rc.bottom - rc.top;
            
            SetWindowPos(hSipWnd, NULL, 
                        0, screenHeight - height,
                        0, 0,
                        SWP_NOSIZE | SWP_NOZORDER);
        }
        
        AddLog(L"Keyboard at bottom", LOG_INFO);
    } else {
        SipShowIM(SIPF_OFF);
    }
    InvalidateRect(g_hWnd, NULL, TRUE);
}

void ShowContextMenu(HWND hWnd, int x, int y) {
    HMENU hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, 100, L"Copy");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, 101, L"Clear log");
    
    POINT pt;
    pt.x = x;
    pt.y = y;
    ClientToScreen(hWnd, &pt);
    
    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, 
                              pt.x, pt.y, 0, hWnd, NULL);
    
    if (cmd == 101) {
        extern void ClearLog();
        ClearLog();
        InvalidateRect(hWnd, NULL, TRUE);
    }
    
    DestroyMenu(hMenu);
}

// === ОПРЕДЕЛЕНИЕ ТИПА УСТРОЙСТВА ===
void DetectDeviceType() {
    TCHAR szPlatform[64] = {0};
    if (SystemParametersInfo(SPI_GETPLATFORMTYPE, sizeof(szPlatform), szPlatform, 0)) {
        if (_tcsicmp(szPlatform, _T("Smartphone")) == 0) {
            g_isButtonPhone = TRUE;
            AddLog(L"Device: Smartphone (button)", LOG_INFO);
            AddLog(L"Controls: D-pad nav, OK=action, Back=exit", LOG_INFO);
        } else {
            g_isButtonPhone = FALSE;
            AddLog(L"Device: Pocket PC (touch)", LOG_INFO);
        }
    } else {
        g_isButtonPhone = (GetSystemMetrics(SM_MOUSEPRESENT) == 0);
        if (g_isButtonPhone) {
            AddLog(L"Device: Button phone", LOG_INFO);
        } else {
            AddLog(L"Device: Touch device", LOG_INFO);
        }
    }
    g_hasHardwareKeyboard = (GetKeyboardType(0) != 0);
    if (g_hasHardwareKeyboard) {
        AddLog(L"Hardware keyboard detected", LOG_INFO);
    }
    if (g_isButtonPhone) {
        g_topPanelY = 0;
        g_taskbarHeight = 0;
        InitButtonInput();
    } else {
        InitTouchInput();
    }
}

// === ГЛАВНАЯ ОКОННАЯ ПРОЦЕДУРА ===
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE:
            Scroll_Init(&g_scroll, hWnd);
            g_scroll.flags = SCROLL_FLAG_Y | SCROLL_FLAG_BOUNCE;
            g_taskbarHeight = GetSystemMetrics(SM_CYCAPTION);
            if (g_taskbarHeight < 20) g_taskbarHeight = 26;
            InitLogSystem();
            DetectDeviceType();
            TextSel_Init(&g_textSel);
            LoadOrGenerateKeys();
            if (g_isButtonPhone) {
                SHFullScreen(hWnd, SHFS_HIDETASKBAR | SHFS_HIDESIPBUTTON);
            } else {
                // Для Pocket PC тоже скрываем SIP button
                SHFullScreen(hWnd, SHFS_HIDESIPBUTTON);
            }
            return 0;
            
        case WM_SIZE:
            // При восстановлении окна из свёрнутого состояния скрываем клавиатуру
            if (wParam == SIZE_RESTORED || wParam == SIZE_MAXIMIZED) {
                ShowKeyboard(FALSE);
                SipShowIM(SIPF_OFF);
            }
            if (!g_isButtonPhone) {
                RECT rcWork;
                SystemParametersInfo(SPI_GETWORKAREA, 0, &rcWork, 0);
                g_topPanelY = g_screenHeight - (rcWork.bottom - rcWork.top);
            } else {
                g_topPanelY = 0;
            }
            {
                HDC hdc = GetDC(hWnd);
                CreateBackBuffer(hdc, LOWORD(lParam), HIWORD(lParam));
                ReleaseDC(hWnd, hdc);
            }
            InvalidateRect(hWnd, NULL, FALSE);
            return 0;
            
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            RECT rcClient;
            GetClientRect(hWnd, &rcClient);
            int width = rcClient.right - rcClient.left;
            int height = rcClient.bottom - rcClient.top;
            
            if (g_hBackBuffer == NULL || g_backBufferWidth != width || g_backBufferHeight != height) {
                CreateBackBuffer(hdc, width, height);
            }
            
            DrawInterface(g_hBackDC, width, height);
            BitBlt(hdc, 0, 0, width, height, g_hBackDC, 0, 0, SRCCOPY);
            
            EndPaint(hWnd, &ps);
            return 0;
        }
        
        case WM_ERASEBKGND:
            return 1;
            
        case WM_TIMER:
            switch(wParam) {
                case ID_TIMER_HIDE_SIP:
                    KillTimer(hWnd, ID_TIMER_HIDE_SIP);
                    SipShowIM(SIPF_OFF);
                    SHFullScreen(hWnd, SHFS_HIDESIPBUTTON);
                    break;
                case ID_TIMER_SPINNER:
                    g_spinnerAngle = (g_spinnerAngle + 15) % 360;
                    InvalidateRect(hWnd, NULL, FALSE);
                    break;
                case ID_TIMER_BUTTON_PULSE:
                    g_buttonPulseState = !g_buttonPulseState;
                    g_pulseCounter++;
                    if (g_pulseCounter > 10) {
                        g_pulseCounter = 0;
                        KillTimer(hWnd, ID_TIMER_BUTTON_PULSE);
                    }
                    InvalidateRect(hWnd, NULL, FALSE);
                    break;
                case ID_TIMER_SCROLL:
                    if (Scroll_OnTimer(&g_scroll)) {
                        InvalidateRect(hWnd, NULL, FALSE);
                    }
                    break;
                case ID_TIMER_LONGPRESS:
                    KillTimer(hWnd, ID_TIMER_LONGPRESS);
                    if (g_currentTab == 1 && !g_isButtonPhone) {
                        ShowContextMenu(hWnd, g_lastX, g_lastY);
                    }
                    break;
                    
                case ID_TIMER_MULTITAP:
                    // Делегируем в input_buttons.cpp
                    if (g_isButtonPhone) {
                        extern void OnMultitapTimeout(HWND hWnd);
                        OnMultitapTimeout(hWnd);
                    }
                    break;
            }
            return 0;
            
        case WM_CHAR:
            if (g_editingKey) {
                int len = wcslen(g_tempKey);
                if (wParam == VK_BACK && len > 0) {
                    g_tempKey[len - 1] = 0;
                    InvalidateRect(hWnd, NULL, TRUE);
                } else if (wParam == VK_RETURN) {
                    if (len > 0) {
                        wcscpy(g_privateKeyFull, g_tempKey);
                        wcsncpy(g_privateKeyShort, g_tempKey, 20);
                        g_privateKeyShort[20] = L'.';
                        g_privateKeyShort[21] = L'.';
                        g_privateKeyShort[22] = L'.';
                        g_privateKeyShort[23] = 0;
                        AddLog(L"Private key updated", LOG_SUCCESS);
                    }
                    g_editingKey = FALSE;
                    g_tempKey[0] = 0;
                    ShowKeyboard(FALSE);
                    InvalidateRect(hWnd, NULL, TRUE);
                } else if (len < 255) {
                    g_tempKey[len] = (WCHAR)wParam;
                    g_tempKey[len + 1] = 0;
                    InvalidateRect(hWnd, NULL, TRUE);
                }
                return 0;
            }
            
            // Для кнопочных телефонов мультитап в input_buttons.cpp
            if (g_addingPeer && !g_isButtonPhone) {
                int len = wcslen(g_newPeer);
                if (wParam == VK_BACK && len > 0) {
                    g_newPeer[len - 1] = 0;
                    InvalidateRect(hWnd, NULL, TRUE);
                } else if (wParam == VK_RETURN) {
                    if (len > 0 && g_peerCount < 10) {
                        wcscpy(g_peersList[g_peerCount], g_newPeer);
                        g_peerCount++;
                        AddLog(L"New peer added", LOG_SUCCESS);
                    }
                    g_addingPeer = FALSE;
                    g_newPeer[0] = 0;
                    ShowKeyboard(FALSE);
                    InvalidateRect(hWnd, NULL, TRUE);
                } else if (len < 127) {
                    g_newPeer[len] = (WCHAR)wParam;
                    g_newPeer[len + 1] = 0;
                    InvalidateRect(hWnd, NULL, TRUE);
                }
                return 0;
            }
            if (g_addingDns && !g_isButtonPhone) {
                int len = wcslen(g_newDns);
                if (wParam == VK_BACK && len > 0) {
                    g_newDns[len - 1] = 0;
                    InvalidateRect(hWnd, NULL, TRUE);
                } else if (wParam == VK_RETURN) {
                    if (len > 0 && g_dnsCount < 8) {
                        wcscpy(g_dnsServers[g_dnsCount], g_newDns);
                        g_dnsCount++;
                        AddLog(L"DNS server added", LOG_SUCCESS);
                        extern void SaveConfig();
                        SaveConfig();
                    }
                    g_addingDns = FALSE;
                    g_newDns[0] = 0;
                    ShowKeyboard(FALSE);
                    InvalidateRect(hWnd, NULL, TRUE);
                } else if (len < 63) {
                    g_newDns[len] = (WCHAR)wParam;
                    g_newDns[len + 1] = 0;
                    InvalidateRect(hWnd, NULL, TRUE);
                }
                return 0;
            }
            break;
            
        case WM_USER + 100: // WM_CONNECT_COMPLETE
            OnConnectComplete();
            return 0;
            
        case WM_USER + 200: // Запрос скрыть SIP после восстановления из SW_HIDE
            SetTimer(hWnd, ID_TIMER_HIDE_SIP, 300, NULL);
            return 0;

        case WM_USER + 101: // WM_CONNECT_FAILED
            OnConnectFailed();
            return 0;

        case WM_USER + 102: // WM_PEER_DISCONNECTED — автопереподключение
            if (g_serviceRunning) {
                OnAutoReconnect(hWnd);
            }
            return 0;
            
        case WM_ACTIVATE:
            // Стандартная обработка для Windows Mobile
            SHHandleWMActivate(hWnd, wParam, lParam, NULL, 0);

            if (LOWORD(wParam) == WA_INACTIVE) {
                ShowKeyboard(FALSE);
                g_editingKey = FALSE;
                g_addingPeer = FALSE;
                g_addingDns = FALSE;
                if (!g_bManualMinimize) {
                    PostQuitMessage(0);
                    return 0;
                }
                g_bManualMinimize = FALSE;
            } else if (LOWORD(wParam) == WA_ACTIVE || LOWORD(wParam) == WA_CLICKACTIVE) {
                ShowKeyboard(FALSE);
            }
            break;
            
        case WM_SETTINGCHANGE:
            // Стандартная обработка для Windows Mobile (SIP и т.д.)
            SHHandleWMSettingChange(hWnd, wParam, lParam, NULL);
            break;
            
        case WM_KEYDOWN:
            // Центральная кнопка (OK/Home) для сворачивания
            if (wParam == VK_RETURN && !g_editingKey && !g_addingPeer && !g_isButtonPhone) {
                g_bManualMinimize = TRUE;
                ShowWindow(hWnd, SW_HIDE);
                AddLog(L"Minimized (OK button)", LOG_INFO);
                return 0;
            }
            break;
            
        case WM_DESTROY:
            // Останавливаем прокси
            extern void StopHttpProxyLocal();
            StopHttpProxyLocal();
            
            if (g_logFile) {
                fclose(g_logFile);
                g_logFile = NULL;
            }
            if (g_hBackBuffer) {
                DeleteObject(g_hBackBuffer);
                DeleteDC(g_hBackDC);
            }
            KillTimer(hWnd, ID_TIMER_BUTTON_PULSE);
            KillTimer(hWnd, ID_TIMER_SPINNER);
            KillTimer(hWnd, ID_TIMER_SCROLL);
            CYggdrasilCore::DestroyInstance();
            WSACleanup();
            PostQuitMessage(0);
            return 0;
    }
    
    // === ДЕЛЕГИРУЕМ ОБРАБОТКУ ВВОДА В МОДУЛИ ===
    if (g_isButtonPhone) {
        if (HandleButtonMessage(hWnd, msg, wParam, lParam)) {
            return 0;
        }
    } else {
        if (HandleTouchMessage(hWnd, msg, wParam, lParam)) {
            return 0;
        }
    }
    
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// === ТОЧКА ВХОДА ===
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPWSTR lpCmdLine, int nCmdShow) {
    HWND hExistingWnd = FindWindow(L"YggstackClass", NULL);
    if (hExistingWnd != NULL) {
        ShowWindow(hExistingWnd, SW_SHOW);
        SetForegroundWindow(hExistingWnd);
        // Просим уже запущенный процесс скрыть SIP после получения фокуса
        PostMessage(hExistingWnd, WM_USER + 200, 0, 0);
        return 0;
    }

    if (!InitWinsock()) {
        MessageBox(NULL, L"Network initialization failed", L"Error", MB_OK);
        return 0;
    }
    
    // Инициализация системы логирования (после Winsock, до использования логов)
    InitLogSystem();

    // Загружаем конфиг (ключи, пиры, DNS-сервер) до показа UI
    LoadConfig();

    g_hInst = hInstance;
    
    WNDCLASS wc = {0};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wc.hCursor = 0;
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"YggstackClass";
    
    if (!RegisterClass(&wc)) {
        return 0;
    }
    
    g_screenWidth = GetSystemMetrics(SM_CXSCREEN);
    g_screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    TCHAR szPlatform[64] = {0};
    BOOL isButton = FALSE;
    if (SystemParametersInfo(SPI_GETPLATFORMTYPE, sizeof(szPlatform), szPlatform, 0)) {
        isButton = (_tcsicmp(szPlatform, _T("Smartphone")) == 0);
    }
    
    if (isButton) {
        g_hWnd = CreateWindow(L"YggstackClass", L"Yggstack",
            WS_VISIBLE, 0, 0, g_screenWidth, g_screenHeight,
            NULL, NULL, hInstance, NULL);
    } else {
        g_hWnd = CreateWindow(L"YggstackClass", L"Yggstack",
            WS_VISIBLE | WS_POPUP, 0, 0, g_screenWidth, g_screenHeight,
            NULL, NULL, hInstance, NULL);
    }
    
    if (!g_hWnd) {
        return 0;
    }

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);
    
    // Принудительно скрываем клавиатуру после показа окна
    // (нужно при восстановлении из Programs)
    Sleep(50);  // Небольшая задержка для системы
    ShowKeyboard(FALSE);
    SipShowIM(SIPF_OFF);
    
    // Для Pocket PC принудительно скрываем SIP button
    if (!isButton) {
        SHFullScreen(g_hWnd, SHFS_HIDESIPBUTTON);
    }
    
    MSG msg;
    while(GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    WSACleanup();
    return msg.wParam;
}
