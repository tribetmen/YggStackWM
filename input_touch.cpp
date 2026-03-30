// input_touch.cpp - Обработка сенсорного ввода
// Тач-скрин, свайпы, долгое нажатие, контекстное меню

#include "stdafx.h"
#include "YggInput.h"
#include "textselector.h"
#include "ygg_constants.h"
#include "YggNet.h"
#include "YggdrasilCore.h"

// Локальные переменные только для этого модуля:
extern TextSelection g_textSel;
extern BOOL g_selectMode;

// Таймеры
#define ID_TIMER_LONGPRESS     1002
#define ID_TIMER_SPINNER       1006

// ID контролов
#define IDC_BTN_CONF            2001
#define IDC_BTN_LOGS            2002
#define IDC_BTN_INFO            2003
#define IDC_BTN_START           2004
#define IDC_BTN_STOP            2005
#define IDC_BTN_ADD_PEER        2006
#define IDC_EDIT_PEER           2007
#define IDC_LIST_PEERS          2008
#define IDC_EDIT_LOG            2009
#define IDC_IP_ADDRESS          2010
#define IDC_STATUS_ICON         2011
#define IDC_BTN_CLEAR_LOG       2012
#define IDM_COPY                 100
#define IDM_CLEAR                101

// Цвета
#define MY_COLOR_PRIMARY     RGB(41, 98, 255)
#define MY_COLOR_PRIMARY_DARK RGB(25, 60, 170)
#define MY_COLOR_SUCCESS     RGB(40, 200, 100)
#define MY_COLOR_WARNING     RGB(255, 170, 0)
#define MY_COLOR_BG          RGB(250, 250, 250)
#define MY_COLOR_CARD        RGB(255, 255, 255)
#define MY_COLOR_TEXT        RGB(30, 30, 30)
#define MY_COLOR_TEXT_LIGHT  RGB(120, 120, 120)
#define MY_COLOR_BORDER      RGB(220, 220, 220)
#define MY_COLOR_HIGHLIGHT   RGB(240, 240, 250)

// === Функции из Yggstack.cpp ===
extern void AddLog(LPCWSTR text, BYTE type);
extern void OnStartService();
extern void ShowContextMenu(HWND hWnd, int x, int y);
extern void ShowKeyboard(BOOL bShow);
extern void DrawFrameRect(HDC hdc, RECT* rc, COLORREF color);
extern COLORREF GetLogColor(BYTE type);

// === Локальные переменные ===
static BOOL s_longPressTimerActive = FALSE;

// === Инициализация ===
void InitTouchInput() {
    g_dragging = FALSE;
    g_longPressDetected = FALSE;
    s_longPressTimerActive = FALSE;
}

// === Обработка нажатия ===
void HandleLButtonDown(HWND hWnd, int x, int y) {
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);
    int width = rcClient.right - rcClient.left;
    int height = rcClient.bottom - rcClient.top;
    
    g_lastX = x;
    g_lastY = y;
    g_longPressDetected = FALSE;
    
    // Запускаем таймер долгого нажатия
    SetTimer(hWnd, ID_TIMER_LONGPRESS, 500, NULL);
    s_longPressTimerActive = TRUE;
    
    // Проверяем нажатие на нижнюю панель (табы)
    int panelHeight = (height >= 640) ? 55 : ((height >= 480) ? 50 : 45);
    int bottomY = height - panelHeight;
    
    if (y >= bottomY && y <= height) {
        KillTimer(hWnd, ID_TIMER_LONGPRESS);
        s_longPressTimerActive = FALSE;
        
        int margin = (width >= 640) ? 10 : ((width >= 480) ? 8 : 5);
        int btnWidth = (width - (margin * 4)) / 3;
        
        if (x >= margin && x <= margin + btnWidth) {
            g_currentTab = 0;
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (x >= margin * 2 + btnWidth && x <= margin * 2 + btnWidth * 2) {
            g_currentTab = 1;
            if (g_editingKey || g_addingPeer) {
                ShowKeyboard(FALSE);
                g_editingKey = FALSE;
                g_addingPeer = FALSE;
            }
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (x >= margin * 3 + btnWidth * 2 && x <= margin * 3 + btnWidth * 3) {
            g_currentTab = 2;
            if (g_editingKey || g_addingPeer) {
                ShowKeyboard(FALSE);
                g_editingKey = FALSE;
                g_addingPeer = FALSE;
            }
            InvalidateRect(hWnd, NULL, TRUE);
        }
        return;
    }
    
    // === Конфиг вкладка ===
    if (g_currentTab == 0) {
        int margin = (width >= 640) ? 30 : ((width >= 480) ? 20 : 5);
        int scrollY = g_scroll.y;
        // Как в YggDraw.cpp DrawConfigTab
        int sectionHeight = (height >= 640) ? 30 : 25;
        int keyFieldHeight = (width >= 640) ? 70 : ((width >= 480) ? 65 : 55);
        int contentY = g_topPanelY + 50;
        
        // === Секция ключа ===
        // Сначала заголовок "Private Key" (sectionHeight)
        // Потом поле ключа на keyFieldY
        int keyFieldY = contentY - scrollY + sectionHeight;
        
        // Кнопка просмотра ключа (рядом с полем ключа)
        RECT rcViewBtn = {width - margin - 25, keyFieldY, width - margin, keyFieldY + 25};
        if (x >= rcViewBtn.left && x <= rcViewBtn.right && 
            y >= rcViewBtn.top && y <= rcViewBtn.bottom) {
            g_showFullKey = !g_showFullKey;
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }
        
        // Поле ключа
        RECT rcKey = {margin, keyFieldY, width - margin - 30, keyFieldY + keyFieldHeight};
        if (x >= rcKey.left && x <= rcKey.right && 
            y >= rcKey.top && y <= rcKey.bottom) {
            if (!g_editingKey) {
                g_editingKey = TRUE;
                wcscpy(g_tempKey, g_privateKeyFull);
                ShowKeyboard(TRUE);
            } else {
                g_editingKey = FALSE;
                g_tempKey[0] = 0;
                ShowKeyboard(FALSE);
            }
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }
        
        // === Секция пиров ===
        // После поля ключа: +10 (или +25 при редактировании)
        int peersSectionY = keyFieldY + keyFieldHeight + 10;
        if (g_editingKey) {
            peersSectionY = keyFieldY + keyFieldHeight + 25;
        }
        
        // Кнопка добавления пира
        RECT rcAddPeer = {width - margin - 25, peersSectionY, width - margin, peersSectionY + 22};
        if (x >= rcAddPeer.left && x <= rcAddPeer.right && 
            y >= rcAddPeer.top && y <= rcAddPeer.bottom) {
            g_addingPeer = !g_addingPeer;
            if (g_addingPeer) {
                // Явная инициализация tcp://
                g_newPeer[0] = L't';
                g_newPeer[1] = L'c';
                g_newPeer[2] = L'p';
                g_newPeer[3] = L':';
                g_newPeer[4] = L'/';
                g_newPeer[5] = L'/';
                g_newPeer[6] = 0;
                ShowKeyboard(TRUE);
            } else {
                ShowKeyboard(FALSE);
            }
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }
        
        // Список пиров - удаление (крестик)
        // После заголовка Peers (sectionHeight) и поля ввода (если есть)
        int peersListY = peersSectionY + sectionHeight;
        if (g_addingPeer) {
            peersListY += 55;
        }
        
        // Как в YggDraw.cpp: peerItemHeight = (height >= 640) ? 26 : 22
        int itemHeight = (height >= 640) ? 26 : 22;
        for (int i = 0; i < g_peerCount; i++) {
            int peerY = peersListY + i * itemHeight;
            RECT rcDelete = {width - margin - 20, peerY, width - margin - 5, peerY + 18};
            if (x >= rcDelete.left && x <= rcDelete.right &&
                y >= rcDelete.top && y <= rcDelete.bottom) {
                for (int j = i; j < g_peerCount - 1; j++) {
                    wcscpy(g_peersList[j], g_peersList[j + 1]);
                }
                g_peerCount--;
                g_peersList[g_peerCount][0] = 0;
                SaveConfig();
                InvalidateRect(hWnd, NULL, TRUE);
                return;
            }
        }
        
        // Кнопка HTTP Proxy (перед IP секцией) - вычисляем позицию как в отрисовке
        extern int g_peerCount;
        extern BOOL g_addingPeer;
        extern BOOL g_isButtonPhone;
        int peerItemHeight = g_isButtonPhone ? 28 : ((height >= 640) ? 26 : 22);
        
        // Точное вычисление позиции как в YggDraw.cpp DrawConfigTab
        int proxyY = g_isButtonPhone ? (g_topPanelY + 22) : (g_topPanelY + 50);
        proxyY += sectionHeight;  // Private Key заголовок, потом y += sectionHeight
        proxyY += keyFieldHeight;  // Поле ключа
        proxyY += sectionHeight;  // Peers заголовок, потом y += sectionHeight  
        // После этого кнопка Add (высота 22), затем y += sectionHeight
        if (g_addingPeer) proxyY += 55;  // Поле ввода
        proxyY += g_peerCount * peerItemHeight;  // Список пиров
        proxyY -= g_scroll.y;  // Учитываем прокрутку
        
        RECT rcHttpBtn = {margin, proxyY, width - margin, proxyY + 25};
        extern BOOL g_httpProxyRunning;
        if (x >= rcHttpBtn.left && x <= rcHttpBtn.right &&
            y >= rcHttpBtn.top && y <= rcHttpBtn.bottom) {
            KillTimer(hWnd, ID_TIMER_LONGPRESS);
            extern void OnToggleHttpProxy();
            OnToggleHttpProxy();
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }
        
        // Кнопка Start/Stop
        int btnY = height - 80;
        if (y >= btnY && y <= btnY + 35 && x >= 20 && x <= width - 20) {
            KillTimer(hWnd, ID_TIMER_LONGPRESS);
            OnStartService();
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }
    }
    
    // === Логи вкладка ===
    if (g_currentTab == 1) {
        int margin = (width >= 640) ? 15 : ((width >= 480) ? 12 : 8);
        int panelY = g_topPanelY + 45;
        
        // Кнопка On/Off
        RECT rcToggle = {width - margin - 120, panelY, width - margin - 65, panelY + 25};
        if (x >= rcToggle.left && x <= rcToggle.right &&
            y >= rcToggle.top && y <= rcToggle.bottom) {
            ToggleLogs();
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }
        
        // Кнопка Clear
        RECT rcClear = {width - margin - 60, panelY, width - margin, panelY + 25};
        if (x >= rcClear.left && x <= rcClear.right &&
            y >= rcClear.top && y <= rcClear.bottom) {
            // Очистка лога
            extern int g_logHead, g_logTail, g_logCount;
            extern LogEntry g_logBuffer[];
            g_logHead = 0;
            g_logTail = 0;
            g_logCount = 0;
            memset(g_logBuffer, 0, sizeof(LogEntry) * 200);
            if (g_logsEnabled) AddLog(L"Log cleared", 0); // LOG_INFO = 0
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }
    }
    
    // Начинаем перетаскивание
    g_dragging = TRUE;
    Scroll_OnDragStart(&g_scroll, x, y);
    SetCapture(hWnd);
}

// === Обработка отпускания ===
void HandleLButtonUp(HWND hWnd) {
    if (s_longPressTimerActive) {
        KillTimer(hWnd, ID_TIMER_LONGPRESS);
        s_longPressTimerActive = FALSE;
    }
    
    if (g_longPressDetected) {
        g_longPressDetected = FALSE;
    } else {
        g_dragging = FALSE;
        Scroll_OnDragEnd(&g_scroll);
        ReleaseCapture();
        InvalidateRect(hWnd, NULL, FALSE);
    }
}

// === Обработка движения ===
void HandleMouseMove(HWND hWnd, int x, int y) {
    if (g_dragging) {
        int oldY = g_scroll.y;
        Scroll_OnDragMove(&g_scroll, x, y);
        if (oldY != g_scroll.y) {
            InvalidateRect(hWnd, NULL, FALSE);
        }
    }
}

// === Обработка долгого нажатия ===
void HandleLongPress(HWND hWnd) {
    if (s_longPressTimerActive) {
        KillTimer(hWnd, ID_TIMER_LONGPRESS);
        s_longPressTimerActive = FALSE;
    }
    
    if (g_currentTab == 1) {
        g_longPressDetected = TRUE;
        ShowContextMenu(hWnd, g_lastX, g_lastY);
    }
}

// === Главная функция обработки сообщений ===
BOOL HandleTouchMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CHAR:
            // Виртуальная клавиатура (SIP)
            if (wParam == VK_BACK) {
                if (g_editingKey) {
                    int len = wcslen(g_tempKey);
                    if (len > 0) g_tempKey[len - 1] = 0;
                } else if (g_addingPeer) {
                    int len = wcslen(g_newPeer);
                    if (len > 0) g_newPeer[len - 1] = 0;
                }
                InvalidateRect(hWnd, NULL, FALSE);
                return TRUE;
            } else if (wParam == VK_RETURN) {
                if (g_editingKey) {
                    wcscpy(g_privateKeyFull, g_tempKey);
                    g_showFullKey = FALSE;
                    g_editingKey = FALSE;
                    ShowKeyboard(FALSE);
                    SaveConfig();
                } else if (g_addingPeer) {
                    g_addingPeer = FALSE;
                    ShowKeyboard(FALSE);
                    if (wcslen(g_newPeer) > 0) {
                        wcscpy(g_peersList[g_peerCount], g_newPeer);
                        g_peerCount++;
                        SaveConfig();
                    }
                }
                InvalidateRect(hWnd, NULL, FALSE);
                return TRUE;
            } else if (wParam >= 32 && wParam < 127) {
                WCHAR ch = (WCHAR)wParam;
                if (g_editingKey) {
                    int len = wcslen(g_tempKey);
                    if (len < 255) {
                        g_tempKey[len] = ch;
                        g_tempKey[len + 1] = 0;
                    }
                } else if (g_addingPeer) {
                    int len = wcslen(g_newPeer);
                    if (len < 127) {
                        g_newPeer[len] = ch;
                        g_newPeer[len + 1] = 0;
                    }
                }
                InvalidateRect(hWnd, NULL, FALSE);
                return TRUE;
            }
            return FALSE;
            
        case WM_TIMER:
            if (wParam == ID_TIMER_LONGPRESS && s_longPressTimerActive) {
                KillTimer(hWnd, ID_TIMER_LONGPRESS);
                s_longPressTimerActive = FALSE;
                if (g_currentTab == 1) {
                    g_longPressDetected = TRUE;
                    ShowContextMenu(hWnd, g_lastX, g_lastY);
                }
                return TRUE;
            }
            return FALSE;
            
        case WM_LBUTTONDOWN:
            HandleLButtonDown(hWnd, LOWORD(lParam), HIWORD(lParam));
            return TRUE;
            
        case WM_LBUTTONUP:
            HandleLButtonUp(hWnd);
            return TRUE;
            
        case WM_MOUSEMOVE:
            if (wParam & MK_LBUTTON) {
                HandleMouseMove(hWnd, LOWORD(lParam), HIWORD(lParam));
            }
            return TRUE;
    }
    return FALSE;
}
