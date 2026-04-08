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
extern void SaveConfig();

// === Локальные переменные ===
static BOOL s_longPressTimerActive = FALSE;
static BOOL s_tapCancelled         = FALSE; // TRUE если палец сдвинулся — тап не засчитывается
static int  s_tapX = 0, s_tapY = 0;        // координаты нажатия для LButtonUp
#define TAP_SLOP 8                           // пикселей допуска до отмены тапа

// === Инициализация ===
void InitTouchInput() {
    g_dragging = FALSE;
    g_longPressDetected = FALSE;
    s_longPressTimerActive = FALSE;
}

// === Обработка тапа (вызывается из LButtonUp если не было drag) ===
static void HandleTap(HWND hWnd, int x, int y) {
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);
    int width  = rcClient.right - rcClient.left;
    int height = rcClient.bottom - rcClient.top;

    // Нижняя панель (табы)
    {
        int SC2   = (width >= 640) ? 3 : ((width >= 480) ? 5 : 4);
        int SD2   = (width >= 640) ? 2 : ((width >= 480) ? 4 : 4);
        int tabH2 = 48 * SC2 / SD2;
        if (y >= height - tabH2) {
            int tw    = width / 3;
            int newTab = (x < tw) ? 0 : (x < tw*2) ? 1 : 2;
            if (newTab != g_currentTab) {
                g_currentTab = newTab;
                if (g_editingKey || g_addingPeer || g_addingDns) {
                    ShowKeyboard(FALSE);
                    g_editingKey = FALSE; g_addingPeer = FALSE; g_addingDns = FALSE;
                }
                InvalidateRect(hWnd, NULL, TRUE);
            }
            return;
        }
    }

    // === Конфиг вкладка ===
    if (g_currentTab == 0) {
        extern BOOL g_isButtonPhone;
        extern BOOL g_httpProxyRunning;
        extern WCHAR g_dnsServers[8][64];
        extern int g_dnsCount;
        extern BOOL g_addingDns;
        extern WCHAR g_newDns[64];

        int SC = (width >= 640) ? 3 : ((width >= 480) ? 5 : 4);
        int SD = (width >= 640) ? 2 : ((width >= 480) ? 4 : 4);
        #define SC_T(px) ((px) * SC / SD)

        int tabH  = SC_T(48);
        int barH  = (width >= 480) ? 44 : 32; // TopBarHeight, синхронно с YggDraw.cpp
        int topH  = g_topPanelY + barH;
        int mx    = SC_T(10);
        int hdrH  = SC_T(20);
        int itemH = SC_T(38);
        int rowH  = SC_T(40);
        int btnH  = SC_T(42);
        int sY    = g_scroll.y;

        // ── Кнопка Start/Stop (фиксированная, проверяем ПЕРВОЙ) ──
        {
            int by = height - tabH - btnH - SC_T(8);
            if (x >= mx && x <= width - mx && y >= by && y <= by + btnH) {
                OnStartService();
                InvalidateRect(hWnd, NULL, TRUE);
                return;
            }
        }

        // Высота карточки ключа совпадает с Draw: 4*(charSz.cy+2) + Scale(10).
        // charSz.cy: ~12 на 240px, ~16 на 480px, ~20 на 640px.
        // На больших экранах запас +6px, на маленьких — без запаса.
        int keyLineH = (width >= 640) ? 30 : ((width >= 480) ? 26 : 16);
        int keyCardH = 4 * keyLineH + SC_T(10) + ((width >= 480) ? 14 : 0);

        int cy = topH + SC_T(8);

        // ── Private Key ──
        cy += hdrH;
        {
            int ctop  = cy - sY;
            int cbottom = ctop + keyCardH;
            // Вся карточка — тап переключает редактирование
            if (x >= mx && x <= width - mx && y >= ctop && y <= cbottom) {
                if (!g_editingKey) {
                    g_editingKey = TRUE;
                    g_showFullKey = FALSE;
                    wcscpy(g_tempKey, g_privateKeyFull);
                    ShowKeyboard(TRUE);
                } else {
                    g_editingKey = FALSE; g_tempKey[0] = 0;
                    ShowKeyboard(FALSE);
                }
                InvalidateRect(hWnd, NULL, TRUE);
                return;
            }
            cy += keyCardH + SC_T(12);
        }

        // ── Peers ──
        cy += hdrH;
        {
            int icy = cy;
            for (int i = 0; i < g_peerCount; i++) {
                int rtop = icy - sY;
                int delW = SC_T(32);
                int delL = width - mx - delW - 4, delR = width - mx - 4;
                int delTop = rtop + (itemH - SC_T(24))/2;
                int delBot = rtop + (itemH + SC_T(24))/2;
                if (x >= delL && x <= delR && y >= delTop && y <= delBot) {
                    for (int j = i; j < g_peerCount - 1; j++)
                        wcscpy(g_peersList[j], g_peersList[j+1]);
                    g_peerCount--;
                    g_peersList[g_peerCount][0] = 0;
                    SaveConfig();
                    InvalidateRect(hWnd, NULL, TRUE);
                    return;
                }
                icy += itemH;
            }
            if (g_addingPeer) icy += itemH;
            {   // Строка «+ Add peer»
                int rtop = icy - sY;
                if (x >= mx && x <= width - mx && y >= rtop && y <= rtop + itemH) {
                    g_addingPeer = !g_addingPeer;
                    if (g_addingPeer) {
                        g_newPeer[0]=L't'; g_newPeer[1]=L'c'; g_newPeer[2]=L'p';
                        g_newPeer[3]=L':'; g_newPeer[4]=L'/'; g_newPeer[5]=L'/';
                        g_newPeer[6]=0;
                        ShowKeyboard(TRUE);
                    } else {
                        g_newPeer[0] = 0;
                        ShowKeyboard(FALSE);
                    }
                    InvalidateRect(hWnd, NULL, TRUE);
                    return;
                }
            }
            int linesCount = g_peerCount + (g_addingPeer ? 1 : 0) + 1;
            cy += linesCount * itemH + SC_T(12);
        }

        // ── Your Yggdrasil IP ── (не кликабельно)
        // Высота считается как в Draw: построчный перенос адаптивно по ширине
        cy += hdrH;
        {
            extern WCHAR g_currentIP[50];
            int ipLineH  = (width >= 640) ? 24 : ((width >= 480) ? 20 : 17);
            int ipPad    = SC_T(8);
            int charW    = (width >= 640) ? 9 : ((width >= 480) ? 8 : 7); // приближение ширины символа
            int textW    = (width - 2 * mx) - 2 * ipPad;
            int charsPerLine = (charW > 0) ? (textW / charW) : 20;
            if (charsPerLine < 4) charsPerLine = 4;
            int ipLen    = (int)wcslen(g_currentIP);
            int ipLines  = (ipLen > 0) ? ((ipLen + charsPerLine - 1) / charsPerLine) : 1;
            int ipCardH  = ipLines * ipLineH + 2 * ipPad;
            int minH     = SC_T(40);
            if (ipCardH < minH) ipCardH = minH;
            cy += ipCardH + SC_T(12);
        }

        // ── Proxy Configuration ──
        cy += hdrH;
        {
            int ctop = cy - sY;
            if (x >= mx && x <= width - mx && y >= ctop && y <= ctop + rowH) {
                extern void OnToggleHttpProxy();
                OnToggleHttpProxy();
                InvalidateRect(hWnd, NULL, TRUE);
                return;
            }
            cy += rowH + SC_T(12);
        }

        // ── DNS Servers ──
        cy += hdrH;
        {
            int icy = cy;
            for (int i = 0; i < g_dnsCount; i++) {
                int rtop = icy - sY;
                int delW = SC_T(32);
                int delL = width - mx - delW - 4, delR = width - mx - 4;
                int delTop = rtop + (itemH - SC_T(24))/2;
                int delBot = rtop + (itemH + SC_T(24))/2;
                if (x >= delL && x <= delR && y >= delTop && y <= delBot) {
                    if (g_dnsCount > 1) {
                        for (int j = i; j < g_dnsCount - 1; j++)
                            wcscpy(g_dnsServers[j], g_dnsServers[j+1]);
                        g_dnsCount--;
                        g_dnsServers[g_dnsCount][0] = L'\0';
                        SaveConfig();
                    }
                    InvalidateRect(hWnd, NULL, TRUE);
                    return;
                }
                icy += itemH;
            }
            if (g_addingDns) icy += itemH;
            {   // Строка «+ Add DNS»
                int rtop = icy - sY;
                if (x >= mx && x <= width - mx && y >= rtop && y <= rtop + itemH) {
                    g_addingDns = !g_addingDns;
                    if (g_addingDns) { g_newDns[0] = L'\0'; ShowKeyboard(TRUE); }
                    else             { ShowKeyboard(FALSE); }
                    InvalidateRect(hWnd, NULL, TRUE);
                    return;
                }
            }
        }

        #undef SC_T
    }

    // === Логи вкладка ===
    if (g_currentTab == 1) {
        int SC = (width >= 640) ? 3 : ((width >= 480) ? 5 : 4);
        int SD = (width >= 640) ? 2 : ((width >= 480) ? 4 : 4);
        #define SC_L(px) ((px) * SC / SD)

        int topH = g_topPanelY + ((width >= 480) ? 44 : 32);
        int mx   = SC_L(8);
        int btnH = SC_L(28);
        int panY = topH + SC_L(6);

        RECT rcOn = { width - mx - SC_L(120), panY, width - mx - SC_L(62), panY + btnH };
        if (x >= rcOn.left && x <= rcOn.right && y >= rcOn.top && y <= rcOn.bottom) {
            ToggleLogs();
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }

        RECT rcCl = { width - mx - SC_L(56), panY, width - mx, panY + btnH };
        if (x >= rcCl.left && x <= rcCl.right && y >= rcCl.top && y <= rcCl.bottom) {
            extern int g_logHead, g_logTail, g_logCount;
            extern LogEntry g_logBuffer[];
            g_logHead = 0; g_logTail = 0; g_logCount = 0;
            memset(g_logBuffer, 0, sizeof(LogEntry) * 200);
            if (g_logsEnabled) AddLog(L"Log cleared", 0);
            InvalidateRect(hWnd, NULL, TRUE);
            return;
        }

        #undef SC_L
    }
}

// === Обработка нажатия (только запоминаем координаты и начинаем скролл) ===
void HandleLButtonDown(HWND hWnd, int x, int y) {
    g_lastX = x;
    g_lastY = y;
    s_tapX  = x;
    s_tapY  = y;
    s_tapCancelled      = FALSE;
    g_longPressDetected = FALSE;

    SetTimer(hWnd, ID_TIMER_LONGPRESS, 500, NULL);
    s_longPressTimerActive = TRUE;

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

    g_dragging = FALSE;
    Scroll_OnDragEnd(&g_scroll);
    ReleaseCapture();
    InvalidateRect(hWnd, NULL, FALSE);

    if (!g_longPressDetected && !s_tapCancelled) {
        HandleTap(hWnd, s_tapX, s_tapY);
    }
    g_longPressDetected = FALSE;
}

// === Обработка движения ===
void HandleMouseMove(HWND hWnd, int x, int y) {
    if (g_dragging) {
        int dx = x - s_tapX;
        int dy = y - s_tapY;
        // Если сдвинулись больше допуска — отменяем тап
        if (!s_tapCancelled && (dx*dx + dy*dy) > TAP_SLOP*TAP_SLOP) {
            s_tapCancelled = TRUE;
            if (s_longPressTimerActive) {
                KillTimer(hWnd, ID_TIMER_LONGPRESS);
                s_longPressTimerActive = FALSE;
            }
        }
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
                } else if (g_addingDns) {
                    int len = wcslen(g_newDns);
                    if (len > 0) g_newDns[len - 1] = 0;
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
                } else if (g_addingDns) {
                    g_addingDns = FALSE;
                    ShowKeyboard(FALSE);
                    if (wcslen(g_newDns) > 0 && g_dnsCount < 8) {
                        wcscpy(g_dnsServers[g_dnsCount], g_newDns);
                        g_dnsCount++;
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
                } else if (g_addingDns) {
                    int len = wcslen(g_newDns);
                    if (len < 63) {
                        g_newDns[len] = ch;
                        g_newDns[len + 1] = 0;
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
