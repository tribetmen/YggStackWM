// input_buttons.cpp - Обработка ввода для кнопочных телефонов
// Мультитап-ввод, навигация, софт-кнопки

#include "stdafx.h"
#include "YggInput.h"
#include "YggLog.h"
#include "YggdrasilCore.h"
#include "ygg_constants.h"
#include "scroll_arm4i.h"

#ifndef PS_DOT
#define PS_DOT 2
#endif

// Раскладка телефонной клавиатуры
const WCHAR* g_tapLayout[10] = {
    L"0",           // 0x30 - кнопка 0
    L"1./:-",       // 0x31 - кнопка 1
    L"2abc",        // 0x32 - кнопка 2
    L"3def",        // 0x33 - кнопка 3
    L"4ghi",        // 0x34 - кнопка 4
    L"5jkl",        // 0x35 - кнопка 5
    L"6mno",        // 0x36 - кнопка 6
    L"7pqrs",       // 0x37 - кнопка 7
    L"8tuv",        // 0x38 - кнопка 8
    L"9wxyz"        // 0x39 - кнопка 9
};

// === Внешние переменные из Yggstack.cpp ===
// Теперь объявлены в YggInput.h

// Таймеры
#define ID_TIMER_MULTITAP      1007

// Коды кнопок
#ifndef VK_TSOFT1
#define VK_TSOFT1 0xD2
#endif
#ifndef VK_TSOFT2
#define VK_TSOFT2 0xD3
#endif
#ifndef VK_TEND
#define VK_TEND 0xD5
#endif
#ifndef VK_THOME
#define VK_THOME 0xD6
#endif
#ifndef VK_TBACK
#define VK_TBACK 0xD9
#endif

// === Функции логирования ===
extern void AddLog(LPCWSTR text, BYTE type);
extern void OnStartService();

// === Инициализация ===
void InitButtonInput() {
    g_focusIndex = 0;
    g_lastTapKey = 0;
    g_tapIndex = 0;
    g_tempChar = 0;
    g_tapTimer = 0;
}

// === Фиксация мультитап-символа ===
void FixMultitap() {
    if (g_tempChar != 0) {
        g_lastTapKey = 0;
        g_tapIndex = 0;
        g_tempChar = 0;
    }
}

// === Обработка мультитап-клавиши ===
void HandleMultitapKey(HWND hWnd, int keyCode) {
    int keyIndex = keyCode - 0x30;  // 0-9
    if (keyIndex < 0 || keyIndex > 9) return;
    
    const WCHAR* chars = g_tapLayout[keyIndex];
    int charCount = wcslen(chars);
    
    // Если нажата та же кнопка - переключаемся на следующую букву
    if (keyCode == g_lastTapKey && g_tempChar != 0) {
        g_tapIndex = (g_tapIndex + 1) % charCount;
        g_tempChar = chars[g_tapIndex];
        
        // Заменяем последний символ в строке
        int len = wcslen(g_newPeer);
        if (len > 0) {
            g_newPeer[len - 1] = g_tempChar;
        }
    } else {
        // Новая кнопка
        FixMultitap();
        g_lastTapKey = keyCode;
        
        // Для кнопок 2-9 сразу берем первую букву (индекс 1), а не цифру (индекс 0)
        // Для кнопок 0 и 1 (только цифры и символы) берем первый символ
        if (keyIndex >= 2 && charCount > 1) {
            g_tapIndex = 1;  // Начинаем с буквы 'a', 'd', 'g' и т.д.
        } else {
            g_tapIndex = 0;  // Для 0 и 1 - первый символ
        }
        g_tempChar = chars[g_tapIndex];
        
        int len = wcslen(g_newPeer);
        if (len < 127) {
            g_newPeer[len] = g_tempChar;
            g_newPeer[len + 1] = 0;
        }
    }
    
    // Перезапускаем таймер (800 мс)
    if (g_tapTimer != 0) {
        KillTimer(hWnd, ID_TIMER_MULTITAP);
    }
    g_tapTimer = SetTimer(hWnd, ID_TIMER_MULTITAP, 800, NULL);
    
    InvalidateRect(hWnd, NULL, TRUE);
}

// === Таймаут мультитапа ===
void OnMultitapTimeout(HWND hWnd) {
    FixMultitap();
    KillTimer(hWnd, ID_TIMER_MULTITAP);
    g_tapTimer = 0;
}

// === Обработка WM_KEYDOWN ===
void HandleKeyDown(HWND hWnd, WPARAM wParam) {
    // === МУЛЬТИТАП-ВВОД ===
    if (g_addingPeer && wParam >= 0x30 && wParam <= 0x39) {
        HandleMultitapKey(hWnd, wParam);
        return;
    }
    
    // === Навигация джойстиком ===
    switch(wParam) {
        case VK_UP:
            if (g_focusIndex > 0) {
                g_focusIndex--;
                InvalidateRect(hWnd, NULL, FALSE);
            } else if (g_scroll.y > 0) {
                g_scroll.y = max(0, g_scroll.y - 30);
                InvalidateRect(hWnd, NULL, FALSE);
            }
            break;
            
        case VK_DOWN:
            if (g_focusIndex < g_maxFocusIndex) {
                g_focusIndex++;
                InvalidateRect(hWnd, NULL, FALSE);
            } else if (g_scroll.y < g_scroll.maxY) {
                g_scroll.y = min(g_scroll.maxY, g_scroll.y + 30);
                InvalidateRect(hWnd, NULL, FALSE);
            }
            break;
            
        case VK_LEFT:
            if (g_currentTab > 0) {
                g_currentTab--;
                g_focusIndex = 0;
                FixMultitap();
                g_addingPeer = FALSE;
                g_editingKey = FALSE;
                InvalidateRect(hWnd, NULL, TRUE);
            }
            break;
            
        case VK_RIGHT:
            if (g_currentTab < 2) {
                g_currentTab++;
                g_focusIndex = 0;
                FixMultitap();
                g_addingPeer = FALSE;
                g_editingKey = FALSE;
                InvalidateRect(hWnd, NULL, TRUE);
            }
            break;
    }
}

// === Обработка WM_KEYUP (для софт-кнопок) ===
void HandleKeyUp(HWND hWnd, WPARAM wParam) {
    switch(wParam) {
        // === Левая софт-клавиша (F1 = 0x70) ===
        case VK_F1:
            FixMultitap();
            if (g_addingPeer) {
                // В режиме добавления - сохраняем пир
                int len = wcslen(g_newPeer);
                if (len > 0 && g_peerCount < 10) {
                    wcscpy(g_peersList[g_peerCount], g_newPeer);
                    g_peerCount++;
                    AddLog(L"New peer added", LOG_SUCCESS);
                }
                g_addingPeer = FALSE;
                g_newPeer[0] = 0;
                InvalidateRect(hWnd, NULL, TRUE);
            } else if (!g_editingKey) {
                ActivateFocusedItem();
            }
            break;
            
        // === Правая софт-клавиша (F2 = 0x71) ===
        case VK_F2:
            FixMultitap();
            if (g_addingPeer || g_editingKey) {
                g_addingPeer = FALSE;
                g_editingKey = FALSE;
                g_newPeer[0] = 0;
                g_tempKey[0] = 0;
                AddLog(L"Cancelled", LOG_WARN);
                InvalidateRect(hWnd, NULL, TRUE);
            } else {
                g_bManualMinimize = TRUE;
                ShowWindow(hWnd, SW_HIDE);
                AddLog(L"Minimized (softkey)", LOG_INFO);
            }
            break;
            
        // === Enter ===
        case VK_RETURN:
            FixMultitap();
            if (g_addingPeer) {
                int len = wcslen(g_newPeer);
                if (len > 0 && g_peerCount < 10) {
                    wcscpy(g_peersList[g_peerCount], g_newPeer);
                    g_peerCount++;
                    AddLog(L"New peer added", LOG_SUCCESS);
                }
                g_addingPeer = FALSE;
                g_newPeer[0] = 0;
                InvalidateRect(hWnd, NULL, TRUE);
            } else {
                ActivateFocusedItem();
            }
            break;
            
        // === Back (Escape) ===
        case VK_BACK:
        case VK_ESCAPE:
            FixMultitap();
            if (g_addingPeer) {
                int len = wcslen(g_newPeer);
                if (len > 0) {
                    g_newPeer[len - 1] = 0;
                    InvalidateRect(hWnd, NULL, TRUE);
                } else {
                    g_addingPeer = FALSE;
                    AddLog(L"Cancelled (Back)", LOG_WARN);
                    InvalidateRect(hWnd, NULL, TRUE);
                }
            } else {
                g_bManualMinimize = TRUE;
                ShowWindow(hWnd, SW_HIDE);
                AddLog(L"Minimized (back)", LOG_INFO);
            }
            break;
            
        // === Красная кнопка (End) ===
        case VK_TEND:
            FixMultitap();
            if (g_addingPeer || g_editingKey) {
                g_addingPeer = FALSE;
                g_editingKey = FALSE;
                g_newPeer[0] = 0;
                g_tempKey[0] = 0;
                InvalidateRect(hWnd, NULL, TRUE);
            } else {
                g_bManualMinimize = TRUE;
                ShowWindow(hWnd, SW_HIDE);
                AddLog(L"Minimized (end)", LOG_INFO);
            }
            break;
            
        // === Home ===
        case VK_THOME:
            FixMultitap();
            g_bManualMinimize = TRUE;
            ShowWindow(hWnd, SW_HIDE);
            AddLog(L"Minimized (home)", LOG_INFO);
            break;
    }
}

// === Главная функция обработки сообщений ===
BOOL HandleButtonMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_KEYDOWN:
            // В режиме мультитапа для клавиш 0-9 не передаем в DefWindowProc
            // (чтобы не генерировался WM_CHAR с цифрой)
            if (g_addingPeer && wParam >= 0x30 && wParam <= 0x39) {
                HandleKeyDown(hWnd, wParam);
                return TRUE;
            }
            HandleKeyDown(hWnd, wParam);
            return TRUE;
            
        case WM_KEYUP:
            HandleKeyUp(hWnd, wParam);
            return TRUE;
            
        case WM_CHAR:
            // В режиме мультитапа поглощаем ВСЕ символы - ввод через WM_KEYDOWN
            if (g_addingPeer) {
                // Всегда возвращаем TRUE чтобы блокировать стандартную обработку
                return TRUE;
            }
            break;
            
        case WM_TIMER:
            if (wParam == ID_TIMER_MULTITAP) {
                OnMultitapTimeout(hWnd);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

// === Отрисовка индикатора фокуса ===
void DrawFocusIndicator(HDC hdc, RECT* rc) {
    HPEN hPen = CreatePen(PS_DOT, 3, RGB(255, 0, 0));
    HGDIOBJ oldPen = SelectObject(hdc, hPen);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
    
    Rectangle(hdc, rc->left + 2, rc->top + 2, rc->right - 2, rc->bottom - 2);
    
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBrush);
    DeleteObject(hPen);
}

// === Активация элемента в фокусе ===
BOOL ActivateFocusedItem() {
    BOOL needRedraw = TRUE;
    
    if (g_currentTab == 0) { // Config
        switch(g_focusIndex) {
            case 0: // Start/Stop
                OnStartService();
                break;
            case 1: // Toggle key view
                // g_showFullKey = !g_showFullKey;
                break;
            case 2: // Add peer
                g_addingPeer = TRUE;  // Включаем режим добавления
                // Явная инициализация tcp://
                g_newPeer[0] = L't';
                g_newPeer[1] = L'c';
                g_newPeer[2] = L'p';
                g_newPeer[3] = L':';
                g_newPeer[4] = L'/';
                g_newPeer[5] = L'/';
                g_newPeer[6] = 0;
                g_focusIndex = 0;  // Сбрасываем фокус для ввода
                if (g_logsEnabled) AddLog(L"Enter peer address", LOG_INFO);
                break;
            default: 
                if (g_focusIndex >= 3 && g_focusIndex < (3 + g_peerCount)) {
                    // Удаление пиров
                    int peerIdx = g_focusIndex - 3;
                    if (peerIdx >= 0 && peerIdx < g_peerCount) {
                        for(int j = peerIdx; j < g_peerCount - 1; j++) {
                            wcscpy(g_peersList[j], g_peersList[j + 1]);
                        }
                        g_peerCount--;
                        AddLog(L"Peer removed", LOG_WARN);
                    }
                } else if (g_focusIndex == (3 + g_peerCount)) {
                    // HTTP Proxy кнопка
                    extern void OnToggleHttpProxy();
                    OnToggleHttpProxy();
                }
                break;
        }
    } else if (g_currentTab == 1) { // Logs
        if (g_focusIndex == 0) { // On/Off
            ToggleLogs();
        } else if (g_focusIndex == 1) { // Clear
            extern int g_logHead, g_logTail, g_logCount;
            extern LogEntry g_logBuffer[];
            g_logHead = 0;
            g_logTail = 0;
            g_logCount = 0;
            memset(g_logBuffer, 0, sizeof(LogEntry) * 200);
            if (g_logsEnabled) AddLog(L"Log cleared", LOG_INFO);
        }
    }
    
    if (needRedraw && g_hWnd) {
        InvalidateRect(g_hWnd, NULL, TRUE);
    }
    return TRUE;
}
