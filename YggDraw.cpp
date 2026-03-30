// YggDraw.cpp - Отрисовка интерфейса

#include "stdafx.h"
#include "YggDraw.h"
#include "YggLog.h"
#include "YggInput.h"
#include "YggdrasilCore.h"

// Цвета
#define COLOR_INFO      RGB(0, 0, 180)
#define COLOR_WARN      RGB(180, 100, 0)
#define COLOR_ERROR     RGB(200, 0, 0)
#define COLOR_DEBUG     RGB(100, 100, 100)
#define COLOR_SUCCESS   RGB(0, 140, 0)
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
#define MY_COLOR_FOCUS       RGB(255, 0, 0)

// Внешние переменные объявлены в YggInput.h
// Дополнительные переменные только для этого модуля:
extern int g_totalHeight;
extern WCHAR g_currentIP[50];

// Буфер отрисовки
HBITMAP g_hBackBuffer = NULL;
HDC g_hBackDC = NULL;
int g_backBufferWidth = 0;
int g_backBufferHeight = 0;

void CreateBackBuffer(HDC hdc, int width, int height) {
    if (g_hBackBuffer != NULL) {
        DeleteObject(g_hBackBuffer);
        DeleteDC(g_hBackDC);
    }
    g_hBackDC = CreateCompatibleDC(hdc);
    g_hBackBuffer = CreateCompatibleBitmap(hdc, width, height);
    g_backBufferWidth = width;
    g_backBufferHeight = height;
    SelectObject(g_hBackDC, g_hBackBuffer);
}

void DrawFrameRect(HDC hdc, RECT* rc, COLORREF color) {
    HPEN hPen = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ oldPen = SelectObject(hdc, hPen);
    HGDIOBJ oldBrush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Rectangle(hdc, rc->left, rc->top, rc->right, rc->bottom);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBrush);
    DeleteObject(hPen);
}

COLORREF GetLogColor(BYTE type) {
    switch(type) {
        case LOG_INFO: return COLOR_INFO;
        case LOG_WARN: return COLOR_WARN;
        case LOG_ERROR: return COLOR_ERROR;
        case LOG_DEBUG: return COLOR_DEBUG;
        case LOG_SUCCESS: return COLOR_SUCCESS;
        default: return MY_COLOR_TEXT;
    }
}

void DrawTopPanel(HDC hdc, int width) {
    if (!g_isButtonPhone) {
        RECT rcTop = {0, g_topPanelY, width, g_topPanelY + 40};
        HBRUSH topBrush = CreateSolidBrush(MY_COLOR_PRIMARY);
        FillRect(hdc, &rcTop, topBrush);
        DeleteObject(topBrush);
        
        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkMode(hdc, TRANSPARENT);
        
        WCHAR statusText[64];
        wsprintf(statusText, L"Service: %s", 
                 g_serviceRunning ? L"Running" : (g_connecting ? L"Connecting..." : L"Stopped"));
        SetTextColor(hdc, g_serviceRunning ? MY_COLOR_SUCCESS : 
                          (g_connecting ? MY_COLOR_WARNING : RGB(255, 200, 200)));
        RECT rcStatus = {10, g_topPanelY + 5, width - 10, g_topPanelY + 25};
        DrawText(hdc, statusText, -1, &rcStatus, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    } else {
        // Компактный статус-бар для кнопочных
        RECT rcTop = {0, 0, width, 20};
        HBRUSH topBrush = CreateSolidBrush(MY_COLOR_PRIMARY_DARK);
        FillRect(hdc, &rcTop, topBrush);
        DeleteObject(topBrush);
        
        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkMode(hdc, TRANSPARENT);
        
        WCHAR statusText[64];
        wsprintf(statusText, L"%s", 
                 g_serviceRunning ? L"Running" : (g_connecting ? L"Connecting..." : L"Stopped"));
        RECT rcStatus = {5, 2, width - 5, 18};
        DrawText(hdc, statusText, -1, &rcStatus, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
}

void DrawBottomPanel(HDC hdc, int width, int height) {
    int panelHeight = g_isButtonPhone ? 30 : ((height >= 640) ? 55 : ((height >= 480) ? 50 : 45));
    int y = height - panelHeight + 5;
    
    if (g_isButtonPhone) {
        // Компактная панель для кнопочных
        RECT rcPanel = {0, height - panelHeight, width, height};
        HBRUSH panelBrush = CreateSolidBrush(MY_COLOR_PRIMARY_DARK);
        FillRect(hdc, &rcPanel, panelBrush);
        DeleteObject(panelBrush);
        
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(100, 100, 100));
        HGDIOBJ oldPen = SelectObject(hdc, pen);
        MoveToEx(hdc, 0, height - panelHeight, NULL);
        LineTo(hdc, width, height - panelHeight);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
        
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        
        // Левая софт-клавиша
        RECT rcLeftSoft = {5, y, width / 3, y + panelHeight - 4};
        LPCWSTR leftLabel = L"[OK]";
        if (g_addingPeer || g_editingKey) leftLabel = L"[Save]";
        else if (g_currentTab == 0 && g_focusIndex == 0) 
            leftLabel = g_serviceRunning ? L"[Stop]" : L"[Start]";
        DrawText(hdc, leftLabel, -1, &rcLeftSoft, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        
        // Центр - название вкладки
        RECT rcCenter = {width / 3, y, width * 2 / 3, y + panelHeight - 4};
        LPCWSTR tabName = (g_currentTab == 0) ? L"CONFIG" : 
                         (g_currentTab == 1) ? L"LOGS" : L"INFO";
        DrawText(hdc, tabName, -1, &rcCenter, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        // Правая софт-клавиша
        RECT rcRightSoft = {width * 2 / 3, y, width - 5, y + panelHeight - 4};
        LPCWSTR rightLabel = (g_addingPeer || g_editingKey) ? L"[Cancel]" : L"[Back]";
        DrawText(hdc, rightLabel, -1, &rcRightSoft, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        
        return;
    }
    
    // Сенсорная панель
    RECT rcPanel = {0, height - panelHeight, width, height};
    HBRUSH panelBrush = CreateSolidBrush(MY_COLOR_CARD);
    FillRect(hdc, &rcPanel, panelBrush);
    DeleteObject(panelBrush);
    
    HPEN pen = CreatePen(PS_SOLID, 1, MY_COLOR_BORDER);
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    MoveToEx(hdc, 0, height - panelHeight, NULL);
    LineTo(hdc, width, height - panelHeight);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);
    
    int margin = (width >= 640) ? 10 : ((width >= 480) ? 8 : 5);
    int btnWidth = (width - (margin * 4)) / 3;
    int btnHeight = panelHeight - 10;
    
    COLORREF bgColors[3] = {MY_COLOR_CARD, MY_COLOR_CARD, MY_COLOR_CARD};
    COLORREF textColors[3] = {MY_COLOR_TEXT, MY_COLOR_TEXT, MY_COLOR_TEXT};
    bgColors[g_currentTab] = MY_COLOR_PRIMARY;
    textColors[g_currentTab] = RGB(255, 255, 255);
    
    for (int i = 0; i < 3; i++) {
        RECT rcBtn = {margin * (i + 1) + btnWidth * i, y, 
                      margin * (i + 1) + btnWidth * (i + 1), y + btnHeight};
        HBRUSH brush = CreateSolidBrush(bgColors[i]);
        FillRect(hdc, &rcBtn, brush);
        DeleteObject(brush);
        SetTextColor(hdc, textColors[i]);
        LPCWSTR label = (i == 0) ? L"Conf" : (i == 1) ? L"Logs" : L"Info";
        DrawText(hdc, label, -1, &rcBtn, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

void DrawConfigTab(HDC hdc, int width, int height, int scrollY) {
    int margin = (width >= 640) ? 30 : ((width >= 480) ? 20 : 5);
    int sectionHeight = g_isButtonPhone ? 35 : ((height >= 640) ? 30 : 25);
    int keyFieldHeight = (width >= 640) ? 70 : ((width >= 480) ? 65 : 55);
    int peerItemHeight = g_isButtonPhone ? 28 : ((height >= 640) ? 26 : 22);
    
    int y = g_isButtonPhone ? (g_topPanelY + 22) : (g_topPanelY + 50);
    int btnY = g_isButtonPhone ? (height - 65) : (height - 80);
    int clipBottom = g_isButtonPhone ? (height - 30) : (height - 45);
    int clipTop = g_isButtonPhone ? 20 : (g_topPanelY + 40);
    
    HRGN hClipRgn = CreateRectRgn(0, clipTop, width, clipBottom);
    SelectClipRgn(hdc, hClipRgn);
    
    // Private Key секция
    RECT rcSection = {margin, y - scrollY, width - margin, y - scrollY + sectionHeight};
    HBRUSH sectionBrush = CreateSolidBrush(MY_COLOR_HIGHLIGHT);
    FillRect(hdc, &rcSection, sectionBrush);
    DeleteObject(sectionBrush);
    
    SetTextColor(hdc, MY_COLOR_PRIMARY_DARK);
    RECT rcText = {margin + 5, y - scrollY, width - margin - 5, y - scrollY + sectionHeight};
    DrawText(hdc, g_isButtonPhone ? L"Private Key" : L"Private Key (tap to edit)", 
             -1, &rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    y += sectionHeight;
    
    // Поле ключа
    RECT rcKey = {margin, y - scrollY, width - margin - 30, y - scrollY + keyFieldHeight};
    HBRUSH keyBrush = CreateSolidBrush(MY_COLOR_CARD);
    FillRect(hdc, &rcKey, keyBrush);
    DeleteObject(keyBrush);
    DrawFrameRect(hdc, &rcKey, g_editingKey ? RGB(0, 120, 215) : MY_COLOR_BORDER);
    
    if (g_isButtonPhone && g_focusIndex == 1 && g_currentTab == 0) {
        DrawFocusIndicator(hdc, &rcKey);
    }
    
    // Кнопка просмотра
    RECT rcViewBtn = {width - margin - 25, y - scrollY, width - margin, y - scrollY + 25};
    HBRUSH viewBrush = CreateSolidBrush(g_showFullKey ? MY_COLOR_PRIMARY : RGB(240, 240, 240));
    FillRect(hdc, &rcViewBtn, viewBrush);
    DeleteObject(viewBrush);
    DrawFrameRect(hdc, &rcViewBtn, MY_COLOR_BORDER);
    SetTextColor(hdc, g_showFullKey ? RGB(255, 255, 255) : MY_COLOR_PRIMARY);
    DrawText(hdc, L"...", -1, &rcViewBtn, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    
    // Текст ключа
    SetTextColor(hdc, MY_COLOR_TEXT);
    RECT rcKeyText = {margin + 5, y - scrollY + 2, width - margin - 35, y - scrollY + keyFieldHeight - 2};
    
    if (g_editingKey) {
        WCHAR displayKey[256];
        wsprintf(displayKey, L"%s_", g_tempKey);
        DrawText(hdc, displayKey, -1, &rcKeyText, DT_LEFT | DT_WORDBREAK);
        
        // Подсказка
        RECT rcHint = {margin + 5, y - scrollY + keyFieldHeight + 2, width - margin - 5, y - scrollY + keyFieldHeight + 20};
        SetTextColor(hdc, RGB(0, 100, 200));
        DrawText(hdc, L"Type new key, press Enter to save", -1, &rcHint, DT_LEFT | DT_TOP | DT_SINGLELINE);
        
        y += keyFieldHeight + 25;
    } else {
        if (g_showFullKey) {
            WCHAR line1[65], line2[65];
            wcsncpy(line1, g_privateKeyFull, 32); line1[32] = 0;
            wcsncpy(line2, g_privateKeyFull + 32, 32); line2[32] = 0;
            RECT rcLine1 = {margin + 5, y - scrollY + 2, width - margin - 35, y - scrollY + 22};
            DrawText(hdc, line1, -1, &rcLine1, DT_LEFT | DT_TOP | DT_SINGLELINE);
            RECT rcLine2 = {margin + 5, y - scrollY + 22, width - margin - 35, y - scrollY + 42};
            DrawText(hdc, line2, -1, &rcLine2, DT_LEFT | DT_TOP | DT_SINGLELINE);
        } else {
            DrawText(hdc, g_privateKeyShort, -1, &rcKeyText, DT_LEFT | DT_WORDBREAK);
        }
        y += keyFieldHeight + 10;
    }
    
    // Peers секция
    RECT rcPeers = {margin, y - scrollY, width - margin, y - scrollY + sectionHeight};
    sectionBrush = CreateSolidBrush(MY_COLOR_HIGHLIGHT);
    FillRect(hdc, &rcPeers, sectionBrush);
    DeleteObject(sectionBrush);
    
    SetTextColor(hdc, MY_COLOR_PRIMARY_DARK);
    RECT rcPeersText = {margin + 5, y - scrollY, width - margin - 35, y - scrollY + sectionHeight};
    DrawText(hdc, L"Peers", -1, &rcPeersText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    
    RECT rcAddPeer = {width - margin - 25, y - scrollY, width - margin, y - scrollY + 22};
    HBRUSH addBrush = CreateSolidBrush(g_addingPeer ? MY_COLOR_SUCCESS : RGB(220, 220, 220));
    FillRect(hdc, &rcAddPeer, addBrush);
    DeleteObject(addBrush);
    DrawFrameRect(hdc, &rcAddPeer, MY_COLOR_BORDER);
    
    if (g_isButtonPhone && g_focusIndex == 2 && g_currentTab == 0) {
        DrawFocusIndicator(hdc, &rcAddPeer);
    }
    
    SetTextColor(hdc, MY_COLOR_TEXT);
    DrawText(hdc, L"+", -1, &rcAddPeer, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    y += sectionHeight;
    
    // Поле ввода нового пира
    if (g_addingPeer) {
        RECT rcNewPeer = {margin, y - scrollY, width - margin, y - scrollY + 25};
        HBRUSH peerBrush = CreateSolidBrush(MY_COLOR_CARD);
        FillRect(hdc, &rcNewPeer, peerBrush);
        DeleteObject(peerBrush);
        DrawFrameRect(hdc, &rcNewPeer, MY_COLOR_SUCCESS);
        
        WCHAR displayPeer[128];
        wsprintf(displayPeer, L"%s_", g_newPeer);
        SetTextColor(hdc, MY_COLOR_TEXT);
        RECT rcPeerText = {margin + 5, y - scrollY, width - margin - 5, y - scrollY + 20};
        DrawText(hdc, displayPeer, -1, &rcPeerText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        
        // Подсказка
        RECT rcHint = {margin + 5, y - scrollY + 27, width - margin - 5, y - scrollY + 45};
        SetTextColor(hdc, RGB(0, 100, 0));
        DrawText(hdc, L"Type address, Enter to add", -1, &rcHint, DT_LEFT | DT_TOP);
        
        y += 55;
    }
    
    // Список пиров
    for (int i = 0; i < g_peerCount; i++) {
        BOOL isSelected = (i == g_selectedPeer);
        RECT rcPeer = {margin, y - scrollY, width - margin - 25, y - scrollY + peerItemHeight};
        
        if (isSelected) {
            HBRUSH selBrush = CreateSolidBrush(MY_COLOR_HIGHLIGHT);
            RECT rcSel = {margin - 5, y - scrollY - 1, width - margin - 20, y - scrollY + peerItemHeight - 1};
            FillRect(hdc, &rcSel, selBrush);
            DeleteObject(selBrush);
        }
        
        SetTextColor(hdc, isSelected ? MY_COLOR_PRIMARY_DARK : MY_COLOR_TEXT);
        RECT rcPeerText = {margin + 5, y - scrollY, width - margin - 35, y - scrollY + peerItemHeight};
        DrawText(hdc, g_peersList[i], -1, &rcPeerText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        
        RECT rcDelete = {width - margin - 20, y - scrollY, width - margin - 5, y - scrollY + 18};
        HBRUSH delBrush = CreateSolidBrush(RGB(255, 200, 200));
        FillRect(hdc, &rcDelete, delBrush);
        DeleteObject(delBrush);
        DrawFrameRect(hdc, &rcDelete, RGB(200, 0, 0));
        
        if (g_isButtonPhone && g_focusIndex == (3 + i) && g_currentTab == 0) {
            DrawFocusIndicator(hdc, &rcDelete);
        }
        
        SetTextColor(hdc, RGB(200, 0, 0));
        DrawText(hdc, L"X", -1, &rcDelete, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        y += peerItemHeight;
    }
    
    // Обновляем максимальный индекс фокуса (+1 для HTTP Proxy кнопки)
    if (g_currentTab == 0) {
        extern int g_maxFocusIndex;
        g_maxFocusIndex = 3 + g_peerCount;
    } else if (g_currentTab == 1) {
        extern int g_maxFocusIndex;
        g_maxFocusIndex = 1; // On/Off и Clear
    }
    
    // HTTP Proxy кнопка (для Opera)
    RECT rcHttpProxyBtn = {margin, y - scrollY, width - margin, y - scrollY + 25};
    extern BOOL g_httpProxyRunning;
    extern HANDLE g_hHttpProxyThread;
    HBRUSH httpBrush = CreateSolidBrush(g_httpProxyRunning ? RGB(40, 200, 100) : RGB(255, 255, 255));
    FillRect(hdc, &rcHttpProxyBtn, httpBrush);
    DeleteObject(httpBrush);
    
    // Рамка фокуса для кнопочных телефонов (рисуем поверх)
    if (g_isButtonPhone && g_focusIndex == (3 + g_peerCount) && g_currentTab == 0) {
        HPEN hPen = CreatePen(PS_SOLID, 3, RGB(255, 0, 0));
        HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, rcHttpProxyBtn.left - 2, rcHttpProxyBtn.top - 2, 
                       rcHttpProxyBtn.right + 2, rcHttpProxyBtn.bottom + 2);
        SelectObject(hdc, hOldPen);
        SelectObject(hdc, hOldBrush);
        DeleteObject(hPen);
    }
    
    DrawFrameRect(hdc, &rcHttpProxyBtn, g_httpProxyRunning ? RGB(0, 150, 0) : RGB(200, 200, 200));
    
    SetTextColor(hdc, g_httpProxyRunning ? RGB(255, 255, 255) : RGB(30, 30, 30));
    WCHAR httpText[64];
    wsprintf(httpText, L"HTTP Proxy: %s", g_httpProxyRunning ? L"ON (127.0.0.1:8080)" : L"OFF");
    DrawText(hdc, httpText, -1, &rcHttpProxyBtn, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    y += 30;
    
    // IP секция
    RECT rcIPSection = {margin, y - scrollY, width - margin, y - scrollY + sectionHeight};
    sectionBrush = CreateSolidBrush(MY_COLOR_HIGHLIGHT);
    FillRect(hdc, &rcIPSection, sectionBrush);
    DeleteObject(sectionBrush);
    
    SetTextColor(hdc, MY_COLOR_PRIMARY_DARK);
    RECT rcIPSectionText = {margin + 5, y - scrollY, width - margin - 5, y - scrollY + sectionHeight};
    DrawText(hdc, L"Your Yggdrasil IP", -1, &rcIPSectionText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    y += sectionHeight;
    
    RECT rcIP = {margin, y - scrollY, width - margin, y - scrollY + 50};
    HBRUSH ipBrush = CreateSolidBrush(MY_COLOR_CARD);
    FillRect(hdc, &rcIP, ipBrush);
    DeleteObject(ipBrush);
    DrawFrameRect(hdc, &rcIP, g_serviceRunning ? MY_COLOR_SUCCESS : MY_COLOR_BORDER);
    
    SetTextColor(hdc, g_serviceRunning ? MY_COLOR_SUCCESS : MY_COLOR_WARNING);
    
    if (g_serviceRunning) {
        // Разбиваем IP на две строки
        WCHAR ipPart1[24] = L"";
        WCHAR ipPart2[24] = L"";
        int ipLen = wcslen(g_currentIP);
        
        int colonCount = 0;
        int splitPos = ipLen / 2;
        for (int i = 0; i < ipLen; i++) {
            if (g_currentIP[i] == L':') {
                colonCount++;
                if (colonCount == 4) {
                    splitPos = i;
                    break;
                }
            }
        }
        
        wcsncpy(ipPart1, g_currentIP, splitPos);
        ipPart1[splitPos] = 0;
        if (splitPos < ipLen - 1) {
            wcscpy(ipPart2, g_currentIP + splitPos + 1);
        }
        
        RECT rcIP1 = {margin + 5, y - scrollY + 2, width - margin - 5, y - scrollY + 25};
        DrawText(hdc, ipPart1, -1, &rcIP1, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        
        RECT rcIP2 = {margin + 5, y - scrollY + 25, width - margin - 5, y - scrollY + 48};
        DrawText(hdc, ipPart2, -1, &rcIP2, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    } else {
        DrawText(hdc, L"Not connected", -1, &rcIP, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
    y += 55;
    
    SelectClipRgn(hdc, NULL);
    DeleteObject(hClipRgn);
    
    // Спиннер и кнопка Start/Stop
    if (g_showSpinner && g_connecting) {
        int barY = btnY - 15;
        int barWidth = width - 60;
        int barX = 30;
        int barHeight = 8;
        
        RECT rcBarBg = {barX, barY, barX + barWidth, barY + barHeight};
        HBRUSH barBgBrush = CreateSolidBrush(RGB(220, 220, 220));
        FillRect(hdc, &rcBarBg, barBgBrush);
        DeleteObject(barBgBrush);
        
        int blockWidth = barWidth / 5;
        int blockPos = (g_spinnerAngle * (barWidth - blockWidth)) / 360;
        
        RECT rcBarFill = {barX + blockPos, barY, barX + blockPos + blockWidth, barY + barHeight};
        HBRUSH barFillBrush = CreateSolidBrush(MY_COLOR_PRIMARY);
        FillRect(hdc, &rcBarFill, barFillBrush);
        DeleteObject(barFillBrush);
    }
    
    RECT rcButton = {20, btnY, width - 20, btnY + 35};
    COLORREF btnColor = g_serviceRunning ? MY_COLOR_SUCCESS :
        (g_connecting ? RGB(255, 170, 0) : MY_COLOR_PRIMARY);
    HBRUSH btnBrush = CreateSolidBrush(btnColor);
    FillRect(hdc, &rcButton, btnBrush);
    DeleteObject(btnBrush);
    DrawFrameRect(hdc, &rcButton, MY_COLOR_PRIMARY_DARK);
    
    if (g_isButtonPhone && g_focusIndex == 0 && g_currentTab == 0) {
        DrawFocusIndicator(hdc, &rcButton);
    }
    
    SetTextColor(hdc, RGB(255, 255, 255));
    LPCWSTR btnText = g_serviceRunning ? L"Stop Service" :
        (g_connecting ? L"Connecting..." : L"Start Service");
    DrawText(hdc, btnText, -1, &rcButton, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    
    g_totalHeight = y + 20;
    int visibleHeight = g_isButtonPhone ? (height - 50) : (height - (g_topPanelY + 40 + 45));
    int maxScroll = max(0, g_totalHeight - visibleHeight);
    Scroll_SetBounds(&g_scroll, 0, 0, 0, maxScroll);
}

void DrawLogsTab(HDC hdc, int width, int height, int scrollY) {
    // Устанавливаем максимальный индекс фокуса для кнопочных телефонов
    if (g_isButtonPhone) {
        extern int g_maxFocusIndex;
        g_maxFocusIndex = 1; // On/Off (0) и Clear (1)
    }
    
    int lineHeight = (height >= 640) ? 34 : ((height >= 480) ? 28 : ((height <= 240) ? 16 : 20));
    int panelHeight = (height >= 640) ? 55 : ((height >= 480) ? 50 : 45);
    int margin = (width >= 640) ? 15 : ((width >= 480) ? 12 : 8);
    int btnHeight = (height >= 640) ? 32 : 25;
    
    int panelY = g_isButtonPhone ? (g_topPanelY + 22) : (g_topPanelY + 45);
    int panelBottom = panelY + btnHeight + 5;
    
    // Кнопка On/Off (левее Clear)
    RECT rcToggle = {width - margin - 120, panelY, width - margin - 65, panelY + btnHeight};
    extern BOOL g_logsEnabled;
    HBRUSH toggleBrush = CreateSolidBrush(g_logsEnabled ? RGB(200, 255, 200) : RGB(255, 200, 200));
    FillRect(hdc, &rcToggle, toggleBrush);
    DeleteObject(toggleBrush);
    DrawFrameRect(hdc, &rcToggle, MY_COLOR_BORDER);
    SetTextColor(hdc, MY_COLOR_TEXT);
    DrawText(hdc, g_logsEnabled ? L"On" : L"Off", -1, &rcToggle, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    
    // Кнопка Clear
    RECT rcClear = {width - margin - 60, panelY, width - margin, panelY + btnHeight};
    HBRUSH clearBrush = CreateSolidBrush(RGB(240, 240, 240));
    FillRect(hdc, &rcClear, clearBrush);
    DeleteObject(clearBrush);
    DrawFrameRect(hdc, &rcClear, MY_COLOR_BORDER);
    SetTextColor(hdc, MY_COLOR_TEXT);
    DrawText(hdc, L"Clear", -1, &rcClear, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    
    // Индикатор фокуса для кнопочных телефонов
    if (g_isButtonPhone && g_currentTab == 1) {
        if (g_focusIndex == 0) {
            DrawFocusIndicator(hdc, &rcToggle);  // On/Off
        } else if (g_focusIndex == 1) {
            DrawFocusIndicator(hdc, &rcClear);   // Clear
        }
    }
    
    WCHAR stats[64];
    wsprintf(stats, L"Log entries: %d", g_logCount);
    RECT rcStats = {margin, panelY, width - margin - 70, panelY + btnHeight};
    SetTextColor(hdc, MY_COLOR_TEXT_LIGHT);
    DrawText(hdc, stats, -1, &rcStats, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    
    HPEN pen = CreatePen(PS_SOLID, 1, MY_COLOR_BORDER);
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    MoveToEx(hdc, margin, panelBottom, NULL);
    LineTo(hdc, width - margin, panelBottom);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);
    
    int clipBottom = g_isButtonPhone ? (height - 30) : (height - panelHeight);
    HRGN hClipRgn = CreateRectRgn(0, panelBottom + 5, width, clipBottom);
    SelectClipRgn(hdc, hClipRgn);
    
    int y = panelBottom + 10;
    int index = g_logTail;
    for (int i = 0; i < g_logCount; i++) {
        LogEntry* entry = &g_logBuffer[index];
        if (entry->text[0] == 0) {
            index = (index + 1) % LOG_BUFFER_SIZE;
            continue;
        }
        
        WCHAR timeStr[16];
        wsprintf(timeStr, L"[%02d:%02d:%02d]", 
                 entry->time.wHour, entry->time.wMinute, entry->time.wSecond);
        WCHAR line[256];
        wsprintf(line, L"%s %s", timeStr, entry->text);
        int itemY = y - scrollY;
        
        SetTextColor(hdc, GetLogColor(entry->type));
        RECT rcText = {margin + 5, itemY + 2, width - margin - 5, itemY + lineHeight - 2};
        DrawText(hdc, line, -1, &rcText, DT_LEFT | DT_TOP | DT_SINGLELINE);
        y += lineHeight;
        index = (index + 1) % LOG_BUFFER_SIZE;
    }
    
    SelectClipRgn(hdc, NULL);
    DeleteObject(hClipRgn);
    
    g_totalHeight = y + 20;
    int visibleHeight = height - (panelBottom + 15 + panelHeight);
    int maxScroll = max(0, g_totalHeight - visibleHeight);
    Scroll_SetBounds(&g_scroll, 0, 0, 0, maxScroll);
}

void DrawInfoTab(HDC hdc, int width, int height, int scrollY) {
    int margin = (width >= 640) ? 15 : ((width >= 480) ? 12 : 8);
    int panelHeight = (height >= 640) ? 55 : ((height >= 480) ? 50 : 45);
    int itemHeight = (height >= 640) ? 32 : ((height <= 240) ? 18 : 22);
    
    int clipBottom = g_isButtonPhone ? (height - 30) : (height - panelHeight);
    int clipTop = g_isButtonPhone ? 22 : (g_topPanelY + 40);
    
    HRGN hClipRgn = CreateRectRgn(0, clipTop, width, clipBottom);
    SelectClipRgn(hdc, hClipRgn);
    
    int y = g_isButtonPhone ? (g_topPanelY + 22) : (g_topPanelY + 50);
    
    LPCWSTR infoItems[] = {
        L"About Yggstack",
        L"  Version 1.1",
        L"  for Windows Mobile 5/6",
        L"  Build: 2026.03.28",
        L"",
        L"Yggdrasil Network",
        L"  IPv6 mesh networking",
        L"  Ironwood protocol",
        L"  End-to-end encryption",
        L"",
        L"Proxy",
        L"  HTTP proxy: 127.0.0.1:8080",
        L"  for Opera",
        L"",
        L"Features",
        L"  + Fast crypto (afternm)",
        L"  + Session reuse",
        L"  + Pre-generated keys",
        L"  + Smooth scrolling",
        L"  + Hardware keyboard",
        L"  + Touch support",
        L"",
        L"Links",
        L"  yggdrasil-network.github.io",
        L"  github.com/tribetmen",
        L"",
        L"(c) 2026 tribetmen"
    };
    int itemCount = sizeof(infoItems) / sizeof(infoItems[0]);
    
    for (int i = 0; i < itemCount; i++) {
        int itemY = y - scrollY;
        
        if (wcslen(infoItems[i]) > 0 && infoItems[i][0] != L' ') {
            HBRUSH sectionBrush = CreateSolidBrush(MY_COLOR_HIGHLIGHT);
            RECT rcSection = {0, itemY, width, itemY + itemHeight};
            FillRect(hdc, &rcSection, sectionBrush);
            DeleteObject(sectionBrush);
            SetTextColor(hdc, MY_COLOR_PRIMARY_DARK);
        } else {
            SetTextColor(hdc, MY_COLOR_TEXT);
        }
        
        RECT rcItem = {margin, itemY + 2, width - margin, itemY + itemHeight - 2};
        DrawText(hdc, infoItems[i], -1, &rcItem, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += itemHeight;
    }
    
    SelectClipRgn(hdc, NULL);
    DeleteObject(hClipRgn);
    
    g_totalHeight = y + 20 - (g_isButtonPhone ? 22 : (g_topPanelY + 50));
    int visibleHeight = g_isButtonPhone ? (height - 52) : (height - (g_topPanelY + 40 + panelHeight));
    int maxScroll = max(0, g_totalHeight - visibleHeight);
    Scroll_SetBounds(&g_scroll, 0, 0, 0, maxScroll);
}

void DrawInterface(HDC hdc, int width, int height) {
    HBRUSH whiteBrush = CreateSolidBrush(MY_COLOR_BG);
    RECT rcClient = {0, 0, width, height};
    FillRect(hdc, &rcClient, whiteBrush);
    DeleteObject(whiteBrush);
    
    DrawTopPanel(hdc, width);
    
    int scrollY = g_scroll.y;
    
    switch(g_currentTab) {
        case 0: DrawConfigTab(hdc, width, height, scrollY); break;
        case 1: DrawLogsTab(hdc, width, height, scrollY); break;
        case 2: DrawInfoTab(hdc, width, height, scrollY); break;
    }
    
    DrawBottomPanel(hdc, width, height);
}
