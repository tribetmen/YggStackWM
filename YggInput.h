#pragma once

#include <windows.h>
#include "scroll_arm4i.h"

// === Структура записи лога ===
typedef struct {
    WCHAR text[128];
    BYTE type;
    SYSTEMTIME time;
} LogEntry;

// === Глобальные переменные состояния устройства ===
extern BOOL g_isButtonPhone;
extern int g_focusIndex;
extern int g_maxFocusIndex;

// === Мультитап-ввод ===
extern int g_lastTapKey;
extern int g_tapIndex;
extern WCHAR g_tempChar;
extern DWORD g_tapTimer;

// Раскладка телефонной клавиатуры
extern const WCHAR* g_tapLayout[10];

// === Переменные тач-ввода ===
extern BOOL g_dragging;
extern int g_lastX, g_lastY;
extern BOOL g_longPressDetected;

// === Глобальные переменные состояния ===
extern HWND g_hWnd;
extern int g_currentTab;
extern BOOL g_addingPeer;
extern BOOL g_editingKey;
extern WCHAR g_newPeer[128];
extern WCHAR g_tempKey[256];
extern int g_peerCount;
extern WCHAR g_peersList[10][128];
extern ScrollState g_scroll;
extern BOOL g_serviceRunning;
extern BOOL g_connecting;
extern BOOL g_bManualMinimize;
extern int g_topPanelY;
extern int g_screenWidth;
extern int g_screenHeight;
extern BOOL g_showFullKey;
extern int g_selectedPeer;
extern BOOL g_hasHardwareKeyboard;
extern WCHAR g_privateKeyFull[128];
extern WCHAR g_privateKeyShort[64];
extern BOOL g_showSpinner;
extern int g_spinnerAngle;
extern WCHAR g_dnsServers[8][64];
extern int g_dnsCount;
extern WCHAR g_newDns[64];
extern BOOL g_addingDns;

// Буфер логов
#define LOG_BUFFER_SIZE 200
extern LogEntry g_logBuffer[LOG_BUFFER_SIZE];
extern int g_logHead;
extern int g_logTail;
extern int g_logCount;
extern BOOL g_logsEnabled;  // Включены ли логи

// === Прототипы функций для сенсорного ввода ===
void InitTouchInput();
BOOL HandleTouchMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// === Прототипы функций для кнопочного ввода ===
void InitButtonInput();
BOOL HandleButtonMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void FixMultitap();

// === Общие функции ===
extern void ShowKeyboard(BOOL bShow);
extern BOOL ActivateFocusedItem();
void DrawFocusIndicator(HDC hdc, RECT* rc);
void ToggleLogs();
void SaveLogsToFile();
void LoadLogsFromFile();
