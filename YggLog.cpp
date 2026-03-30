// YggLog.cpp - Работа с логом

#include "stdafx.h"
#include "YggInput.h"
#include "YggLog.h"

// Внешние переменные
extern HWND g_hWnd;
extern int g_currentTab;

// Файл для записи логов
FILE* g_logFile = NULL;

// Флаг включения логов (по умолчанию ОТКЛЮЧЕНЫ)
BOOL g_logsEnabled = FALSE;

void InitLogSystem() {
    g_logHead = 0;
    g_logTail = 0;
    g_logCount = 0;
    g_logFile = NULL;
    
    WCHAR path[MAX_PATH];
    wsprintf(path, L"\\Storage Card\\yggdrasil.log");
    
    // Проверяем существование файла
    DWORD attr = GetFileAttributes(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        // Первый запуск - создаем файл с флагом 0
        FILE* f = _wfopen(path, L"w");
        if (f) {
            fwprintf(f, L"#LOGS_ENABLED=0\n");
            fclose(f);
        }
        g_logsEnabled = FALSE;
        return;
    }
    
    // Читаем состояние
    LoadLogSettings();
    
    if (g_logsEnabled) {
        // Логи включены - открываем для дозаписи
        g_logFile = _wfopen(path, L"a");
        if (g_logFile) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            fwprintf(g_logFile, L"[%02d:%02d:%02d] [INFO] Yggstack v1.1 started\n", 
                     st.wHour, st.wMinute, st.wSecond);
            fflush(g_logFile);
        }
    } else {
        // Логи выключены - пересоздаем файл с флагом 0
        FILE* f = _wfopen(path, L"w");
        if (f) {
            fwprintf(f, L"#LOGS_ENABLED=0\n");
            fclose(f);
        }
    }
}

void AddLog(LPCWSTR text, BYTE type) {
    // Если логи отключены - ничего не записываем
    if (!g_logsEnabled) return;
    
    LogEntry* entry = &g_logBuffer[g_logHead];
    wcsncpy(entry->text, text, 127);
    entry->text[127] = 0;
    entry->type = type;
    GetLocalTime(&entry->time);
    
    g_logHead = (g_logHead + 1) % LOG_BUFFER_SIZE;
    if (g_logHead == g_logTail) {
        g_logTail = (g_logTail + 1) % LOG_BUFFER_SIZE;
    } else {
        g_logCount++;
    }
    
    if (g_currentTab == 1 && g_hWnd) {
        InvalidateRect(g_hWnd, NULL, FALSE);
    }
    
    // Записываем в файл если логи включены
    if (g_logsEnabled) {
        // Открываем файл если не открыт
        if (!g_logFile) {
            g_logFile = _wfopen(L"\\Storage Card\\yggdrasil.log", L"a");
        }
        if (g_logFile) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            
            LPCWSTR typeStr = L"INFO";
            switch(type) {
                case 1: typeStr = L"WARN"; break;
                case 2: typeStr = L"ERROR"; break;
                case 3: typeStr = L"DEBUG"; break;
                case 4: typeStr = L"SUCCESS"; break;
            }
            
            fwprintf(g_logFile, L"[%02d:%02d:%02d] [%s] %s\n", 
                     st.wHour, st.wMinute, st.wSecond, typeStr, text);
            fflush(g_logFile);
        }
    }
}

void ClearLog() {
    g_logHead = 0;
    g_logTail = 0;
    g_logCount = 0;
    memset(g_logBuffer, 0, sizeof(LogEntry) * LOG_BUFFER_SIZE);
}

void ToggleLogs() {
    g_logsEnabled = !g_logsEnabled;
    WCHAR path[MAX_PATH];
    wsprintf(path, L"\\Storage Card\\yggdrasil.log");
    
    if (g_logsEnabled) {
        // Включаем логи - пересоздаем файл с флагом 1 и текущими логами
        FILE* f = _wfopen(path, L"w");
        if (f) {
            fwprintf(f, L"#LOGS_ENABLED=1\n");
            // Записываем текущие логи из буфера
            int index = g_logTail;
            for (int i = 0; i < g_logCount; i++) {
                LogEntry* entry = &g_logBuffer[index];
                if (entry->text[0] != 0) {
                    LPCWSTR typeStr = L"INFO";
                    switch(entry->type) {
                        case 1: typeStr = L"WARN"; break;
                        case 2: typeStr = L"ERROR"; break;
                        case 3: typeStr = L"DEBUG"; break;
                        case 4: typeStr = L"SUCCESS"; break;
                    }
                    fwprintf(f, L"[%02d:%02d:%02d] [%s] %s\n", 
                             entry->time.wHour, entry->time.wMinute, entry->time.wSecond, 
                             typeStr, entry->text);
                }
                index = (index + 1) % LOG_BUFFER_SIZE;
            }
            fclose(f);
        }
        // Открываем для дозаписи
        g_logFile = _wfopen(path, L"a");
        AddLog(L"Logs enabled", LOG_INFO);
    } else {
        // Выключаем логи
        AddLog(L"Logs disabled", LOG_INFO);
        if (g_logFile) {
            fclose(g_logFile);
            g_logFile = NULL;
        }
        // Пересоздаем файл с флагом 0
        FILE* f = _wfopen(path, L"w");
        if (f) {
            fwprintf(f, L"#LOGS_ENABLED=0\n");
            fclose(f);
        }
    }
}

// Устаревшая функция - больше не используется
// Логи пишутся сразу в файл, состояние сохраняется через UpdateLogFlag
void SaveLogsToFile() {
    // Ничего не делаем - логи уже записаны в файл если они включены
}

// Загружает только настройку (вкл/выкл), не сами логи
void LoadLogSettings() {
    WCHAR path[MAX_PATH];
    wsprintf(path, L"\\Storage Card\\yggdrasil.log");
    
    // Проверяем существование файла
    DWORD attr = GetFileAttributes(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        // Файла нет - первый запуск, логи отключены по умолчанию
        g_logsEnabled = FALSE;
        return;
    }
    
    FILE* f = _wfopen(path, L"r");
    if (!f) {
        g_logsEnabled = FALSE;
        return;
    }
    
    // Читаем только первую строку - флаг состояния
    WCHAR line[256];
    if (fgetws(line, 256, f)) {
        if (wcsncmp(line, L"#LOGS_ENABLED=", 14) == 0) {
            g_logsEnabled = (line[14] == L'1');
        } else {
            // Старый формат без флага - считаем что логи отключены
            g_logsEnabled = FALSE;
        }
    }
    
    fclose(f);
}

// Устаревшая функция - больше не загружает логи, только настройки
void LoadLogsFromFile() {
    LoadLogSettings();
}
