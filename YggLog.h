#pragma once
#include <windows.h>

// Структура записи лога уже определена в YggInput.h

// Размер буфера лога
#define LOG_BUFFER_SIZE 200

// Типы логов
#define LOG_INFO     0
#define LOG_WARN     1
#define LOG_ERROR    2
#define LOG_DEBUG    3
#define LOG_SUCCESS  4

// Инициализация и работа с логом
void InitLogSystem();
void AddLog(LPCWSTR text, BYTE type);
void ClearLog();
void LoadLogSettings();
void ToggleLogs();

// Экспорт переменных
extern int g_logHead;
extern int g_logTail;
extern int g_logCount;
