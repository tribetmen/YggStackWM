#pragma once
#include <windows.h>

// Прототипы сетевых функций
void OnStartService();
void OnConnectComplete();
void OnConnectFailed();
void OnAutoReconnect(HWND hWnd);
void DisconnectAll();
BOOL InitWinsock();

// Функция генерации/загрузки ключей
void LoadOrGenerateKeys();

// Сохранение конфигурации
void SaveConfig(void);

// HTTP прокси
void OnToggleHttpProxy();
void StartHttpProxyAsync();
void StopHttpProxyLocal();
