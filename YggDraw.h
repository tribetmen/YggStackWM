#pragma once
#include <windows.h>

// Функции отрисовки
void DrawInterface(HDC hdc, int width, int height);
void DrawConfigTab(HDC hdc, int width, int height, int scrollY);
void DrawLogsTab(HDC hdc, int width, int height, int scrollY);
void DrawInfoTab(HDC hdc, int width, int height, int scrollY);
void DrawBottomPanel(HDC hdc, int width, int height);
void DrawTopPanel(HDC hdc, int width);

// Вспомогательные функции
void DrawFrameRect(HDC hdc, RECT* rc, COLORREF color);
COLORREF GetLogColor(BYTE type);
void CreateBackBuffer(HDC hdc, int width, int height);

// Буфер отрисовки
extern HBITMAP g_hBackBuffer;
extern HDC g_hBackDC;
extern int g_backBufferWidth;
extern int g_backBufferHeight;
