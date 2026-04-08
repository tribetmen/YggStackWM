// YggDraw.cpp - Отрисовка интерфейса (Material-style)

#include "stdafx.h"
#include "YggDraw.h"
#include "YggLog.h"
#include "YggInput.h"
#include "YggdrasilCore.h"

#ifndef PS_DOT
#define PS_DOT 2
#endif

// ============================================================================
// Цвета
// ============================================================================
#define C_BG            RGB(235, 237, 242)   // серый фон страницы
#define C_CARD          RGB(255, 255, 255)   // белая карточка
#define C_PRIMARY       RGB(52, 100, 210)    // синий основной
#define C_PRIMARY_DARK  RGB(30,  65, 160)    // тёмно-синий
#define C_SUCCESS       RGB(52, 199, 120)    // зелёный
#define C_DANGER        RGB(220,  53,  69)   // красный
#define C_WARNING       RGB(255, 160,   0)   // жёлтый
#define C_TEXT          RGB( 28,  28,  35)   // основной текст
#define C_TEXT_LIGHT    RGB(120, 125, 140)   // серый текст
#define C_BORDER        RGB(210, 213, 220)   // граница карточки
#define C_SECTION_HDR   RGB( 28,  28,  35)   // заголовок секции (тёмный)
#define C_TOGGLE_OFF    RGB(180, 185, 195)   // переключатель выкл

// Логи
#define COLOR_INFO      RGB(  0,   0, 180)
#define COLOR_WARN      RGB(180, 100,   0)
#define COLOR_ERROR     RGB(200,   0,   0)
#define COLOR_DEBUG     RGB(120, 120, 120)
#define COLOR_SUCCESS   RGB(  0, 140,   0)

extern int  g_totalHeight;
extern WCHAR g_currentIP[50];

// Буфер отрисовки
HBITMAP g_hBackBuffer    = NULL;
HDC     g_hBackDC        = NULL;
int     g_backBufferWidth  = 0;
int     g_backBufferHeight = 0;

void CreateBackBuffer(HDC hdc, int width, int height) {
    if (g_hBackBuffer) { DeleteObject(g_hBackBuffer); DeleteDC(g_hBackDC); }
    g_hBackDC     = CreateCompatibleDC(hdc);
    g_hBackBuffer = CreateCompatibleBitmap(hdc, width, height);
    g_backBufferWidth  = width;
    g_backBufferHeight = height;
    SelectObject(g_hBackDC, g_hBackBuffer);
}

// ============================================================================
// Вспомогательные функции рисования
// ============================================================================

// Радиус скругления карточек
#define CARD_RADIUS 6

// Скруглённый прямоугольник с заливкой и рамкой
static void FillRoundCard(HDC hdc, RECT* rc, COLORREF fill, COLORREF border) {
    HPEN   pen   = CreatePen(PS_SOLID, 1, border);
    HBRUSH br    = CreateSolidBrush(fill);
    HGDIOBJ op   = SelectObject(hdc, pen);
    HGDIOBJ ob   = SelectObject(hdc, br);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, CARD_RADIUS*2, CARD_RADIUS*2);
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    DeleteObject(pen);
    DeleteObject(br);
}

// Рамка без заливки (прямоугольная, для полей ввода и т.п.)
void DrawFrameRect(HDC hdc, RECT* rc, COLORREF color) {
    HPEN   pen      = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ oldPen   = SelectObject(hdc, pen);
    HGDIOBJ oldBrush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Rectangle(hdc, rc->left, rc->top, rc->right, rc->bottom);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBrush);
    DeleteObject(pen);
}

// Залитая карточка со скруглёнными углами
static void FillCard(HDC hdc, RECT* rc, COLORREF fill, COLORREF border) {
    FillRoundCard(hdc, rc, fill, border);
}

// Горизонтальная линия-разделитель
static void DrawDivider(HDC hdc, int x0, int x1, int y, COLORREF color) {
    HPEN pen    = CreatePen(PS_SOLID, 1, color);
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    MoveToEx(hdc, x0, y, NULL);
    LineTo(hdc, x1, y);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);
}

// Кнопка удаления — красный фон, крестик «X»
static void DrawDeleteBtn(HDC hdc, RECT* rc) {
    // Квадратная зона для симметричного крестика — берём меньшую сторону
    int w  = rc->right  - rc->left;
    int h  = rc->bottom - rc->top;
    int sz = (w < h) ? w : h;  // квадрат по меньшей стороне
    int cx = (rc->left + rc->right)  / 2;
    int cy = (rc->top  + rc->bottom) / 2;
    int pad = sz / 4;

    HPEN pen = CreatePen(PS_SOLID, 2, C_TEXT);
    HPEN old = (HPEN)SelectObject(hdc, pen);
    MoveToEx(hdc, cx - sz/2 + pad, cy - sz/2 + pad, NULL); LineTo(hdc, cx + sz/2 - pad, cy + sz/2 - pad);
    MoveToEx(hdc, cx + sz/2 - pad, cy - sz/2 + pad, NULL); LineTo(hdc, cx - sz/2 + pad, cy + sz/2 - pad);
    SelectObject(hdc, old);
    DeleteObject(pen);
}

// Toggle-переключатель со скруглёнными углами
static void DrawToggle(HDC hdc, RECT* rc, BOOL on) {
    int w  = rc->right  - rc->left;
    int h  = rc->bottom - rc->top;
    int r  = h; // радиус = высота (таблетка)

    COLORREF bg  = on ? C_PRIMARY : C_TOGGLE_OFF;
    COLORREF brd = on ? C_PRIMARY_DARK : C_BORDER;
    HPEN   pen = CreatePen(PS_SOLID, 1, brd);
    HBRUSH br  = CreateSolidBrush(bg);
    HGDIOBJ op = SelectObject(hdc, pen);
    HGDIOBJ ob = SelectObject(hdc, br);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, r, r);
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    DeleteObject(pen);
    DeleteObject(br);

    // Белый кружок-ползунок
    int sz  = h - 4;
    int cx  = on ? (rc->right - 2 - sz) : (rc->left + 2);
    HPEN   pp  = CreatePen(PS_SOLID, 1, RGB(200,200,200));
    HBRUSH dpb = CreateSolidBrush(RGB(255,255,255));
    HGDIOBJ op2 = SelectObject(hdc, pp);
    HGDIOBJ ob2 = SelectObject(hdc, dpb);
    Ellipse(hdc, cx, rc->top + 2, cx + sz, rc->top + 2 + sz);
    SelectObject(hdc, op2);
    SelectObject(hdc, ob2);
    DeleteObject(pp);
    DeleteObject(dpb);
}

COLORREF GetLogColor(BYTE type) {
    switch(type) {
        case LOG_INFO:    return COLOR_INFO;
        case LOG_WARN:    return COLOR_WARN;
        case LOG_ERROR:   return COLOR_ERROR;
        case LOG_DEBUG:   return COLOR_DEBUG;
        case LOG_SUCCESS: return COLOR_SUCCESS;
        default:          return C_TEXT;
    }
}

// ============================================================================
// Масштабирование
// ============================================================================

// Базовая единица — % от ширины экрана для горизонтали,
// фиксированные пиксели для вертикали с коэф. масштаба.
static int Scale(int px, int width) {
    // Базовая ширина 240px. На 480px удваиваем и т.д.
    if (width >= 640) return px * 3 / 2;
    if (width >= 480) return px * 5 / 4;
    return px;
}

// ============================================================================
// Карточка-секция (заголовок + контент внутри белой карточки)
// ============================================================================

// Рисует заголовок секции (над карточкой)
// Возвращает новый y после заголовка
static int DrawSectionHeader(HDC hdc, int x0, int x1, int y, int scrollY, LPCWSTR title, int hdr) {
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, C_TEXT_LIGHT);
    RECT rc = { x0, y - scrollY, x1, y - scrollY + hdr };
    DrawText(hdc, title, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    return y + hdr;
}

// ============================================================================
// Верхняя панель
// ============================================================================

// Высота нашей шапки (без системного трея): 32px на маленьких, 44px на больших
static int TopBarHeight(int width) {
    return (width >= 480) ? 44 : 32;
}

void DrawTopPanel(HDC hdc, int width) {
    if (g_isButtonPhone) {
        // Компактная строка состояния
        RECT rc = { 0, 0, width, 20 };
        HBRUSH br = CreateSolidBrush(C_PRIMARY_DARK);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
        SetTextColor(hdc, RGB(255,255,255));
        SetBkMode(hdc, TRANSPARENT);
        WCHAR s[64];
        wsprintf(s, L"%s", g_serviceRunning ? L"Running" : (g_connecting ? L"Connecting..." : L"Stopped"));
        RECT rcS = { 5, 2, width-5, 18 };
        DrawText(hdc, s, -1, &rcS, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    } else {
        // Белая шапка с тенью
        int barH = TopBarHeight(width);
        int h = g_topPanelY + barH;
        RECT rc = { 0, g_topPanelY, width, h };
        HBRUSH br = CreateSolidBrush(C_CARD);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
        DrawDivider(hdc, 0, width, h - 1, C_BORDER);

        SetBkMode(hdc, TRANSPARENT);

        COLORREF statusColor = g_serviceRunning ? C_SUCCESS : (g_connecting ? C_WARNING : C_DANGER);
        LPCWSTR  statusText  = g_serviceRunning ? L"Connected" : (g_connecting ? L"Connecting..." : L"Disconnected");

        // Цветной прямоугольник-индикатор слева
        RECT rcBar = { 0, g_topPanelY, 4, h };
        HBRUSH barBr = CreateSolidBrush(statusColor);
        FillRect(hdc, &rcBar, barBr);
        DeleteObject(barBr);

        // Текст статуса — цветной, по центру по вертикали
        SetTextColor(hdc, statusColor);
        RECT rcS = { 12, g_topPanelY, width - 10, h };
        DrawText(hdc, statusText, -1, &rcS, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
}

// ============================================================================
// Нижняя панель с вкладками
// ============================================================================

void DrawBottomPanel(HDC hdc, int width, int height) {
    int tabH = g_isButtonPhone ? 30 : Scale(48, width);
    int y0   = height - tabH;

    RECT rcPanel = { 0, y0, width, height };
    HBRUSH br = CreateSolidBrush(C_CARD);
    FillRect(hdc, &rcPanel, br);
    DeleteObject(br);
    DrawDivider(hdc, 0, width, y0, C_BORDER);

    SetBkMode(hdc, TRANSPARENT);

    if (g_isButtonPhone) {
        // Мягкие кнопки
        int my = y0 + 5;
        SetTextColor(hdc, RGB(255,255,255));
        RECT rcL = { 5, my, width/3, my + tabH - 8 };
        LPCWSTR lbl = L"[OK]";
        if (g_addingPeer || g_editingKey || g_addingDns) lbl = L"[Save]";
        else if (g_currentTab == 0 && g_focusIndex == 0)
            lbl = g_serviceRunning ? L"[Stop]" : L"[Start]";
        HBRUSH pbr = CreateSolidBrush(C_PRIMARY_DARK);
        FillRect(hdc, &rcPanel, pbr); DeleteObject(pbr);
        SetTextColor(hdc, RGB(255,255,255));
        DrawText(hdc, lbl, -1, &rcL, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT rcC = { width/3, my, width*2/3, my + tabH - 8 };
        LPCWSTR tab = g_currentTab==0?L"CONFIG":g_currentTab==1?L"LOGS":L"INFO";
        DrawText(hdc, tab, -1, &rcC, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT rcR = { width*2/3, my, width-5, my + tabH - 8 };
        LPCWSTR rl = (g_addingPeer||g_editingKey||g_addingDns) ? L"[Cancel]" : L"[Back]";
        DrawText(hdc, rl, -1, &rcR, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        return;
    }

    // Три вкладки равной ширины
    int tw = width / 3;
    LPCWSTR labels[3] = { L"Configuration", L"Diagnostics", L"Info" };
    for (int i = 0; i < 3; i++) {
        int x0 = i * tw, x1 = (i == 2) ? width : x0 + tw;
        BOOL active = (g_currentTab == i);
        // Подчёркивание активной
        if (active) {
            RECT rcLine = { x0 + 4, height - 3, x1 - 4, height };
            HBRUSH lb = CreateSolidBrush(C_PRIMARY);
            FillRect(hdc, &rcLine, lb);
            DeleteObject(lb);
        }
        SetTextColor(hdc, active ? C_PRIMARY : C_TEXT_LIGHT);
        RECT rcTab = { x0, y0, x1, height - 3 };
        DrawText(hdc, labels[i], -1, &rcTab, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

// ============================================================================
// Config вкладка
// ============================================================================

void DrawConfigTab(HDC hdc, int width, int height, int scrollY) {
    extern WCHAR g_dnsServers[8][64];
    extern int   g_dnsCount;
    extern BOOL  g_addingDns;
    extern WCHAR g_newDns[64];
    extern BOOL  g_httpProxyRunning;

    int tabH    = g_isButtonPhone ? 30 : Scale(48, width);
    int topH    = g_isButtonPhone ? 20 : (g_topPanelY + TopBarHeight(width));
    int mx      = Scale(10, width);          // горизонтальный отступ
    int cardMx  = mx;
    int cardW   = width - 2 * cardMx;
    int rowH    = Scale(40, width);          // высота строки внутри карточки
    int hdrH    = Scale(20, width);          // высота заголовка секции
    int btnH    = Scale(42, width);          // кнопка Start
    int btnAreaH = btnH + Scale(12, width);  // зона кнопки Start

    // Высота пункта пира/dns
    int itemH = g_isButtonPhone ? 28 : Scale(38, width);

    SetBkMode(hdc, TRANSPARENT);

    // Область клипа (между шапкой и нижней панелью)
    int clipTop    = topH;
    int clipBottom = height - tabH - btnAreaH;
    HRGN clipRgn = CreateRectRgn(0, clipTop, width, height - tabH);
    SelectClipRgn(hdc, clipRgn);

    int y = topH + Scale(8, width); // начальная позиция с отступом

    // ── Private Key ──────────────────────────────────────────────────
    y = DrawSectionHeader(hdc, cardMx + 4, width - cardMx, y, scrollY, L"PRIVATE KEY", hdrH);

    {
        // 1. Сначала измеряем шрифт чтобы знать высоту строки
        SIZE charSz = { 8, 14 };
        GetTextExtentPoint32(hdc, L"0", 1, &charSz);
        int lineH = charSz.cy + 2;
        if (lineH < 12) lineH = 12;

        // 2. Фиксируем 4 строки — карточка всегда одного размера
        const int KEY_LINES = 4;
        int cardH = KEY_LINES * lineH + Scale(10, width); // +padding сверху/снизу

        RECT rcCard = { cardMx, y - scrollY, cardMx + cardW, y - scrollY + cardH };
        FillCard(hdc, &rcCard, C_CARD, g_editingKey ? C_PRIMARY : C_BORDER);

        if (g_isButtonPhone && g_focusIndex == 1 && g_currentTab == 0)
            DrawFocusIndicator(hdc, &rcCard);

        // Текстовая область — вся карточка
        int pad = Scale(6, width);
        RECT rcKT = { rcCard.left + pad, rcCard.top + pad,
                      rcCard.right - pad, rcCard.bottom - pad };
        int textAreaW = rcKT.right - rcKT.left;

        // Символов в строке
        int charsPerLine = (charSz.cx > 0) ? (textAreaW / charSz.cx) : 24;
        if (charsPerLine < 4)  charsPerLine = 4;
        if (charsPerLine > 64) charsPerLine = 64;

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, g_editingKey ? C_TEXT : (g_showFullKey ? C_TEXT : C_TEXT_LIGHT));

        if (g_editingKey) {
            // Показываем последние KEY_LINES строки + курсор '|'
            int len   = wcslen(g_tempKey);
            int total = KEY_LINES * charsPerLine;
            int start = (len > total - 1) ? len - (total - 1) : 0;

            WCHAR src[260];
            int si = 0;
            int ki = start;
            while (ki < len && si < 258) src[si++] = g_tempKey[ki++];
            src[si++] = L'|';
            src[si]   = 0;

            int ry = rcKT.top, pos = 0, slen = si;
            while (pos < slen && ry < rcKT.bottom) {
                int n = slen - pos;
                if (n > charsPerLine) n = charsPerLine;
                RECT rl = { rcKT.left, ry, rcKT.right, ry + lineH };
                DrawText(hdc, src + pos, n, &rl, DT_LEFT | DT_TOP | DT_SINGLELINE);
                ry += lineH; pos += n;
            }
        } else if (g_showFullKey) {
            // Полный ключ, 4 строки
            int len = wcslen(g_privateKeyFull);
            int ry = rcKT.top, pos = 0;
            while (pos < len && ry < rcKT.bottom) {
                int n = len - pos;
                if (n > charsPerLine) n = charsPerLine;
                RECT rl = { rcKT.left, ry, rcKT.right, ry + lineH };
                DrawText(hdc, g_privateKeyFull + pos, n, &rl, DT_LEFT | DT_TOP | DT_SINGLELINE);
                ry += lineH; pos += n;
            }
        } else {
            // Маскировка — символ U+25CF (● Black Circle) из Tahoma
            {
                // Измеряем реальную ширину кружка — он шире обычного символа
                WCHAR dot[2] = { 0x25CF, 0 };
                SIZE dotSz = { charSz.cx, charSz.cy };
                GetTextExtentPoint32(hdc, dot, 1, &dotSz);
                int circlesPerLine = (dotSz.cx > 0) ? (textAreaW / dotSz.cx) : charsPerLine;
                if (circlesPerLine < 2)  circlesPerLine = 2;
                if (circlesPerLine > 68) circlesPerLine = 68;

                SetTextColor(hdc, C_TEXT);
                WCHAR circles[70];
                int ci;
                for (ci = 0; ci < circlesPerLine; ci++) circles[ci] = 0x25CF;
                circles[ci] = 0;
                int ry = rcKT.top;
                while (ry + lineH <= rcKT.bottom + 1) {
                    RECT rl = { rcKT.left, ry, rcKT.right, ry + lineH };
                    DrawText(hdc, circles, -1, &rl, DT_LEFT | DT_TOP | DT_SINGLELINE);
                    ry += lineH;
                }
            }
        }

        y += cardH + Scale(12, width);
    }

    // ── Peers ─────────────────────────────────────────────────────────
    y = DrawSectionHeader(hdc, cardMx + 4, width - cardMx, y, scrollY, L"PEERS", hdrH);

    {
        // Строки пиров + строка добавления
        int linesCount = g_peerCount + (g_addingPeer ? 1 : 0) + 1; // +1 = кнопка Add
        int cardH = linesCount * itemH;
        RECT rcCard = { cardMx, y - scrollY, cardMx + cardW, y - scrollY + cardH };
        FillCard(hdc, &rcCard, C_CARD, C_BORDER);

        int iy = y;

        // Существующие пиры
        for (int i = 0; i < g_peerCount; i++) {
            RECT rcRow = { cardMx, iy - scrollY, cardMx + cardW, iy - scrollY + itemH };
            if (i < g_peerCount - 1 || g_addingPeer)
                DrawDivider(hdc, cardMx + Scale(8,width), cardMx + cardW - Scale(8,width),
                            iy - scrollY + itemH - 1, C_BORDER);

            int delW = Scale(32, width);
            RECT rcDel = { rcRow.right - delW - 4, rcRow.top + (itemH - Scale(24,width))/2,
                           rcRow.right - 4, rcRow.top + (itemH + Scale(24,width))/2 };
            DrawDeleteBtn(hdc, &rcDel);

            if (g_isButtonPhone && g_focusIndex == (2 + i) && g_currentTab == 0)
                DrawFocusIndicator(hdc, &rcDel);

            SetTextColor(hdc, C_TEXT);
            RECT rcT = { rcRow.left + Scale(8,width), rcRow.top,
                         rcDel.left - 4, rcRow.bottom };
            DrawText(hdc, g_peersList[i], -1, &rcT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            iy += itemH;
        }

        // Поле ввода нового пира
        if (g_addingPeer) {
            RECT rcRow = { cardMx, iy - scrollY, cardMx + cardW, iy - scrollY + itemH };
            DrawDivider(hdc, cardMx + Scale(8,width), cardMx + cardW - Scale(8,width),
                        iy - scrollY + itemH - 1, C_BORDER);
            RECT rcIn = { rcRow.left + Scale(8,width), rcRow.top + 4,
                          rcRow.right - Scale(8,width), rcRow.bottom - 4 };
            FillRoundCard(hdc, &rcIn, RGB(240,245,255), C_PRIMARY);
            WCHAR d[130]; wsprintf(d, L"%s_", g_newPeer);
            SetTextColor(hdc, C_TEXT);
            RECT rcIT = { rcIn.left + 4, rcIn.top, rcIn.right - 4, rcIn.bottom };
            DrawText(hdc, d, -1, &rcIT, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            iy += itemH;
        }

        // Строка «Добавить пир»
        {
            RECT rcAdd = { cardMx, iy - scrollY, cardMx + cardW, iy - scrollY + itemH };
            if (g_addingPeer) {
                HBRUSH ab = CreateSolidBrush(RGB(230,245,255));
                FillRect(hdc, &rcAdd, ab); DeleteObject(ab);
            }
            if (g_isButtonPhone && g_focusIndex == (2 + g_peerCount) && g_currentTab == 0)
                DrawFocusIndicator(hdc, &rcAdd);
            SetTextColor(hdc, C_PRIMARY);
            LPCWSTR lbl = g_addingPeer ? L"-  Enter peer URI..." : L"+  Add peer";
            RECT rcT = { rcAdd.left + Scale(8,width), rcAdd.top,
                         rcAdd.right - Scale(8,width), rcAdd.bottom };
            DrawText(hdc, lbl, -1, &rcT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }

        y += cardH + Scale(12, width);
    }

    // ── Your Yggdrasil IP ─────────────────────────────────────────────
    y = DrawSectionHeader(hdc, cardMx + 4, width - cardMx, y, scrollY, L"YOUR YGGDRASIL IP", hdrH);

    {
        // Измеряем шрифт для адаптивного переноса
        SIZE ipCharSz = { 8, 14 };
        GetTextExtentPoint32(hdc, L"0", 1, &ipCharSz);
        int ipLineH = ipCharSz.cy + 2;
        if (ipLineH < 12) ipLineH = 12;

        int pad = Scale(8, width);
        int textW = cardW - 2 * pad;
        int ipCharsPerLine = (ipCharSz.cx > 0) ? (textW / ipCharSz.cx) : 20;
        if (ipCharsPerLine < 4) ipCharsPerLine = 4;

        // Высота карточки — по количеству строк IP (минимум 1)
        int ipLen = g_serviceRunning ? (int)wcslen(g_currentIP) : 0;
        int ipLines = g_serviceRunning ? ((ipLen + ipCharsPerLine - 1) / ipCharsPerLine) : 1;
        if (ipLines < 1) ipLines = 1;
        int cardH = ipLines * ipLineH + 2 * pad;
        if (cardH < Scale(40, width)) cardH = Scale(40, width); // минимум

        RECT rcCard = { cardMx, y - scrollY, cardMx + cardW, y - scrollY + cardH };
        COLORREF borderColor = g_serviceRunning ? C_SUCCESS : C_BORDER;
        FillCard(hdc, &rcCard, C_CARD, borderColor);

        if (g_serviceRunning) {
            // Адаптивный перенос — построчно, зелёным цветом
            SetTextColor(hdc, C_SUCCESS);
            SetBkMode(hdc, TRANSPARENT);
            int ry = rcCard.top + pad, pos = 0;
            while (pos < ipLen && ry < rcCard.bottom - pad + 1) {
                int n = ipLen - pos;
                if (n > ipCharsPerLine) n = ipCharsPerLine;
                RECT rl = { rcCard.left + pad, ry, rcCard.right - pad, ry + ipLineH };
                DrawText(hdc, g_currentIP + pos, n, &rl, DT_LEFT | DT_TOP | DT_SINGLELINE);
                ry += ipLineH; pos += n;
            }
        } else {
            SetTextColor(hdc, C_TEXT_LIGHT);
            DrawText(hdc, L"Not connected", -1, &rcCard, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        y += cardH + Scale(12, width);
    }

    // ── Proxy Configuration ───────────────────────────────────────────
    y = DrawSectionHeader(hdc, cardMx + 4, width - cardMx, y, scrollY, L"PROXY CONFIGURATION", hdrH);

    {
        int cardH = rowH;
        RECT rcCard = { cardMx, y - scrollY, cardMx + cardW, y - scrollY + cardH };
        FillCard(hdc, &rcCard, C_CARD, C_BORDER);

        if (g_isButtonPhone && g_focusIndex == (3 + g_peerCount) && g_currentTab == 0)
            DrawFocusIndicator(hdc, &rcCard); // HTTP Proxy = 3+n

        SetTextColor(hdc, C_TEXT);
        RECT rcL = { rcCard.left + Scale(8,width), rcCard.top,
                     rcCard.right - Scale(52,width), rcCard.bottom };
        DrawText(hdc, L"HTTP Proxy  127.0.0.1:8080", -1, &rcL, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // Toggle
        int tgW = Scale(44, width), tgH = Scale(22, width);
        RECT rcTg = { rcCard.right - tgW - Scale(8,width),
                      rcCard.top + (rowH - tgH)/2,
                      rcCard.right - Scale(8,width),
                      rcCard.top + (rowH + tgH)/2 };
        DrawToggle(hdc, &rcTg, g_httpProxyRunning);
        y += cardH + Scale(12, width);
    }

    // ── DNS Servers ───────────────────────────────────────────────────
    y = DrawSectionHeader(hdc, cardMx + 4, width - cardMx, y, scrollY, L"DNS SERVERS", hdrH);

    {
        int linesCount = g_dnsCount + (g_addingDns ? 1 : 0) + 1;
        int cardH = linesCount * itemH;
        RECT rcCard = { cardMx, y - scrollY, cardMx + cardW, y - scrollY + cardH };
        FillCard(hdc, &rcCard, C_CARD, C_BORDER);

        int iy = y;
        for (int i = 0; i < g_dnsCount; i++) {
            RECT rcRow = { cardMx, iy - scrollY, cardMx + cardW, iy - scrollY + itemH };
            if (i < g_dnsCount - 1 || g_addingDns)
                DrawDivider(hdc, cardMx + Scale(8,width), cardMx + cardW - Scale(8,width),
                            iy - scrollY + itemH - 1, C_BORDER);

            int delW = Scale(32, width);
            RECT rcDel = { rcRow.right - delW - 4, rcRow.top + (itemH - Scale(24,width))/2,
                           rcRow.right - 4, rcRow.top + (itemH + Scale(24,width))/2 };
            DrawDeleteBtn(hdc, &rcDel);

            int dnsFocusBase = 4 + g_peerCount; // 0=Start,1=Key,2..2+n-1=DelPeer,2+n=AddPeer,3+n=Proxy,4+n..=DelDNS,4+n+m=AddDNS
            if (g_isButtonPhone && g_focusIndex == (dnsFocusBase + i) && g_currentTab == 0)
                DrawFocusIndicator(hdc, &rcDel);

            // Пометка «primary» для первого — измеряем реальную ширину
            int tagW = 0;
            if (i == 0) {
                SIZE tagSz = { 0, 0 };
                GetTextExtentPoint32(hdc, L"primary", 7, &tagSz);
                tagW = tagSz.cx + Scale(6, width);
                SetTextColor(hdc, C_TEXT_LIGHT);
                RECT rcTag = { rcDel.left - tagW - 4, rcRow.top, rcDel.left - 4, rcRow.bottom };
                DrawText(hdc, L"primary", -1, &rcTag, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
            }

            SetTextColor(hdc, i == 0 ? C_TEXT : C_TEXT_LIGHT);
            RECT rcT = { rcRow.left + Scale(8,width), rcRow.top,
                         rcDel.left - (i == 0 ? tagW + 4 : 4),
                         rcRow.bottom };
            DrawText(hdc, g_dnsServers[i], -1, &rcT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            iy += itemH;
        }

        // Поле ввода нового DNS
        if (g_addingDns) {
            RECT rcRow = { cardMx, iy - scrollY, cardMx + cardW, iy - scrollY + itemH };
            DrawDivider(hdc, cardMx + Scale(8,width), cardMx + cardW - Scale(8,width),
                        iy - scrollY + itemH - 1, C_BORDER);
            RECT rcIn = { rcRow.left + Scale(8,width), rcRow.top + 4,
                          rcRow.right - Scale(8,width), rcRow.bottom - 4 };
            FillRoundCard(hdc, &rcIn, RGB(240,245,255), C_PRIMARY);
            WCHAR d[70]; wsprintf(d, L"%s_", g_newDns);
            SetTextColor(hdc, C_TEXT);
            RECT rcIT = { rcIn.left + 4, rcIn.top, rcIn.right - 4, rcIn.bottom };
            DrawText(hdc, d, -1, &rcIT, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            iy += itemH;
        }

        // Строка «Добавить DNS»
        {
            RECT rcAdd = { cardMx, iy - scrollY, cardMx + cardW, iy - scrollY + itemH };
            if (g_addingDns) {
                HBRUSH ab = CreateSolidBrush(RGB(230,245,255));
                FillRect(hdc, &rcAdd, ab); DeleteObject(ab);
            }
            if (g_isButtonPhone && g_focusIndex == (4 + g_peerCount + g_dnsCount) && g_currentTab == 0)
                DrawFocusIndicator(hdc, &rcAdd);
            SetTextColor(hdc, C_PRIMARY);
            LPCWSTR lbl = g_addingDns ? L"-  Enter DNS address..." : L"+  Add DNS server";
            RECT rcT = { rcAdd.left + Scale(8,width), rcAdd.top,
                         rcAdd.right - Scale(8,width), rcAdd.bottom };
            DrawText(hdc, lbl, -1, &rcT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }

        y += cardH + Scale(12, width);
    }

    SelectClipRgn(hdc, NULL);
    DeleteObject(clipRgn);

    // Обновляем g_maxFocusIndex
    if (g_currentTab == 0) {
        extern int g_maxFocusIndex;
        // 0=Start, 1=Key, 2..2+n-1=DelPeer, 2+n=AddPeer,
        // 3+n=Proxy, 4+n..4+n+m-1=DelDNS, 4+n+m=AddDNS
        g_maxFocusIndex = 4 + g_peerCount + g_dnsCount;
    }

    // ── Кнопка Start / Stop (фиксированно над нижней панелью) ─────────
    {
        int bH  = btnH;
        int by  = height - tabH - bH - Scale(8, width);
        RECT rcBtn = { mx, by, width - mx, by + bH };
        COLORREF bc  = g_serviceRunning ? C_SUCCESS : (g_connecting ? C_WARNING : C_PRIMARY);
        COLORREF brc = g_serviceRunning ? RGB(30,150,70) : (g_connecting ? RGB(180,110,0) : C_PRIMARY_DARK);
        HPEN   bpen = CreatePen(PS_SOLID, 1, brc);
        HBRUSH bb   = CreateSolidBrush(bc);
        HGDIOBJ obp = SelectObject(hdc, bpen);
        HGDIOBJ obb = SelectObject(hdc, bb);
        RoundRect(hdc, rcBtn.left, rcBtn.top, rcBtn.right, rcBtn.bottom, CARD_RADIUS*2, CARD_RADIUS*2);
        SelectObject(hdc, obp); SelectObject(hdc, obb);
        DeleteObject(bpen); DeleteObject(bb);
        if (g_isButtonPhone && g_focusIndex == 0 && g_currentTab == 0)
            DrawFocusIndicator(hdc, &rcBtn);
        SetTextColor(hdc, RGB(255,255,255));
        LPCWSTR btnTxt = g_serviceRunning ? L"Stop Service" :
                         (g_connecting ? L"Connecting..." : L"Start Service");
        DrawText(hdc, btnTxt, -1, &rcBtn, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    // Прогресс-бар при подключении
    if (g_showSpinner && g_connecting) {
        int by = height - tabH - btnH - Scale(8,width) - Scale(12,width);
        int bw = width - 2*mx;
        RECT rcBg = { mx, by, mx + bw, by + Scale(4,width) };
        HBRUSH bgBr = CreateSolidBrush(C_BORDER);
        FillRect(hdc, &rcBg, bgBr); DeleteObject(bgBr);
        int bk = bw / 5;
        int bp = (g_spinnerAngle * (bw - bk)) / 360;
        RECT rcFl = { mx + bp, by, mx + bp + bk, by + Scale(4,width) };
        HBRUSH flBr = CreateSolidBrush(C_PRIMARY);
        FillRect(hdc, &rcFl, flBr); DeleteObject(flBr);
    }

    // Контент стартует с topH + Scale(8), видимая область = height - tabH - topH - btnAreaH
    int contentH = y - topH + Scale(8, width);
    int visH = height - tabH - topH - btnAreaH;
    int maxSc = (contentH > visH) ? contentH - visH : 0;
    Scroll_SetBounds(&g_scroll, 0, 0, 0, maxSc);
}

// ============================================================================
// Logs вкладка
// ============================================================================

void DrawLogsTab(HDC hdc, int width, int height, int scrollY) {
    if (g_isButtonPhone) { extern int g_maxFocusIndex; g_maxFocusIndex = 1; }

    int tabH   = g_isButtonPhone ? 30 : Scale(48, width);
    int topH   = g_isButtonPhone ? 20 : (g_topPanelY + TopBarHeight(width));
    int mx     = Scale(8, width);
    int btnH   = Scale(28, width);

    // Измеряем реальную высоту шрифта
    SIZE charSz = { 8, 14 };
    GetTextExtentPoint32(hdc, L"Ag", 2, &charSz);
    int lineH = charSz.cy + 4; // +4px межстрочный интервал
    if (lineH < 16) lineH = 16;

    // Панель управления логами
    int panY = topH + Scale(6, width);
    RECT rcPanel = { mx, panY, width - mx, panY + btnH };
    SetBkMode(hdc, TRANSPARENT);

    // Счётчик
    WCHAR stats[32]; wsprintf(stats, L"%d entries", g_logCount);
    SetTextColor(hdc, C_TEXT_LIGHT);
    RECT rcSt = { rcPanel.left, rcPanel.top, rcPanel.right - Scale(130,width), rcPanel.bottom };
    DrawText(hdc, stats, -1, &rcSt, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    // Кнопка On/Off
    extern BOOL g_logsEnabled;
    RECT rcOn = { width - mx - Scale(120,width), panY, width - mx - Scale(62,width), panY + btnH };
    COLORREF onC = g_logsEnabled ? C_SUCCESS : C_DANGER;
    HBRUSH onBr = CreateSolidBrush(onC);
    FillRect(hdc, &rcOn, onBr); DeleteObject(onBr);
    SetTextColor(hdc, RGB(255,255,255));
    DrawText(hdc, g_logsEnabled ? L"ON" : L"OFF", -1, &rcOn, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if (g_isButtonPhone && g_focusIndex == 0) DrawFocusIndicator(hdc, &rcOn);

    // Кнопка Clear
    RECT rcCl = { width - mx - Scale(56,width), panY, width - mx, panY + btnH };
    HBRUSH clBr = CreateSolidBrush(C_BORDER);
    FillRect(hdc, &rcCl, clBr); DeleteObject(clBr);
    DrawFrameRect(hdc, &rcCl, C_BORDER);
    SetTextColor(hdc, C_TEXT);
    DrawText(hdc, L"Clear", -1, &rcCl, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if (g_isButtonPhone && g_focusIndex == 1) DrawFocusIndicator(hdc, &rcCl);

    DrawDivider(hdc, mx, width - mx, panY + btnH + Scale(4,width), C_BORDER);

    int clipTop    = panY + btnH + Scale(6,width);
    int clipBottom = height - tabH;
    HRGN clipRgn = CreateRectRgn(0, clipTop, width, clipBottom);
    SelectClipRgn(hdc, clipRgn);

    // Логи в обратном порядке: последний сверху
    // g_logHead указывает на следующую позицию записи (самую новую - 1)
    int y = clipTop;
    for (int i = 0; i < g_logCount; i++) {
        // Идём от последней записи к первой
        int index = ((g_logHead - 1 - i) % LOG_BUFFER_SIZE + LOG_BUFFER_SIZE) % LOG_BUFFER_SIZE;
        LogEntry* e = &g_logBuffer[index];
        if (e->text[0]) {
            WCHAR line[256];
            wsprintf(line, L"[%02d:%02d:%02d] %s",
                     e->time.wHour, e->time.wMinute, e->time.wSecond, e->text);
            int iy = y - scrollY;
            if (iy + lineH > clipTop && iy < clipBottom) {
                SetTextColor(hdc, GetLogColor(e->type));
                RECT rcL = { mx, iy, width - mx, iy + lineH };
                DrawText(hdc, line, -1, &rcL, DT_LEFT | DT_TOP | DT_SINGLELINE);
            }
            y += lineH;
        }
    }

    SelectClipRgn(hdc, NULL);
    DeleteObject(clipRgn);

    // Полная высота контента (без учёта clipTop-смещения)
    int contentH = y - clipTop + Scale(8, width);
    int visH = clipBottom - clipTop;
    int maxSc = (contentH > visH) ? contentH - visH : 0;
    Scroll_SetBounds(&g_scroll, 0, 0, 0, maxSc);
}

// ============================================================================
// Info вкладка
// ============================================================================

void DrawInfoTab(HDC hdc, int width, int height, int scrollY) {
    int tabH  = g_isButtonPhone ? 30 : Scale(48, width);
    int topH  = g_isButtonPhone ? 20 : (g_topPanelY + TopBarHeight(width));
    int mx    = Scale(10, width);
    int itemH = Scale(26, width);
    if (itemH < 18) itemH = 18;

    int clipBottom = height - tabH;
    HRGN clipRgn = CreateRectRgn(0, topH, width, clipBottom);
    SelectClipRgn(hdc, clipRgn);

    SetBkMode(hdc, TRANSPARENT);
    int y = topH + Scale(8, width);

    struct { LPCWSTR text; BOOL header; } items[] = {
        { L"Yggstack",                          TRUE  },
        { L"Version 1.2",                       FALSE },
        { L"Windows Mobile 5/6",                FALSE },
        { L"",                                  FALSE },
        { L"Yggdrasil Network",                 TRUE  },
        { L"IPv6 mesh networking",              FALSE },
        { L"Ironwood protocol",                 FALSE },
        { L"End-to-end encryption",             FALSE },
        { L"",                                  FALSE },
        { L"HTTP Proxy",                        TRUE  },
        { L"127.0.0.1:8080",                    FALSE },
        { L"For use with Opera browser",        FALSE },
        { L"",                                  FALSE },
        { L"Links",                             TRUE  },
        { L"github.com/tribetmen/YggStackWM",   FALSE },
        { L"yggdrasil-network.github.io",       FALSE },
    };
    int n = sizeof(items)/sizeof(items[0]);

    for (int i = 0; i < n; i++) {
        if (!items[i].text[0]) { y += itemH/2; continue; }
        int iy = y - scrollY;
        if (items[i].header) {
            SetTextColor(hdc, C_TEXT_LIGHT);
            RECT rc = { mx, iy, width - mx, iy + itemH };
            DrawText(hdc, items[i].text, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            DrawDivider(hdc, mx, width - mx, iy + itemH - 1, C_BORDER);
        } else {
            SetTextColor(hdc, C_TEXT);
            RECT rc = { mx + Scale(12,width), iy, width - mx, iy + itemH };
            DrawText(hdc, items[i].text, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        }
        y += itemH;
    }

    SelectClipRgn(hdc, NULL);
    DeleteObject(clipRgn);

    int maxSc = (y + 20 > clipBottom) ? y + 20 - clipBottom : 0;
    Scroll_SetBounds(&g_scroll, 0, 0, 0, maxSc);
}

// ============================================================================
// Главная функция отрисовки
// ============================================================================

void DrawInterface(HDC hdc, int width, int height) {
    // Серый фон
    HBRUSH bgBr = CreateSolidBrush(C_BG);
    RECT rcAll  = { 0, 0, width, height };
    FillRect(hdc, &rcAll, bgBr);
    DeleteObject(bgBr);

    DrawTopPanel(hdc, width);

    int scrollY = g_scroll.y;
    switch (g_currentTab) {
        case 0: DrawConfigTab(hdc, width, height, scrollY); break;
        case 1: DrawLogsTab(hdc, width, height, scrollY);   break;
        case 2: DrawInfoTab(hdc, width, height, scrollY);    break;
    }

    DrawBottomPanel(hdc, width, height);
}
